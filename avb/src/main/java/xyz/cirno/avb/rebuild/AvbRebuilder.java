package xyz.cirno.avb.rebuild;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.AvbPublicKey;
import xyz.cirno.avb.ChainPartitionDescriptor;
import xyz.cirno.avb.HashDescriptor;
import xyz.cirno.avb.ParsedVerifiedBootMetaImage;
import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.util.Logger;
import xyz.cirno.avb.verify.AvbVerifier;
import xyz.cirno.avb.verify.AvbVerifyResult;
import xyz.cirno.avb.verify.PartitionRecord;
import xyz.cirno.avb.verify.VerificationIssue;

public class AvbRebuilder {
    private final Map<String, PartitionRecord> partitionRecords = new HashMap<>();
    private final Set<AvbVerifier.PartitionReference> partitionReferences = new HashSet<>();
    private final List<VerificationIssue> issues = new ArrayList<>();

    // re-sign if value is not null
    private final Map<String, AvbKeyPair> dirtyVbmetaImages = new HashMap<>();

    private final Map<AvbPublicKey, AvbKeyPair> availableKeys = new HashMap<>();
    private final Map<Integer, AvbKeyPair> generatedKeys = new HashMap<>();

    public AvbRebuilder(AvbVerifyResult result) {
        for (var entry : result.partitionRecords.entrySet()) {
            var record = entry.getValue();
            var dup = new PartitionRecord(record.name(), record.vbmetaImage().clone(), record.footer() != null ? record.footer().clone() : null);
            this.partitionRecords.put(entry.getKey(), dup);
        }
        this.partitionRecords.putAll(result.partitionRecords);
        this.partitionReferences.addAll(result.partitionReferences);
        for (var issue : result.issues) {
            addIssue(issue);
        }
    }

    public void addKeyPair(AvbKeyPair keyPair) {
        availableKeys.put(keyPair.publicKey, keyPair);
    }

    private boolean addIssue(VerificationIssue issue) {
        if (!issues.contains(issue)) {
            issues.add(issue);
            return true;
        }
        return false;
    }

    private ParsedVerifiedBootMetaImage getVbmetaImage(String partitionName) throws IOException {
        if (partitionRecords.containsKey(partitionName)) {
            return partitionRecords.get(partitionName).vbmetaImage();
        }
        throw new IllegalStateException("Vbmeta image for partition " + partitionName + " not verified");
    }

    public List<VbmetaRebuildRequest> rebuildWithTrustedData() throws IOException {
        int i = 0;
        while (!issues.isEmpty()) {
            var issue = issues.remove(0);
            if (issue instanceof VerificationIssue.HashMismatch hm) {
                fixHashMismatch(hm);
            } else if (issue instanceof VerificationIssue.PublicKeyMismatch pkm) {
                fixPublicKeyMismatch(pkm);
            } else if (issue instanceof VerificationIssue.InvalidSignature is) {
                fixInvalidSignature(is);
            } else if (issue instanceof VerificationIssue.InvalidPartitionData ipd) {
                throw new UnsupportedOperationException("cannot fix invalid data in partition " + ipd.partitionName());
            }
            i++;
            if (i > 1000) {
                throw new IllegalStateException("too many fix iterations, possible infinite loop");
            }
        }
        var result = new ArrayList<VbmetaRebuildRequest>();
        for (var vbmetaPartition : dirtyVbmetaImages.entrySet()) {
            var name = vbmetaPartition.getKey();
            var record = partitionRecords.get(name);
            var signKey = vbmetaPartition.getValue();
            result.add(new VbmetaRebuildRequest(name, record.vbmetaImage(), record.footer(), signKey));
        }
        return result;
    }

    private void markVbmetaDirty(String vbmetaPartition, AvbKeyPair signKey) {
        AvbKeyPair value = null;
        var partitionRecord = partitionRecords.get(vbmetaPartition);
        var header = partitionRecord.vbmetaImage();
        if (header != null) {
            if (header.signature != null) {
                if (signKey == null) {
                    if (addIssue(new VerificationIssue.InvalidSignature(vbmetaPartition))) {
                        Logger.info("Invalidated signature for partition " + vbmetaPartition);
                    }
                } else {
                    value = signKey;
                }
            }
        }
        dirtyVbmetaImages.put(vbmetaPartition, value);
    }

    private void fixInvalidSignature(VerificationIssue.InvalidSignature is) throws IOException {
        var vbmetaPartition = is.vbmetaPartition();
        var header = getVbmetaImage(vbmetaPartition);
        Logger.info("Fixing invalid signature for partition " + is.vbmetaPartition() + "with public key " + header.publicKey);
        var privKey = tryGetKeyPairFor(header.publicKey);
        // have private key for current partition
        if (privKey != null) {
            markVbmetaDirty(vbmetaPartition, privKey);
            return;
        }

        Logger.info("No private key found for partition " + vbmetaPartition + ", trying to replace public key");

        // try to replace key from references
        var refs = partitionReferences.stream()
                .filter(r -> !r.partitionName().equals(r.referencedInVbmetaPartition())
                        && r.partitionName().equals(vbmetaPartition))
                .toList();
        if (refs.isEmpty()) {
            Logger.error("No references found for partition " + vbmetaPartition + ", unable to fix signature");
            throw new IllegalStateException("unable to fix signature");
        }
        for (var ref : refs) {
            var header2 = getVbmetaImage(ref.referencedInVbmetaPartition());
            var desc2 = header2.descriptors.get(ref.descriptorIndex());
            if (!(desc2 instanceof ChainPartitionDescriptor cpd)) {
                Logger.error("Descriptor is not ChainPartitionDescriptor in partition " + ref.referencedInVbmetaPartition());
                throw new IllegalStateException("unable to fix signature");
            }
            var newKeyPair = getGeneratedKeyPair(cpd.publicKey.keySizeBits);
            header.publicKey = newKeyPair.publicKey;
            markVbmetaDirty(vbmetaPartition, newKeyPair);
            Logger.info("Replaced public key in vbmeta partition %s to %s",
                    vbmetaPartition, IOUtils.sha256ToHex(newKeyPair.publicKey.toByteArray()));
            addIssue(new VerificationIssue.PublicKeyMismatch(ref.referencedInVbmetaPartition(), ref.descriptorIndex(), newKeyPair.publicKey));
        }
    }

    private AvbKeyPair getGeneratedKeyPair(int keySize) {
        if (generatedKeys.containsKey(keySize)) {
            return generatedKeys.get(keySize);
        }
        try {
            var keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(keySize);
            var jkp = keygen.generateKeyPair();
            var akp = new AvbKeyPair(new AvbPublicKey((RSAPublicKey) jkp.getPublic()), jkp.getPrivate());
            generatedKeys.put(keySize, akp);
            return akp;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private AvbKeyPair tryGetKeyPairFor(AvbPublicKey publicKey) {
        if (publicKey == null) {
            return null;
        }
        var result = availableKeys.get(publicKey);
        if (result == null) {
            result = generatedKeys.values().stream()
                    .filter(x -> x.publicKey.equals(publicKey))
                    .findFirst().orElse(null);
        }
        return result;
    }

    private void fixPublicKeyMismatch(VerificationIssue.PublicKeyMismatch pkm) throws IOException {
        var header = getVbmetaImage(pkm.vbmetaPartition());
        var descriptor = header.descriptors.get(pkm.descriptorIndex());
        if (!(descriptor instanceof ChainPartitionDescriptor cpd)) {
            throw new IllegalArgumentException("Descriptor is not ChainPartitionDescriptor");
        }
        Logger.info("Fixing public key mismatch in chain partition descriptor %s:%d -> %s", pkm.vbmetaPartition(), pkm.descriptorIndex(), cpd.partitionName);
        var newPublicKey = pkm.actualPublicKey();
        cpd.publicKey = newPublicKey;
        markVbmetaDirty(pkm.vbmetaPartition(), null);
    }

    private void fixHashMismatch(VerificationIssue.HashMismatch hm) throws IOException {
        var vbmetaPartition = hm.vbmetaPartition();
        var descriptorIndex = hm.descriptorIndex();
        var header = getVbmetaImage(vbmetaPartition);
        var descriptor = header.descriptors.get(descriptorIndex);
        if (!(descriptor instanceof HashDescriptor hd)) {
            throw new IllegalArgumentException("Descriptor is not HashDescriptor");
        }
        Logger.info("Fixing hash mismatch in hash descriptor %s:%d", hm.vbmetaPartition(), hm.descriptorIndex());
        hd.digest = hm.actualHash();
        hd.imageSize = hm.actualSize();
        markVbmetaDirty(vbmetaPartition, null);
    }
}
