package xyz.cirno.avb.verify;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import xyz.cirno.avb.AvbDescriptor;
import xyz.cirno.avb.AvbPartitionInfo;
import xyz.cirno.avb.ChainPartitionDescriptor;
import xyz.cirno.avb.HashDescriptor;
import xyz.cirno.avb.HashTreeDescriptor;
import xyz.cirno.avb.ParsedVerifiedBootMetaImage;
import xyz.cirno.avb.PartitionProvider;
import xyz.cirno.avb.VerifiedBootMetaImage;
import xyz.cirno.avb.util.Logger;

public class AvbVerifier {
    private PartitionProvider provider;
    private List<VerificationIssue> issues = new ArrayList<>();
    private Map<String, AvbPartitionInfo> cachedPartitionInfo = new HashMap<>();
    private Map<String, ParsedVerifiedBootMetaImage> cachedVbmetaImages = new HashMap<>();
    private Set<PartitionReference> partitionReferences = new HashSet<>();
    private Set<String> dirtyVbmetaImages = new HashSet<>();

    public AvbVerifier(PartitionProvider provider) {
        this.provider = provider;
    }

    private static VerifyHashResult verifyHashDescriptorRaw(ReadableByteChannel ch, HashDescriptor desc, long actualSize) {
        MessageDigest hasher;
        try {
            hasher = MessageDigest.getInstance(desc.hashAlgorithm);
        } catch (Exception e) {
            Logger.error("Unsupported hash algorithm: " + desc.hashAlgorithm);
            return new VerifyHashResult(false, null);
        }
        hasher.update(desc.salt);
        var buffer = ByteBuffer.allocateDirect(262144);
        long remaining = actualSize;
        while (remaining > 0) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.capacity(), remaining);
            buffer.limit(toRead);
            try {
                int read = ch.read(buffer);
                if (read < 0) {
                    Logger.error("Unexpected end of channel");
                    return new VerifyHashResult(false, null);
                }
                remaining -= read;
                buffer.flip();
                hasher.update(buffer);
            } catch (IOException e) {
                Logger.error("IOException while reading channel: " + e.getMessage());
                return new VerifyHashResult(false, null);
            }
        }
        var digest = hasher.digest();
//        Logger.debug("partition %s size %d salt %s computed hash: %s", desc.partitionName, actualSize,
//                IOUtils.bytesToHex(desc.salt), IOUtils.bytesToHex(digest));
        return new VerifyHashResult(MessageDigest.isEqual(digest, desc.digest), digest);
    }

    private void addIssue(VerificationIssue issue) {
        for (var existing : issues) {
            if (existing.equals(issue)) {
                return;
            }
        }
        issues.add(issue);
    }

    private AvbPartitionInfo getPartitionInfo(String partitionName) throws IOException {
        if (cachedPartitionInfo.containsKey(partitionName)) {
            return cachedPartitionInfo.get(partitionName);
        }
        try (var part = provider.openPartition(partitionName)) {
            var info = AvbPartitionInfo.ofPartition(part);
            cachedPartitionInfo.put(partitionName, info);
            return info;
        }
    }

    private ParsedVerifiedBootMetaImage getVbmetaImage(String partitionName) throws IOException {
        if (cachedVbmetaImages.containsKey(partitionName)) {
            return cachedVbmetaImages.get(partitionName);
        }
        try (var part = provider.openPartition(partitionName)) {
            var info = getPartitionInfo(partitionName);
            if (info == null) {
                return null;
            }
            part.position(info.vbmetaOffset);
            var vbmeta = VerifiedBootMetaImage.parseFrom(part);
            cachedVbmetaImages.put(partitionName, vbmeta);
            return vbmeta;
        }
    }

    private void recursiveVerifyInternal(String vbmetaPartitionName) throws IOException {
        var info = getPartitionInfo(vbmetaPartitionName);
        if (info == null) {
            Logger.error("Unable to find vbmeta image header in partition " + vbmetaPartitionName);
            addIssue(new VerificationIssue.InvalidPartitionData(vbmetaPartitionName));
        }
        Logger.info("Verifying vbmeta image in partition " + vbmetaPartitionName);
        var header = getVbmetaImage(vbmetaPartitionName);
        if (header.publicKey != null && !header.signatureValid) {
            Logger.error("Invalid signature for partition " + vbmetaPartitionName);
            addIssue(new VerificationIssue.InvalidSignature(vbmetaPartitionName));
        }
        // TODO: check if we have private key for header.publicKey
        for (int i = 0; i < header.descriptors.size(); i++) {
            var descriptor = header.descriptors.get(i);
            verifyDescriptor(vbmetaPartitionName, i, descriptor);
        }
    }

    public AvbVerifyResult recursiveVerify(String rootPartitionName) throws IOException {
        recursiveVerifyInternal(rootPartitionName);
        var records = cachedVbmetaImages.keySet().stream()
                .map(name -> new PartitionRecord(name, cachedVbmetaImages.get(name), cachedPartitionInfo.get(name).footer))
                .collect(Collectors.toMap(PartitionRecord::name, r -> r));
        return new AvbVerifyResult(rootPartitionName, records, new ArrayList<>(issues), new HashSet<>(partitionReferences));
    }

    private void addReference(String partitionName, String fromVbmetaPartition, int descriptorIndex) {
        var ref = new PartitionReference(partitionName, fromVbmetaPartition, descriptorIndex);
        partitionReferences.add(ref);
    }

    private void verifyDescriptor(String fromVbmetaPartition, int descriptorIndex, AvbDescriptor descriptor)
            throws IOException {
        if (descriptor instanceof HashDescriptor hd) {
            addReference(hd.partitionName, fromVbmetaPartition, descriptorIndex);
            verifyHashDescriptor(fromVbmetaPartition, descriptorIndex, hd);
        } else if (descriptor instanceof ChainPartitionDescriptor cpd) {
            addReference(cpd.partitionName, fromVbmetaPartition, descriptorIndex);
            verifyChainPartitionDescriptor(fromVbmetaPartition, descriptorIndex, cpd);
        } else if (descriptor instanceof HashTreeDescriptor htd) {
            Logger.warn("Ignoring HashTreeDescriptor for partition " + htd.partitionName);
        }
    }

    private void verifyChainPartitionDescriptor(String fromVbmetaPartition, int descriptorIndex,
                                                ChainPartitionDescriptor desc) throws IOException {
        Logger.info("Verifying chain partition " + desc.partitionName);
        var info = getPartitionInfo(desc.partitionName);
        if (info == null) {
            Logger.error("Chain partition " + desc.partitionName + " is not AVB-protected");
            addIssue(new VerificationIssue.InvalidPartitionData(desc.partitionName));
            // unable to verify further
        }
        var vbmeta = getVbmetaImage(desc.partitionName);
        if (vbmeta == null) {
            Logger.error("Failed to parse vbmeta of chain partition " + desc.partitionName);
            addIssue(new VerificationIssue.InvalidPartitionData(desc.partitionName));
            // unable to verify further
            return;
        }
        if (!vbmeta.signatureValid) {
            Logger.error("Chain partition " + desc.partitionName + " has invalid signature");
            addIssue(new VerificationIssue.InvalidSignature(desc.partitionName));
        }
        if (!vbmeta.publicKey.equals(desc.publicKey)) {
            Logger.error("Public key mismatch for chain partition " + desc.partitionName);
            addIssue(new VerificationIssue.PublicKeyMismatch(fromVbmetaPartition, descriptorIndex, vbmeta.publicKey));
        }
        recursiveVerifyInternal(desc.partitionName);
    }

    private void verifyHashDescriptor(String fromVbmetaPartition, int descriptorIndex, HashDescriptor desc)
            throws IOException {
        Logger.info("Verifying hash descriptor for partition " + desc.partitionName);
        // also verify footer if any
        var info = getPartitionInfo(desc.partitionName);
        var actualSize = desc.imageSize;
        var parent_mismatch = false;
        if (info != null && info.hasFooter()) {
            Logger.info("Verifying hash footer of partition " + desc.partitionName);
            var footer_mismatch = false;
            var newActualSize = info.footer.originalImageSize;
            if (newActualSize != actualSize) {
                actualSize = newActualSize;
                Logger.error("Footer original image size does not match descriptor for partition " + desc.partitionName);
                parent_mismatch = true;
            }
            var part_vbmeta = getVbmetaImage(desc.partitionName);
            if (part_vbmeta == null) {
                Logger.error("Failed to parse vbmeta of partition " + desc.partitionName);
                addIssue(new VerificationIssue.InvalidPartitionData(desc.partitionName));
                // unable to verify further
                return;
            }
            var desc_index = -1;
            for (int i = 0; i < part_vbmeta.descriptors.size(); i++) {
                var d = part_vbmeta.descriptors.get(i);
                if (d instanceof HashDescriptor hd && hd.partitionName.equals(desc.partitionName)) {
                    desc_index = i;
                }
            }
            if (desc_index == -1) {
                Logger.error("No matching hash descriptor in vbmeta of partition " + desc.partitionName);
                addIssue(new VerificationIssue.InvalidPartitionData(desc.partitionName));
                // unable to verify further
                return;
            }

            var embedded = (HashDescriptor) part_vbmeta.descriptors.get(desc_index);
            if (embedded.imageSize != actualSize) {
                footer_mismatch = true;
                Logger.error("Embedded descriptor image size does not match footer for partition " + desc.partitionName);
            }
            try (var part = provider.openPartition(desc.partitionName)) {
                part.position(0);
                var footer_verify = verifyHashDescriptorRaw(part, embedded, actualSize);
                if (!footer_verify.matches) {
                    footer_mismatch = true;
                    Logger.error("Hash mismatch for footer verification of partition " + desc.partitionName);
                }

                if (footer_mismatch) {
                    addIssue(
                            new VerificationIssue.HashMismatch(desc.partitionName, desc_index, actualSize, footer_verify.actualHash));
                }

            }
        }


        try (var part = provider.openPartition(desc.partitionName)) {
            part.position(0);
            var hash_verify = verifyHashDescriptorRaw(part, desc, actualSize);
            if (!hash_verify.matches) {
                parent_mismatch = true;
            }
            if (parent_mismatch) {
                addIssue(new VerificationIssue.HashMismatch(fromVbmetaPartition, descriptorIndex, actualSize,
                        hash_verify.actualHash));
                // skip hash verification on parent descriptor
                return;
            }
        }
    }


    public record PartitionReference(String partitionName, String referencedInVbmetaPartition,
                                     int descriptorIndex) {
    }

    private record VerifyHashResult(boolean matches, byte[] actualHash) {
    }
}
