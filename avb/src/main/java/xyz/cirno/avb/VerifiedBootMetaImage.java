package xyz.cirno.avb;

import static xyz.cirno.avb.util.IOUtils.alignTo;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.List;

public class VerifiedBootMetaImage {
    public VerifiedBootHeader header;
    public List<AvbDescriptor> descriptors;
    public byte[] publicKeyMetadata;

    public byte[] asUnsignedByteArray() {
        var serializedDescriptors = descriptors.stream().map(AvbDescriptor::toByteArray).toList();
        var descSize = serializedDescriptors.stream().mapToInt(x->x.length).sum();
        var auxSize = alignTo(descSize, 64);

        header.authenticationDataBlockSize = 0;
        header.auxiliaryDataBlockSize = auxSize;
        header.algorithmType = AvbAlgorithmType.NONE;
        header.hashOffset = 0;
        header.hashSize = 0;
        header.signatureOffset = 0;
        header.signatureSize = 0;
        header.publicKeyOffset = 0;
        header.publicKeySize = 0;
        header.publicKeyMetadataOffset = 0;
        header.publicKeyMetadataSize = 0;
        header.descriptorsOffset = 0;
        header.descriptorsSize = descSize;
        var headerBuf = header.toByteArray();

        var totalSize = headerBuf.length + auxSize;
        var buf = ByteBuffer.allocate(totalSize);
        buf.put(headerBuf);
        for (var desc : serializedDescriptors) {
            buf.put(desc);
        }
        return buf.array();
    }

    public byte[] asSignedByteArray(RSAPrivateCrtKey privateKey) {
        if (header.algorithmType == AvbAlgorithmType.NONE) {
            throw new InvalidAvbDataException("cannot create signed header with algorithmType=NONE");
        }
        var pubkey = AvbPublicKey.fromPrivateKey(privateKey);
        var pubkeyBuf = pubkey.asByteBuffer();
        var metadataSize = publicKeyMetadata != null ? publicKeyMetadata.length : 0;
        var serializedDescriptors = descriptors.stream().map(AvbDescriptor::toByteArray).toList();
        var descriptorsSize = serializedDescriptors.stream().mapToInt(x->x.length).sum();
        var auxSize = alignTo(pubkeyBuf.remaining() + metadataSize + descriptorsSize, 64);


        header.auxiliaryDataBlockSize = auxSize;
        header.hashOffset = 0;
        header.hashSize = header.algorithmType.getHashSize();
        header.signatureOffset = header.hashSize;
        header.signatureSize = header.algorithmType.getSignatureSize();
        header.authenticationDataBlockSize = alignTo(header.algorithmType.getAuthenticationBlockSize(), 64);
        header.publicKeyOffset = descriptorsSize;
        header.publicKeySize = pubkeyBuf.remaining();
        header.publicKeyMetadataOffset = header.publicKeyOffset + header.publicKeySize;
        header.publicKeyMetadataSize = metadataSize;
        header.descriptorsOffset = 0;
        header.descriptorsSize = descriptorsSize;

        var headerBuf = header.toByteArray();
        var auxBuf = ByteBuffer.allocate(auxSize);
        for (var desc : serializedDescriptors) {
            auxBuf.put(desc);
        }
        auxBuf.put(pubkeyBuf);
        if (publicKeyMetadata != null) {
            auxBuf.put(publicKeyMetadata);
        }
        auxBuf.position(0);

        var digestAlgorithm = header.algorithmType.getDigestAlgorithm();
        if (digestAlgorithm == null) {
            throw new InvalidAvbDataException("invalid algorithmType");
        }
        MessageDigest hasher;
        try {
            hasher = MessageDigest.getInstance(digestAlgorithm);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get digest instance", e);
        }
        hasher.update(headerBuf);
        hasher.update(auxBuf.duplicate());
        var digest = hasher.digest();
        var authBuf = ByteBuffer.allocate((int)header.authenticationDataBlockSize);
        authBuf.put(digest);

        try {
            var algo = header.algorithmType.getSignatureAlgorithm();
            assert algo != null;
            var sig = Signature.getInstance(algo);
            sig.initSign(privateKey);
            sig.update(headerBuf);
            sig.update(auxBuf.duplicate());
            var signature = sig.sign();
            authBuf.put(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get signature instance", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("invalid private key", e);
        } catch (SignatureException e) {
            throw new RuntimeException("Failed to sign digest", e);
        }

        authBuf.position(0);

        var totalSize = headerBuf.length + authBuf.remaining() + auxBuf.remaining();
        var buf = ByteBuffer.allocate(totalSize);
        buf.put(headerBuf);
        buf.put(authBuf);
        buf.put(auxBuf);
        return buf.array();
    }
}
