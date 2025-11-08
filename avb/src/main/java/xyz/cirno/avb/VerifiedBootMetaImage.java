package xyz.cirno.avb;

import static xyz.cirno.avb.util.IOUtils.alignTo;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.List;

import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.util.Logger;

public class VerifiedBootMetaImage {
    public VerifiedBootHeader header;
    public List<AvbDescriptor> descriptors;
    public byte[] publicKeyMetadata;

    public static ParsedVerifiedBootMetaImage parseFrom(InputStream stream) throws IOException {
        return parseFrom(Channels.newChannel(stream));
    }

    public static ParsedVerifiedBootMetaImage parseFrom(ReadableByteChannel ch) throws IOException {
        var headerBuf = ByteBuffer.allocate(VerifiedBootHeader.HEADER_SIZE);
        IOUtils.readFully(ch, headerBuf);
        headerBuf.flip();
        var header = VerifiedBootHeader.parseFrom(headerBuf);
        if (header == null) {
            return null;
        }
        var authDataBuf = ByteBuffer.allocate((int) header.authenticationDataBlockSize);
        IOUtils.readFully(ch, authDataBuf);
        authDataBuf.flip();
        var auxDataBuf = ByteBuffer.allocate((int) header.auxiliaryDataBlockSize);
        IOUtils.readFully(ch, auxDataBuf);
        auxDataBuf.flip();

        AvbPublicKey publicKey = null;
        if (header.publicKeySize != 0) {
            var publicKeyBuf = IOUtils.slice(auxDataBuf, (int) header.publicKeyOffset, (int) header.publicKeySize);
            publicKey = AvbPublicKey.parseFrom(publicKeyBuf);
        }

        byte[] digest = null;
        byte[] signature = null;

        if (header.hashSize != 0) {
            var hashBuf = IOUtils.slice(authDataBuf, (int) header.hashOffset, (int) header.hashSize);
            digest = new byte[(int) header.hashSize];
            hashBuf.get(digest);
        }
        if (header.signatureSize != 0) {
            var sigBuf = IOUtils.slice(authDataBuf, (int) header.signatureOffset, (int) header.signatureSize);
            signature = new byte[(int) header.signatureSize];
            sigBuf.get(signature);
        }
        var descriptorBuf = IOUtils.slice(auxDataBuf, (int) header.descriptorsOffset, (int) header.descriptorsSize);
        var descriptors = new ArrayList<AvbDescriptor>();

        while (descriptorBuf.remaining() >= AvbDescriptor.DESCRIPTOR_HEADER_SIZE) {
            var desc = AvbDescriptor.parseFrom(descriptorBuf);
            descriptors.add(desc);
        }

        var sigValid = false;

        //noinspection LoopStatementThatDoesntLoop
        while (digest != null) {
            Logger.info("verifying digest");
            MessageDigest hasher;
            var digestAlgo = header.algorithmType.getDigestAlgorithm();
            if (digestAlgo == null) {
                Logger.warn("unsupported digest algorithm: " + header.algorithmType);
                break;
            }
            try {
                hasher = MessageDigest.getInstance(digestAlgo);
            } catch (Exception e) {
                Logger.error("unsupported digest algorithm: " + digestAlgo);
                break;
            }
            hasher.update(headerBuf.array(), headerBuf.arrayOffset(), headerBuf.capacity());
            hasher.update(auxDataBuf.array(), auxDataBuf.arrayOffset(), auxDataBuf.capacity());
            var computedDigest = hasher.digest();
            if (!MessageDigest.isEqual(digest, computedDigest)) {
                Logger.warn("digest mismatch");
            }
            if (signature != null && publicKey != null) {
                Logger.info("verifying signature");
                var signatureAlgorithm = header.algorithmType.getSignatureAlgorithm();
                if (signatureAlgorithm == null) {
                    Logger.warn("unsupported signature algorithm: " + header.algorithmType);
                    break;
                }
                try {
                    var sig = Signature.getInstance(signatureAlgorithm);
                    sig.initVerify(publicKey.getPublicKey());
                    sig.update(headerBuf.array(), headerBuf.arrayOffset(), headerBuf.capacity());
                    sig.update(auxDataBuf.array(), auxDataBuf.arrayOffset(), auxDataBuf.capacity());
                    sigValid = sig.verify(signature);
                } catch (NoSuchAlgorithmException e) {
                    Logger.error("unsupported signature algorithm: " + signatureAlgorithm);
                } catch (InvalidKeyException e) {
                    Logger.error("invalid public key: " + e.getMessage());
                } catch (Exception e) {
                    Logger.error("signature verification error: " + e.getMessage());
                }
                if (!sigValid) {
                    Logger.warn("signature invalid");
                } else {
                    Logger.info("signature valid");
                }
            } else {
                Logger.warn("the header contains digest but no signature or public key");
            }
            break;
        }
        return new ParsedVerifiedBootMetaImage(header, publicKey, descriptors, digest, signature, sigValid);
    }

    public byte[] toUnsignedByteArray() {
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

    public byte[] toSignedByteArray(RSAPrivateCrtKey privateKey) {
        if (header.algorithmType == AvbAlgorithmType.NONE) {
            throw new InvalidAvbDataException("cannot create signed header with algorithmType=NONE");
        }
        var pubkey = AvbPublicKey.fromPrivateKey(privateKey);
        var pubkeyBuf = pubkey.toByteArray();
        var metadataSize = publicKeyMetadata != null ? publicKeyMetadata.length : 0;
        var serializedDescriptors = descriptors.stream().map(AvbDescriptor::toByteArray).toList();
        var descriptorsSize = serializedDescriptors.stream().mapToInt(x->x.length).sum();
        var auxSize = alignTo(pubkeyBuf.length + metadataSize + descriptorsSize, 64);

        header.auxiliaryDataBlockSize = auxSize;
        header.hashOffset = 0;
        header.hashSize = header.algorithmType.getHashSize();
        header.signatureOffset = header.hashSize;
        header.signatureSize = header.algorithmType.getSignatureSize();
        header.authenticationDataBlockSize = alignTo(header.algorithmType.getAuthenticationBlockSize(), 64);
        header.publicKeyOffset = descriptorsSize;
        header.publicKeySize = pubkeyBuf.length;
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

        var totalSize = alignTo(headerBuf.length + authBuf.remaining() + auxBuf.remaining(), 4096);
        var buf = ByteBuffer.allocate(totalSize);
        buf.put(headerBuf);
        buf.put(authBuf);
        buf.put(auxBuf);
        return buf.array();
    }
}
