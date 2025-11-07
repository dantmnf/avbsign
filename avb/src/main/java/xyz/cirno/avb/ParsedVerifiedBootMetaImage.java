package xyz.cirno.avb;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.util.Logger;

public class ParsedVerifiedBootMetaImage extends VerifiedBootMetaImage {
    public final AvbPublicKey publicKey;
    public final byte[] digest;
    public final byte[] signature;
    public final boolean signatureValid;

    public ParsedVerifiedBootMetaImage(VerifiedBootHeader header, AvbPublicKey publicKey, List<AvbDescriptor> descriptors, byte[] digest, byte[] signature, boolean sigValid) {
        super();
        this.header = header;
        this.publicKey = publicKey;
        this.descriptors = descriptors;
        this.digest = digest;
        this.signature = signature;
        this.signatureValid = sigValid;
    }

    public static ParsedVerifiedBootMetaImage readFrom(SeekableByteChannel ch) throws IOException {
        var magicBuf = ByteBuffer.allocate(4);
        IOUtils.readFully(ch, magicBuf);
        magicBuf.flip();
        var magic = magicBuf.getInt();
        if (magic == VerifiedBootHeader.AVB_MAGIC) {
            return readFrom(ch, 0);
        }
        // check for avb footer
        var footer = VerifiedBootFooter.readFrom(ch);
        if (footer == null) {
            return null;
        }
        return readFrom(ch, footer.vbmetaOffset);
    }

    public static ParsedVerifiedBootMetaImage readFrom(SeekableByteChannel ch, long offset) throws IOException {
        ch.position(offset);
        var headerBuf = ByteBuffer.allocate(VerifiedBootHeader.HEADER_SIZE);
        IOUtils.readFully(ch, headerBuf);
        headerBuf.flip();
        var header = VerifiedBootHeader.readFrom(headerBuf);
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
            publicKey = AvbPublicKey.readFrom(publicKeyBuf);
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

        while (digest != null) {
            Logger.info("verifying digest");
            MessageDigest hasher;
            try {
                hasher = MessageDigest.getInstance(header.algorithmType.getDigestAlgorithm());
            } catch (Exception e) {
                Logger.error("unsupported digest algorithm: " + header.algorithmType.getDigestAlgorithm());
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
                try {
                    var sig = Signature.getInstance(header.algorithmType.getSignatureAlgorithm());
                    sig.initVerify(publicKey.getPublicKey());
                    sig.update(headerBuf.array(), headerBuf.arrayOffset(), headerBuf.capacity());
                    sig.update(auxDataBuf.array(), auxDataBuf.arrayOffset(), auxDataBuf.capacity());
                    sigValid = sig.verify(signature);
                } catch (NoSuchAlgorithmException e) {
                    Logger.error("unsupported signature algorithm: " + header.algorithmType.getSignatureAlgorithm());
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
}
