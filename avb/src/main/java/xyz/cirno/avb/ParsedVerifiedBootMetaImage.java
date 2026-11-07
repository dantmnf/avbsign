package xyz.cirno.avb;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.util.List;

import xyz.cirno.avb.util.IOUtils;

public class ParsedVerifiedBootMetaImage extends VerifiedBootMetaImage {
    public AvbPublicKey publicKey;
    public byte[] digest;
    public byte[] signature;
    public boolean signatureValid;

    public ParsedVerifiedBootMetaImage(VerifiedBootHeader header, AvbPublicKey publicKey, List<AvbDescriptor> descriptors, byte[] digest, byte[] signature, boolean sigValid) {
        super();
        this.header = header;
        this.publicKey = publicKey;
        this.descriptors = descriptors;
        this.digest = digest;
        this.signature = signature;
        this.signatureValid = sigValid;
    }

    public static ParsedVerifiedBootMetaImage parseFromPartition(SeekableByteChannel ch) throws IOException {
        var info = AvbPartitionInfo.ofPartition(ch);
        if (info == null) {
            return null;
        }
        ch.position(info.vbmetaOffset);
        return parseFrom(ch);
    }

    @Override
    public ParsedVerifiedBootMetaImage clone() {
        return new ParsedVerifiedBootMetaImage(
                header.clone(),
                publicKey,
                descriptors.stream().map(AvbDescriptor::clone).toList(),
                digest == null ? null : digest.clone(),
                signature == null ? null : signature.clone(),
                signatureValid);
    }
}
