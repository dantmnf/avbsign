package xyz.cirno.avb;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.util.Logger;

public class VerifiedBootFooter {
    public static final int FOOTER_SIZE = 64;
    public int versionMajor;
    public int versionMinor;
    public long originalImageSize;
    public long vbmetaOffset;

    public long vbmetaSize;
    public final byte[] reserved = new byte[28];

    private static final int MAGIC = 0x41564266;  // big endian 'AVBf'

    public static VerifiedBootFooter parseFrom(ReadableByteChannel f) throws IOException {
        var buf = ByteBuffer.allocate(FOOTER_SIZE);
        IOUtils.readFully(f, buf);
        buf.flip();
        return parseFrom(buf);
    }

    public static VerifiedBootFooter parseFrom(ByteBuffer buf) {
        if (buf.remaining() < FOOTER_SIZE) {
            Logger.debug("footer buffer too small");
            return null;
        }
        var magic2 = buf.getInt();
        if (magic2 != MAGIC) {
            return null;
        }
        var result = new VerifiedBootFooter();
        result.versionMajor = buf.getInt();
        result.versionMinor = buf.getInt();
        result.originalImageSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(result.originalImageSize);
        result.vbmetaOffset = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(result.vbmetaOffset);
        result.vbmetaSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(result.vbmetaSize);
        buf.get(result.reserved);
        return result;
    }

}
