package xyz.cirno.avb;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

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

    private static final int magic = 0x41564266;

    public static VerifiedBootFooter readFrom(SeekableByteChannel f) throws IOException {
        var len = f.size();
        if (len < FOOTER_SIZE) {
            Logger.debug("image too small");
            return null;
        }
        var offset = len - FOOTER_SIZE;
        f.position(offset);

        var buf = ByteBuffer.allocate(FOOTER_SIZE);
        IOUtils.readFully(f, buf);
        buf.flip();
        return readFrom(buf);
    }

    public static VerifiedBootFooter readFrom(ByteBuffer buf) {
        if (buf.remaining() < FOOTER_SIZE) {
            Logger.debug("footer buffer too small");
            return null;
        }
        var magic2 = buf.getInt();
        if (magic2 != magic) {
            return null;
        }
        var result = new VerifiedBootFooter();
        result.versionMajor = buf.getInt();
        result.versionMinor = buf.getInt();
        result.originalImageSize = buf.getLong();
        result.vbmetaOffset = buf.getLong();
        result.vbmetaSize = buf.getLong();
        buf.get(result.reserved);
        return result;
    }

}
