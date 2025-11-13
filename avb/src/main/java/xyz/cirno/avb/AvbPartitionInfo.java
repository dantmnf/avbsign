package xyz.cirno.avb;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.util.Logger;

public class AvbPartitionInfo {
    public final long vbmetaOffset;
    public final long footerOffset;
    public final VerifiedBootFooter footer;

    protected AvbPartitionInfo() {
        vbmetaOffset = 0;
        footerOffset = 0;
        footer = null;
    }

    protected AvbPartitionInfo(long footerOffset, VerifiedBootFooter footer) {
        this.footerOffset = footerOffset;
        this.footer = footer;
        this.vbmetaOffset = footer.vbmetaOffset;
    }

    public final boolean hasFooter() {
        return footer != null;
    }

    /**
     * @param ch the partition as {@link SeekableByteChannel}, will not change the position
     * @return {@link AvbPartitionInfo} if the partition is AVB-protected, otherwise null
     * @throws java.io.IOException from {@link SeekableByteChannel}
     */
    public static AvbPartitionInfo ofPartition(SeekableByteChannel ch) throws IOException {
        var magicBuf = ByteBuffer.allocate(4);
        ch.position(0);
        IOUtils.readFully(ch, magicBuf);
        magicBuf.flip();
        var magic = magicBuf.getInt();
        if (magic == VerifiedBootHeader.AVB_MAGIC) {
            return new AvbPartitionInfo();
        }
        // check for avb footer
        var len = ch.size();
        if (len < VerifiedBootFooter.FOOTER_SIZE) {
            Logger.debug("image too small");
            return null;
        }
        var offset = len - VerifiedBootFooter.FOOTER_SIZE;
        var footerBuf = ByteBuffer.allocate(VerifiedBootFooter.FOOTER_SIZE);
        ch.position(offset);
        IOUtils.readFully(ch, footerBuf);
        footerBuf.flip();
        var footer = VerifiedBootFooter.parseFrom(footerBuf);
        if (footer == null) {
            return null;
        }
        if (footer.originalImageSize > len) {
            Logger.warn("footer.originalImageSize larger than partition");
            return null;
        }
        if (footer.vbmetaOffset + footer.vbmetaSize > len) {
            Logger.warn("vbmeta outside the partition");
            return null;
        }
        return new AvbPartitionInfo(offset, footer);
    }
}
