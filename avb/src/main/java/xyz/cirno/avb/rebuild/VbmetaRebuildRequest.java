package xyz.cirno.avb.rebuild;

import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Objects;

import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.VerifiedBootFooter;
import xyz.cirno.avb.VerifiedBootMetaImage;
import xyz.cirno.avb.util.IOUtils;

public record VbmetaRebuildRequest(String partitionName, VerifiedBootMetaImage header,
                                   @Nullable VerifiedBootFooter footer,
                                   @Nullable AvbKeyPair signKey) {
    public void rebuildCopy(SeekableByteChannel originalImage, SeekableByteChannel newImage) throws IOException {
        if (footer == null) {
            newImage.position(0);
            var vbm = header.toByteArray(signKey);
            IOUtils.writeFully(newImage, ByteBuffer.wrap(vbm));
        } else {
            Objects.requireNonNull(originalImage);
            var buffer = ByteBuffer.allocate(262144);
            // copy original image
            var remaining = footer.originalImageSize;
            originalImage.position(0);
            newImage.position(0);
            while (remaining > 0) {
                var toRead = (int) Math.min(buffer.capacity(), remaining);
                buffer.clear();
                buffer.limit(toRead);
                IOUtils.readFully(originalImage, buffer);
                buffer.flip();
                IOUtils.writeFully(newImage, buffer);
                remaining -= toRead;
            }
            footer.vbmetaOffset = newImage.position();
            var vbm = header.toByteArray(signKey);
            IOUtils.writeFully(newImage, ByteBuffer.wrap(vbm));
            footer.vbmetaSize = vbm.length;
            // write footer
            newImage.position(originalImage.size() - VerifiedBootFooter.FOOTER_SIZE);
            var footerBytes = footer.toByteArray();
            IOUtils.writeFully(newImage, ByteBuffer.wrap(footerBytes));
        }
    }

    public void rebuildInplace(SeekableByteChannel image) throws IOException {
        Objects.requireNonNull(image);
        if (footer == null) {
            image.position(0);
            var vbm = header.toByteArray(signKey);
            IOUtils.writeFully(image, ByteBuffer.wrap(vbm));
        } else {
            // copy original image
            footer.vbmetaOffset = footer.originalImageSize;
            image.position(footer.vbmetaOffset);
            var vbm = header.toByteArray(signKey);
            IOUtils.writeFully(image, ByteBuffer.wrap(vbm));
            footer.vbmetaSize = vbm.length;
            // write footer
            image.position(image.size() - VerifiedBootFooter.FOOTER_SIZE);
            var footerBytes = footer.toByteArray();
            IOUtils.writeFully(image, ByteBuffer.wrap(footerBytes));
        }
    }
}
