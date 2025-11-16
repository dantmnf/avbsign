package xyz.cirno.avb;

import java.io.IOException;
import java.io.RandomAccessFile;

public class AndroidBootImage {
    private RandomAccessFile f;

    private static final byte[] ANDROID_BOOT_MAGIC = {
            0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x21 // "ANDROID!"
    };

    private static final byte[] VENDOR_BOOT_MAGIC = {
            // "VNDRBOOT"
            0x56, 0x4E, 0x44, 0x52, 0x42, 0x4F, 0x4F, 0x54
    };


    public enum ImageType {
        BOOT,
        VENDOR
    }

    private ImageType type;

    private AndroidBootImage(RandomAccessFile f, ImageType type) {
        this.f = f;
        this.type = type;
    }

    public static AndroidBootImage tryAttach(RandomAccessFile f) throws IOException {
        var magic = new byte[8];
        f.seek(0);
        var len = f.read(magic);
        if (len != 8) {
            return null;
        }
        if (java.util.Arrays.equals(magic, ANDROID_BOOT_MAGIC)) {
            return new AndroidBootImage(f, ImageType.BOOT);
        } else if (java.util.Arrays.equals(magic, VENDOR_BOOT_MAGIC)) {
            return new AndroidBootImage(f, ImageType.VENDOR);
        } else {
            return null;
        }
    }

    private static long toUIntLE(int x) {
        var rev = Integer.reverseBytes(x);
        return ((long) rev) & 0x0FFFFFFFFL;
    }

    private static long readUIntLE(RandomAccessFile f) throws IOException {
        var rev = Integer.reverseBytes(f.readInt());
        return ((long) rev) & 0x0FFFFFFFFL;
    }

    private static long roundToPage(long size, long pageSize) {
        return ((size + pageSize - 1) / pageSize) * pageSize;
    }

    public long calcuateSize() {
        // https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/android16-release/include/bootimg/bootimg.h
        try {
            if (type == ImageType.BOOT) {
                f.seek(0x28);
                var headerVersion = Integer.reverseBytes(f.readInt());
                if (headerVersion <= 2) {
                    f.seek(8);
                    var kernelSize = readUIntLE(f);
                    f.seek(16);
                    var ramdiskSize = readUIntLE(f);
                    f.seek(24);
                    var secondSize = readUIntLE(f);
                    f.seek(36);
                    var pageSize = Integer.reverseBytes(f.readInt());
                    if (headerVersion == 0) {
                        return pageSize
                                + roundToPage(kernelSize, pageSize)
                                + roundToPage(ramdiskSize, pageSize)
                                + roundToPage(secondSize, pageSize);
                    }
                    f.seek(1632);
                    var recoveryDtboSize = readUIntLE(f);
                    if (headerVersion == 1) {
                        return pageSize
                                + roundToPage(kernelSize, pageSize)
                                + roundToPage(ramdiskSize, pageSize)
                                + roundToPage(secondSize, pageSize)
                                + roundToPage(recoveryDtboSize, pageSize);
                    }
                    // version 2
                    f.seek(1648);
                    var dtbSize = readUIntLE(f);
                    return pageSize
                            + roundToPage(kernelSize, pageSize)
                            + roundToPage(ramdiskSize, pageSize)
                            + roundToPage(secondSize, pageSize)
                            + roundToPage(recoveryDtboSize, pageSize)
                            + roundToPage(dtbSize, pageSize);
                } else if (headerVersion <= 4) {
                    f.seek(8);
                    var kernelSize = readUIntLE(f);
                    var ramdiskSize = readUIntLE(f);
                    if (headerVersion == 3) {
                        return 4096 + roundToPage(kernelSize, 4096) + roundToPage(ramdiskSize, 4096);
                    }
                    // version 4
                    f.seek(1580);
                    var sigSize = readUIntLE(f);
                    return 4096 + roundToPage(kernelSize, 4096) + roundToPage(ramdiskSize, 4096) + roundToPage(sigSize, 4096);
                }
                // unknown header version, fallthrough
            } else if (type == ImageType.VENDOR) {
                f.seek(8);
                var headerVersion = Integer.reverseBytes(f.readInt());
                if (headerVersion == 3 || headerVersion == 4) {
                    f.seek(12);
                    var pageSize = Integer.reverseBytes(f.readInt());
                    f.seek(24);
                    var ramdiskSize = readUIntLE(f);
                    f.seek(2100);
                    var dtbSize = readUIntLE(f);
                    if (headerVersion == 3) {
                        return roundToPage(2112, pageSize)
                                + roundToPage(ramdiskSize, pageSize)
                                + roundToPage(dtbSize, pageSize);
                    }
                    // version 4
                    f.seek(2112);
                    var ramdiskTableSize = readUIntLE(f);
                    f.seek(2124);
                    var bootConfigSize = readUIntLE(f);
                    return roundToPage(2128, pageSize)
                            + roundToPage(ramdiskSize, pageSize)
                            + roundToPage(dtbSize, pageSize)
                            + roundToPage(ramdiskTableSize, pageSize)
                            + roundToPage(bootConfigSize, pageSize);
                }
            }
        } catch (IOException ignore) {
        }
        return -1;
    }
}
