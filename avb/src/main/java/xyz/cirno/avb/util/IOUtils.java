package xyz.cirno.avb.util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class IOUtils {
    public static void readFully(ReadableByteChannel ch, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            int read = ch.read(buf);
            if (read == -1) {
                throw new IOException("Unexpected end of stream");
            }
        }
    }

    public static void readFullyAt(FileChannel ch, ByteBuffer buf, long pos) throws IOException {
        while (buf.hasRemaining()) {
            int read = ch.read(buf, pos);
            if (read == -1) {
                throw new IOException("Unexpected end of stream");
            }
            pos += read;
        }
    }

    public static void writeFully(WritableByteChannel ch, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            ch.write(buf);
        }
    }

    public static byte[] readArray(ReadableByteChannel ch, int size) throws IOException {
        var buf = ByteBuffer.allocate(size);
        readFully(ch, buf);
        return buf.array();
    }

    public static byte[] getArray(ByteBuffer buf, int size) throws IOException {
        var result = new byte[size];
        buf.get(result);
        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        var sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String sha256ToHex(byte[] data) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        var hash = digest.digest(data);
        return bytesToHex(hash);
    }

    public static ByteBuffer slice(ByteBuffer orig, int offset, int count) {
        if (orig.hasArray()) {
            var arr = orig.array();
            var offset2 = orig.arrayOffset() + offset;
            return ByteBuffer.wrap(arr, offset2, count);
        } else {
            var buf2 = orig.duplicate();
            buf2.clear();
            buf2.position(offset);
            buf2.limit(offset + count);
            return buf2.slice();
        }
    }

    public static long alignTo(long value, long alignment) {
        var rem = value % alignment;
        if (rem == 0) {
            return value;
        } else {
            return value + alignment - rem;
        }
    }

    public static int alignTo(int value, int alignment) {
        var rem = value % alignment;
        if (rem == 0) {
            return value;
        } else {
            return value + alignment - rem;
        }
    }
}
