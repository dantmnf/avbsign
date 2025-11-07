package xyz.cirno.avb;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import xyz.cirno.avb.util.Logger;

public class HashTreeDescriptor extends AvbDescriptor {
    public static final int FLAG_DO_NOT_USE_AB = (1 << 0);
    public static final int FLAG_CHECK_AT_MOST_ONCE = (1 << 1);
    public int dmVerityVersion;
    public long imageSize;
    public long treeOffset;
    public long treeSize;
    public int dataBlockSize;
    public int hashBlockSize;
    public int fecNumRoots;
    public long fecOffset;
    public long fecSize;
    public String hashAlgorithm;
    public String partitionName;
    public byte[] salt;
    public byte[] rootDigest;
    public int flags;
    public byte[] reserved = new byte[60];

    public HashTreeDescriptor() {
        super(TAG_HASHTREE);
    }

    static HashTreeDescriptor readFromPayload(ByteBuffer buf) {
        // The fixed-size part of the C struct is 164 bytes.
        final int FIXED_SIZE = 164;
        if (buf.remaining() < FIXED_SIZE) {
            return null;
        }
        Logger.debug("HashTreeDescriptor: read from %d bytes", buf.remaining() + DESCRIPTOR_HEADER_SIZE);
        var h = new HashTreeDescriptor();

        h.dmVerityVersion = buf.getInt();
        h.imageSize = buf.getLong();
        h.treeOffset = buf.getLong();
        h.treeSize = buf.getLong();
        h.dataBlockSize = buf.getInt();
        h.hashBlockSize = buf.getInt();
        h.fecNumRoots = buf.getInt();
        h.fecOffset = buf.getLong();
        h.fecSize = buf.getLong();

        var hashAlgBytes = new byte[32];
        buf.get(hashAlgBytes);
        int z = 0;
        while (z < hashAlgBytes.length && hashAlgBytes[z] != 0) z++;
        h.hashAlgorithm = new String(hashAlgBytes, 0, z, StandardCharsets.UTF_8);

        int partitionNameLen = buf.getInt();
        int saltLen = buf.getInt();
        int rootDigestLen = buf.getInt();
        h.flags = buf.getInt();

        buf.get(h.reserved);

        var partitionBytes = new byte[partitionNameLen];
        if (partitionNameLen > 0) buf.get(partitionBytes);
        h.partitionName = new String(partitionBytes, StandardCharsets.UTF_8);

        h.salt = new byte[saltLen];
        if (saltLen > 0) buf.get(h.salt);

        h.rootDigest = new byte[rootDigestLen];
        if (rootDigestLen > 0) buf.get(h.rootDigest);

        return h;
    }

    @Override
    public byte[] toByteArray() {
        var hashAlgBytes = new byte[32];
        if (hashAlgorithm != null) {
            var hb = hashAlgorithm.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(hb, 0, hashAlgBytes, 0, Math.min(hb.length, 32));
        }

        var partBytes = partitionName != null ? partitionName.getBytes(StandardCharsets.UTF_8) : new byte[0];
        var saltBytes = salt != null ? salt : new byte[0];
        var rootBytes = rootDigest != null ? rootDigest : new byte[0];

        final int FIXED_SIZE = 164; // as in C struct
        int bodyLen = FIXED_SIZE + partBytes.length + saltBytes.length + rootBytes.length;
        if (bodyLen % 8 != 0) bodyLen += 8 - (bodyLen % 8);
        int totalLen = 16 + bodyLen;

        Logger.debug("%s: marshaling to %d bytes", getClass(), totalLen);

        var buf = ByteBuffer.allocate(totalLen);
        buf.putLong(tag);
        buf.putLong(bodyLen);

        buf.putInt(dmVerityVersion);
        buf.putLong(imageSize);
        buf.putLong(treeOffset);
        buf.putLong(treeSize);
        buf.putInt(dataBlockSize);
        buf.putInt(hashBlockSize);
        buf.putInt(fecNumRoots);
        buf.putLong(fecOffset);
        buf.putLong(fecSize);

        buf.put(hashAlgBytes);

        buf.putInt(partBytes.length);
        buf.putInt(saltBytes.length);
        buf.putInt(rootBytes.length);
        buf.putInt(flags);

        // reserved must be exactly 60 bytes
        if (reserved != null && reserved.length >= 60) {
            buf.put(reserved, 0, 60);
        } else {
            buf.put(new byte[60]);
        }

        if (partBytes.length > 0) buf.put(partBytes);
        if (saltBytes.length > 0) buf.put(saltBytes);
        if (rootBytes.length > 0) buf.put(rootBytes);

        return buf.array();
    }
}
