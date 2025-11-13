package xyz.cirno.avb;// Moved to :avb module. This file intentionally left as a stub to avoid duplicate symbols.

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HashDescriptor extends AvbDescriptor {
    public static final int DESCRIPTOR_SIZE = 132;
    // Do not apply the default A/B partition logic to this partition.
    public static final int FLAG_DO_NOT_USE_AB = (1 << 0);
    public long imageSize;
    public String hashAlgorithm;
    public String partitionName;
    public byte[] salt;
    public byte[] digest;
    public int flags;
    public byte[] reserved = new byte[60];

    public HashDescriptor() {
        super(TAG_HASH);
    }

    // convenience constructor
    public HashDescriptor(long imageSize, String hashAlgorithm, String partitionName, byte[] salt, byte[] digest, int flags) {
        super(TAG_HASH);
        this.imageSize = imageSize;
        this.hashAlgorithm = hashAlgorithm;
        this.partitionName = partitionName;
        this.salt = salt != null ? Arrays.copyOf(salt, salt.length) : null;
        this.digest = digest != null ? Arrays.copyOf(digest, digest.length) : null;
        this.flags = flags;
    }

    static HashDescriptor parseFromPayload(ByteBuffer buf) {
        final int FIXED_SIZE = DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE;
        if (buf.remaining() < FIXED_SIZE) {
            return null;
        }
        var h = new HashDescriptor();

        h.imageSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.imageSize);

        var hashAlgBytes = new byte[32];
        buf.get(hashAlgBytes);
        int z = 0;
        while (z < hashAlgBytes.length && hashAlgBytes[z] != 0) z++;
        h.hashAlgorithm = new String(hashAlgBytes, 0, z, StandardCharsets.UTF_8);

        int partitionLen = buf.getInt();
        InvalidAvbDataException.checkUnsignedOverflow(partitionLen);
        int saltLen = buf.getInt();
        InvalidAvbDataException.checkUnsignedOverflow(saltLen);
        int digestLen = buf.getInt();
        InvalidAvbDataException.checkUnsignedOverflow(digestLen);
        h.flags = buf.getInt();

        buf.get(h.reserved);

        var partBytes = new byte[partitionLen];
        if (partitionLen > 0) buf.get(partBytes);
        h.partitionName = new String(partBytes, StandardCharsets.UTF_8);

        h.salt = new byte[saltLen];
        if (saltLen > 0) buf.get(h.salt);

        h.digest = new byte[digestLen];
        if (digestLen > 0) buf.get(h.digest);

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
        var digestBytes = digest != null ? digest : new byte[0];

        final int FIXED_SIZE = 116;
        int bodyLen = FIXED_SIZE + partBytes.length + saltBytes.length + digestBytes.length;
        if (bodyLen % 8 != 0) bodyLen += 8 - (bodyLen % 8);
        int totalLen = 16 + bodyLen;

        var buf = ByteBuffer.allocate(totalLen);
        buf.putLong(tag);
        buf.putLong(bodyLen);

        buf.putLong(imageSize);
        buf.put(hashAlgBytes);

        buf.putInt(partBytes.length);
        buf.putInt(saltBytes.length);
        buf.putInt(digestBytes.length);
        buf.putInt(flags);

        if (reserved != null && reserved.length >= 60) {
            buf.put(reserved, 0, 60);
        } else {
            buf.put(new byte[60]);
        }

        if (partBytes.length > 0) buf.put(partBytes);
        if (saltBytes.length > 0) buf.put(saltBytes);
        if (digestBytes.length > 0) buf.put(digestBytes);

        return buf.array();
    }
}
