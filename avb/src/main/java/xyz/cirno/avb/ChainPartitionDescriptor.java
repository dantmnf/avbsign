package xyz.cirno.avb;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class ChainPartitionDescriptor extends AvbDescriptor {
    public static final int DESCRIPTOR_SIZE = 92;

    // Do not apply the default A/B partition logic to this partition.
    public static final int FLAG_DO_NOT_USE_AB = (1 << 0);

    public int rollbackIndexLocation;
    public String partitionName;
    public AvbPublicKey publicKey;
    public int flags;
    public byte[] reserved = new byte[60];

    public ChainPartitionDescriptor() {
        super(TAG_CHAIN_PARTITION);
    }

    public ChainPartitionDescriptor(int rollbackIndexLocation, String partitionName, AvbPublicKey publicKey, int flags) {
        super(TAG_CHAIN_PARTITION);
        this.rollbackIndexLocation = rollbackIndexLocation;
        this.partitionName = partitionName;
        this.publicKey = publicKey;
        this.flags = flags;
    }

    static ChainPartitionDescriptor parseFromPayload(ByteBuffer buf) {
        if (buf.remaining() < DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE) return null;
        var h = new ChainPartitionDescriptor();
        h.rollbackIndexLocation = buf.getInt();
        int partitionLen = buf.getInt();
        InvalidAvbDataException.checkUnsignedOverflow(partitionLen);
        int pubKeyLen = buf.getInt();
        InvalidAvbDataException.checkUnsignedOverflow(pubKeyLen);
        h.flags = buf.getInt();
        buf.get(h.reserved);

        var partBytes = new byte[partitionLen];
        if (partitionLen > 0) buf.get(partBytes);
        h.partitionName = new String(partBytes, StandardCharsets.UTF_8);

        var publicKeyBytes = new byte[pubKeyLen];
        if (pubKeyLen > 0) buf.get(publicKeyBytes);

        h.publicKey = AvbPublicKey.parseFrom(ByteBuffer.wrap(publicKeyBytes));

        return h;
    }

    @Override
    public byte[] toByteArray() {
        var partBytes = partitionName != null ? partitionName.getBytes(StandardCharsets.UTF_8) : new byte[0];
        var keyBytes = publicKey != null ? publicKey.toByteArray() : new byte[0];

        int bodyLen = DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE + partBytes.length + keyBytes.length;
        if (bodyLen % 8 != 0) bodyLen += 8 - (bodyLen % 8);
        int totalLen = 16 + bodyLen;

        var buf = ByteBuffer.allocate(totalLen);

        buf.putLong(tag);
        buf.putLong(bodyLen);

        buf.putInt(rollbackIndexLocation);
        buf.putInt(partBytes.length);
        buf.putInt(keyBytes.length);
        buf.putInt(flags);

        if (reserved != null && reserved.length >= 60) buf.put(reserved, 0, 60);
        else buf.put(new byte[60]);

        if (partBytes.length > 0) buf.put(partBytes);
        if (keyBytes.length > 0) buf.put(keyBytes);

        return buf.array();
    }
}
