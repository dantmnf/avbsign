package xyz.cirno.avb;

import java.nio.ByteBuffer;

import xyz.cirno.avb.util.Logger;

public abstract class AvbDescriptor {
    public static final int DESCRIPTOR_HEADER_SIZE = 16;
    public static final long TAG_PROPERTY = 0;
    public static final long TAG_HASHTREE = 1;
    public static final long TAG_HASH = 2;
    public static final long TAG_KERNEL_CMDLINE = 3;
    public static final long TAG_CHAIN_PARTITION = 4;

    public final long tag;

    protected AvbDescriptor(long tag) {
        this.tag = tag;
    }

    public abstract byte[] toByteArray();

    public static AvbDescriptor parseFrom(byte[] buf) {
        return parseFrom(ByteBuffer.wrap(buf));
    }

    public static AvbDescriptor parseFrom(ByteBuffer buf) {
        var tag = buf.getLong();
        var numBytesFollowing = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(numBytesFollowing);
        if (numBytesFollowing > buf.remaining()) {
            throw new InvalidAvbDataException("descriptor size overflow");
        }
        var payload = new byte[(int) numBytesFollowing];
        var buf2 = ByteBuffer.wrap(payload);
        buf.get(payload);

        if (tag == TAG_PROPERTY) {
            return PropertyDescriptor.parseFromPayload(buf2);
        } else if (tag == TAG_HASHTREE) {
            return HashTreeDescriptor.parseFromPayload(buf2);
        } else if (tag == TAG_HASH) {
            return HashDescriptor.parseFromPayload(buf2);
        } else if (tag == TAG_KERNEL_CMDLINE) {
            return KernelCmdlineDescriptor.parseFromPayload(buf2);
        } else if (tag == TAG_CHAIN_PARTITION) {
            return ChainPartitionDescriptor.parseFromPayload(buf2);
        } else {
            Logger.warn("Unknown AVB descriptor tag: " + tag);
            return new UnparsedAvbDescriptor(tag, payload);
        }
    }

    @Override
    public AvbDescriptor clone() {
        return parseFrom(ByteBuffer.wrap(toByteArray()));
    }
}
