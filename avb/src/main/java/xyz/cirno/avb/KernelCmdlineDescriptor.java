package xyz.cirno.avb;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import xyz.cirno.avb.util.Logger;

public class KernelCmdlineDescriptor extends AvbDescriptor {
    public static final int FLAG_USE_ONLY_IF_HASHTREE_NOT_DISABLED = (1 << 0);
    public static final int FLAG_USE_ONLY_IF_HASHTREE_DISABLED = (1 << 1);
    public int flags;
    public String kernelCmdline;

    public KernelCmdlineDescriptor() {
        super(TAG_KERNEL_CMDLINE);
    }

    // convenience constructor
    public KernelCmdlineDescriptor(int flags, String kernelCmdline) {
        super(TAG_KERNEL_CMDLINE);
        this.flags = flags;
        this.kernelCmdline = kernelCmdline;
    }

    static KernelCmdlineDescriptor readFromPayload(ByteBuffer buf) {
        final int FIXED_SIZE = 8; // flags(4) + length(4)
        Logger.debug("KernelCmdlineDescriptor: read from %d bytes", buf.remaining() + DESCRIPTOR_HEADER_SIZE);
        if (buf.remaining() < FIXED_SIZE) return null;
        var h = new KernelCmdlineDescriptor();
        h.flags = buf.getInt();
        int len = buf.getInt();
        var cmdBytes = new byte[len];
        if (len > 0) buf.get(cmdBytes);
        h.kernelCmdline = new String(cmdBytes, StandardCharsets.UTF_8);
        return h;
    }

    @Override
    public byte[] toByteArray() {
        var cmdBytes = kernelCmdline != null ? kernelCmdline.getBytes(StandardCharsets.UTF_8) : new byte[0];
        int bodyLen = 8 + cmdBytes.length;
        if (bodyLen % 8 != 0) bodyLen += 8 - (bodyLen % 8);
        int totalLen = 16 + bodyLen;
        Logger.debug("%s: marshaling to %d bytes", getClass(), totalLen);
        var buf = ByteBuffer.allocate(totalLen);
        buf.putLong(tag);
        buf.putLong(bodyLen);
        buf.putInt(flags);
        buf.putInt(cmdBytes.length);
        if (cmdBytes.length > 0) buf.put(cmdBytes);
        return buf.array();
    }

}
