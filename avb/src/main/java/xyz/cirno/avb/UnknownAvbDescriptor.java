package xyz.cirno.avb;

import java.nio.ByteBuffer;

import xyz.cirno.avb.util.Logger;

public class UnknownAvbDescriptor extends AvbDescriptor {
    public byte[] payload;

    public UnknownAvbDescriptor(long tag, byte[] payload) {
        super(tag);
        Logger.debug("%s: created with tag=%d, length=%d", getClass(), tag, payload.length + DESCRIPTOR_HEADER_SIZE);
        this.payload = payload;
    }

    @Override
    public byte[] toByteArray() {
        var len = 16 + payload.length;
        Logger.debug("%s: marshaling to %d bytes", getClass(), len);
        var buf = ByteBuffer.allocate(len);
        buf.putLong(tag);
        buf.putLong(payload.length);
        buf.put(payload);
        return buf.array();
    }



}
