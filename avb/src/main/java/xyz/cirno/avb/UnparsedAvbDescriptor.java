package xyz.cirno.avb;

import java.nio.ByteBuffer;

import xyz.cirno.avb.util.Logger;

public class UnparsedAvbDescriptor extends AvbDescriptor {
    public byte[] payload;

    public UnparsedAvbDescriptor(long tag, byte[] payload) {
        super(tag);
        Logger.debug("UnparsedAvbDescriptor: created with tag=%d, length=%d", tag, payload.length + DESCRIPTOR_HEADER_SIZE);
        this.payload = payload;
    }

    @Override
    public byte[] toByteArray() {
        var len = 16 + payload.length;
        Logger.debug("UnparsedAvbDescriptor: marshaling to %d bytes", len);
        var buf = ByteBuffer.allocate(len);
        buf.putLong(tag);
        buf.putLong(payload.length);
        buf.put(payload);
        return buf.array();
    }



}
