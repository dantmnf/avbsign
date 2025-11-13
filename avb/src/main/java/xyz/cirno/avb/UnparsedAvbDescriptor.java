package xyz.cirno.avb;

import java.nio.ByteBuffer;

public class UnparsedAvbDescriptor extends AvbDescriptor {
    public byte[] payload;

    public UnparsedAvbDescriptor(long tag, byte[] payload) {
        super(tag);
        this.payload = payload;
    }

    @Override
    public byte[] toByteArray() {
        var len = 16 + payload.length;
        var buf = ByteBuffer.allocate(len);
        buf.putLong(tag);
        buf.putLong(payload.length);
        buf.put(payload);
        return buf.array();
    }
}
