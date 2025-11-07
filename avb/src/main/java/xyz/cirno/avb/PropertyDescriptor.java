package xyz.cirno.avb;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import xyz.cirno.avb.util.Logger;

public class PropertyDescriptor extends AvbDescriptor {
    public String name;
    public String value;

    public PropertyDescriptor(String name, String value) {
        super(TAG_PROPERTY);
        this.name = name;
        this.value = value;
    }

    static PropertyDescriptor readFromPayload(ByteBuffer buf) {
        Logger.debug("PropertyDescriptor: read from %d bytes", buf.remaining() + DESCRIPTOR_HEADER_SIZE);
        var keyLen = buf.getLong();
        var valueLen = buf.getLong();
        var keyBytes = new byte[(int) keyLen];
        buf.get(keyBytes);
        assert buf.get() == 0;
        var valueBytes = new byte[(int) valueLen];
        buf.get(valueBytes);
        assert buf.get() == 0;
        var name = new String(keyBytes, StandardCharsets.UTF_8);
        var value = new String(valueBytes, StandardCharsets.UTF_8);
        return new PropertyDescriptor(name, value);
    }

    @Override
    public byte[] toByteArray() {
        var nameBytes = name.getBytes(StandardCharsets.UTF_8);
        var valueBytes = value.getBytes(StandardCharsets.UTF_8);
        var len = AvbDescriptor.DESCRIPTOR_HEADER_SIZE + 16 + nameBytes.length + 1 + valueBytes.length + 1;
        if (len % 8 != 0) {
            len += 8 - (len % 8);
        }
        Logger.debug("%s: marshaling to %d bytes", getClass(), len);
        var buf = ByteBuffer.allocate(len);
        buf.putLong(tag);
        buf.putLong(len - 16);
        buf.putLong(nameBytes.length);
        buf.putLong(valueBytes.length);
        buf.put(nameBytes);
        buf.put((byte) 0);
        buf.put(valueBytes);
        buf.put((byte) 0);
        return buf.array();
    }


}
