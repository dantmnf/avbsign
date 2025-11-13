package xyz.cirno.avb;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public class VerifiedBootHeader {
    public static final int AVB_MAGIC = 0x41564230; // big endian 'AVB0'
    public static final int HEADER_SIZE = 256;

    public static final int FLAG_HASHTREE_DISABLED = (1 << 0);
    public static final int FLAG_VERIFICATION_DISABLED = (1 << 1);

    public int requiredLibavbVersionMajor;
    public int requiredLibavbVersionMinor;

    public long authenticationDataBlockSize;
    public long auxiliaryDataBlockSize;

    public AvbAlgorithmType algorithmType;

    public long hashOffset;
    public long hashSize;

    public long signatureOffset;
    public long signatureSize;

    public long publicKeyOffset;
    public long publicKeySize;

    public long publicKeyMetadataOffset;
    public long publicKeyMetadataSize;

    public long descriptorsOffset;
    public long descriptorsSize;

    public long rollbackIndex;

    public int flags;

    public int rollbackIndexLocation;

    public final byte[] releaseString = new byte[48];

    public final byte[] reserved = new byte[80];


    public static VerifiedBootHeader parseFrom(ByteBuffer buf) {
        if (buf.remaining() < HEADER_SIZE) {
            throw new BufferUnderflowException();
        }
        var magic2 = buf.getInt();
        if (magic2 != AVB_MAGIC) {
            throw new InvalidAvbDataException("AVB header magic mismatch");
        }

        var h = new VerifiedBootHeader();

        h.requiredLibavbVersionMajor = buf.getInt();
        h.requiredLibavbVersionMinor = buf.getInt();
        h.authenticationDataBlockSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.authenticationDataBlockSize);
        h.auxiliaryDataBlockSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.auxiliaryDataBlockSize);
        h.algorithmType = AvbAlgorithmType.fromInt(buf.getInt());
        h.hashOffset = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.hashOffset);
        h.hashSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.hashSize);
        h.signatureOffset = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.signatureOffset);
        h.signatureSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.signatureSize);
        h.publicKeyOffset = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.publicKeyOffset);
        h.publicKeySize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.publicKeySize);
        h.publicKeyMetadataOffset = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.publicKeyMetadataOffset);
        h.publicKeyMetadataSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.publicKeyMetadataSize);
        h.descriptorsOffset = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.descriptorsOffset);
        h.descriptorsSize = buf.getLong();
        InvalidAvbDataException.checkUnsignedOverflow(h.descriptorsSize);
        h.rollbackIndex = buf.getLong();
        h.flags = buf.getInt();
        h.rollbackIndexLocation = buf.getInt();
        buf.get(h.releaseString);
        buf.get(h.reserved);
        return h;
    }

    public byte[] toByteArray() {
        var buf = ByteBuffer.allocate(HEADER_SIZE);
        buf.putInt(AVB_MAGIC);
        buf.putInt(requiredLibavbVersionMajor);
        buf.putInt(requiredLibavbVersionMinor);

        buf.putLong(authenticationDataBlockSize);
        buf.putLong(auxiliaryDataBlockSize);

        buf.putInt(algorithmType.ordinal());

        buf.putLong(hashOffset);
        buf.putLong(hashSize);

        buf.putLong(signatureOffset);
        buf.putLong(signatureSize);

        buf.putLong(publicKeyOffset);
        buf.putLong(publicKeySize);

        buf.putLong(publicKeyMetadataOffset);
        buf.putLong(publicKeyMetadataSize);

        buf.putLong(descriptorsOffset);
        buf.putLong(descriptorsSize);

        buf.putLong(rollbackIndex);

        buf.putInt(flags);
        buf.putInt(rollbackIndexLocation);
        buf.put(releaseString);
        buf.put(reserved);
        return buf.array();
    }

    @Override
    public VerifiedBootHeader clone() {
        return parseFrom(ByteBuffer.wrap(toByteArray()));
    }
}
