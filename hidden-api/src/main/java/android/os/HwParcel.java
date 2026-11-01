package android.os;

public class HwParcel {
    public final native void enforceInterface(String str);

    public final native boolean readBool();


    public final native double readDouble();

    public final native float readFloat();

    public final native short readInt16();

    public final native int readInt32();

    public final native long readInt64();

    public final native byte readInt8();

    public final native String readString();

    public final native IHwBinder readStrongBinder();

    public final native void release();

    public final native void releaseTemporaryStorage();

    public final native void send();

    public final native void verifySuccess();

    public final native void writeBool(boolean z);

    public final native void writeDouble(double d);

    public final native void writeFloat(float f);

    public final native void writeInt16(short s);

    public final native void writeInt32(int i);

    public final native void writeInt64(long j);

    public final native void writeInt8(byte b);

    public final native void writeInterfaceToken(String str);

    public final native void writeStatus(int i);

    public final native void writeString(String str);

    public final native void writeStrongBinder(IHwBinder iHwBinder);

    private HwParcel(boolean allocate) {
        throw new RuntimeException("Stub!");
    }

    public HwParcel() {
        throw new RuntimeException("Stub!");
    }
}
