package android.os;

import java.util.NoSuchElementException;

public class HwBinder implements IHwBinder {
    public static native IHwBinder getService(String str, String str2, boolean z) throws RemoteException, NoSuchElementException;
    @Override
    public native void transact(int i, HwParcel hwParcel, HwParcel hwParcel2, int i2) throws RemoteException;
}
