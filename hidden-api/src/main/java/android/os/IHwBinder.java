package android.os;

public interface IHwBinder {
    void transact(int i, HwParcel hwParcel, HwParcel hwParcel2, int i2) throws RemoteException;
}
