package xyz.cirno.avbsign;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;

/**
 * Minimal client for the android.hardware.boot.IBootControl AIDL HAL,
 * equivalent to the transactions performed by magisk/content/tools/bootctl-aidl.sh.
 */
public class BootControlAidl {
    public static final String kServiceName = "android.hardware.boot.IBootControl/default";
    public static final String kDescriptor = "android.hardware.boot.IBootControl";

    // transaction codes match bootctl-aidl.sh
    private static final int TRANSACTION_getActiveBootSlot = IBinder.FIRST_CALL_TRANSACTION;
    private static final int TRANSACTION_getSuffix = IBinder.FIRST_CALL_TRANSACTION + 4;

    private final IBinder remote;

    private BootControlAidl(IBinder binder) {
        remote = binder;
    }

    public static BootControlAidl getInstance() {
        try {
            var binder = ServiceManager.getService(kServiceName);
            return binder == null ? null : new BootControlAidl(binder);
        } catch (Throwable e) {
            return null;
        }
    }

    public int getActiveBootSlot() throws RemoteException {
        var request = Parcel.obtain();
        var reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(kDescriptor);
            remote.transact(TRANSACTION_getActiveBootSlot, request, reply, 0);
            reply.readException();
            return reply.readInt();
        } finally {
            request.recycle();
            reply.recycle();
        }
    }

    public String getSuffix(int slot) throws RemoteException {
        var request = Parcel.obtain();
        var reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(kDescriptor);
            request.writeInt(slot);
            remote.transact(TRANSACTION_getSuffix, request, reply, 0);
            reply.readException();
            return reply.readString();
        } finally {
            request.recycle();
            reply.recycle();
        }
    }
}
