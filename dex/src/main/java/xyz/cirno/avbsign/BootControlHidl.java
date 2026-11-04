package xyz.cirno.avbsign;

import android.os.HwBinder;
import android.os.HwParcel;
import android.os.IHwBinder;
import android.os.RemoteException;

public class BootControlHidl {
    public static final String kInterfaceName = "android.hardware.boot@1.2::IBootControl";

    private final IHwBinder remote;

    private BootControlHidl(IHwBinder conn) {
        remote = conn;
    }
    public static BootControlHidl getInstance() {
        try {
            var hwbinder = HwBinder.getService(kInterfaceName, "default", false);
            return new BootControlHidl(hwbinder);
        } catch (Exception e) {
            return null;
        }
    }

    public String getSuffix(int slot) throws RemoteException {
        var request = new HwParcel();
        request.writeInterfaceToken("android.hardware.boot@1.0::IBootControl");
        request.writeInt32(slot);
        var reply = new HwParcel();
        try {
            remote.transact(8, request, reply, 0);
            reply.verifySuccess();
            request.releaseTemporaryStorage();
            return reply.readString();
        } finally {
            reply.release();
        }
    }

    public int getActiveBootSlot() throws RemoteException {
        var request = new HwParcel();
        request.writeInterfaceToken("android.hardware.boot@1.2::IBootControl");
        var reply = new HwParcel();
        try {
            remote.transact(11, request, reply, 0);
            reply.verifySuccess();
            request.releaseTemporaryStorage();
            return reply.readInt32();
        } finally {
            reply.release();
        }
    }

}
