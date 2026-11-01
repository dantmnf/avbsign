package xyz.cirno.avbsign;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import rikka.shizuku.Shizuku;

/**
 * Holds the single Shizuku user-service binding shared by the whole process.
 * Activities register listeners instead of binding their own connections.
 */
public final class AvbServiceManager {

    public interface Listener {
        /** Called on the main thread; service is null when unavailable. */
        void onServiceChanged(IAvbService service);
    }

    private static final Handler mainHandler = new Handler(Looper.getMainLooper());
    private static final List<Listener> listeners = new CopyOnWriteArrayList<>();

    private static volatile IAvbService service;
    private static boolean binding;
    private static boolean shizukuListenersRegistered;

    private AvbServiceManager() {
    }

    private static final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            binding = false;
            if (binder == null || !binder.pingBinder()) {
                return;
            }
            service = IAvbService.Stub.asInterface(binder);
            notifyListeners();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            binding = false;
            service = null;
            notifyListeners();
        }
    };

    private static void registerShizukuListeners() {
        if (shizukuListenersRegistered) {
            return;
        }
        shizukuListenersRegistered = true;
        Shizuku.addBinderReceivedListenerSticky(() -> {
            ensureBound();
            notifyStateChanged();
        });
        Shizuku.addBinderDeadListener(() -> {
            binding = false;
            service = null;
            notifyStateChanged();
        });
    }

    public static void addListener(Listener listener) {
        registerShizukuListeners();
        listeners.add(listener);
        var svc = service;
        if (svc != null) {
            mainHandler.post(() -> listener.onServiceChanged(svc));
        }
        ensureBound();
    }

    public static void removeListener(Listener listener) {
        listeners.remove(listener);
    }

    public static IAvbService getService() {
        return service;
    }

    public static boolean isShizukuGranted() {
        return Shizuku.pingBinder() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
    }

    /** Bind the shared service if Shizuku is available and granted. */
    public static void ensureBound() {
        if (service != null || binding || !isShizukuGranted()) {
            return;
        }
        var args = new Shizuku.UserServiceArgs(new ComponentName("xyz.cirno.avbsign", AvbService.class.getName()))
                .daemon(false)
                .processNameSuffix("service")
                .debuggable(false)
                .version(1);
        try {
            binding = true;
            Shizuku.bindUserService(args, serviceConnection);
        } catch (Throwable e) {
            binding = false;
        }
    }

    private static void notifyListeners() {
        var svc = service;
        mainHandler.post(() -> {
            for (var l : listeners) {
                l.onServiceChanged(svc);
            }
        });
    }

    private static void notifyStateChanged() {
        mainHandler.post(() -> {
            for (var l : listeners) {
                l.onServiceChanged(service);
            }
        });
    }
}
