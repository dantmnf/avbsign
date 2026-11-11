package xyz.cirno.avbsign;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import rikka.shizuku.Shizuku;

/**
 * Holds the single Shizuku user-service binding shared by the whole process.
 * Activities register listeners instead of binding their own connections.
 * Implemented as a singleton.
 */
public final class AvbServiceManager {

    public interface Listener {
        /** Called on the main thread; service is null when unavailable. */
        void onServiceChanged(IAvbService service);
    }

    public interface ServiceAction<T> {
        T run(IAvbService svc) throws Exception;
    }

    public interface ResultHandler<T> {
        void onResult(T result, Exception error);
    }

    private static final AvbServiceManager INSTANCE = new AvbServiceManager();

    public static AvbServiceManager getInstance() {
        return INSTANCE;
    }

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    private volatile IAvbService service;
    private boolean binding;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
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

    private AvbServiceManager() {
        Shizuku.addBinderReceivedListenerSticky(() -> {
            ensureBound();
            notifyListeners();
        });
        Shizuku.addBinderDeadListener(() -> {
            binding = false;
            service = null;
            notifyListeners();
        });
        Shizuku.addRequestPermissionResultListener((requestCode, grantResult) -> {
            if (grantResult == PackageManager.PERMISSION_GRANTED) {
                ensureBound();
            }
            notifyListeners();
        });
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
        var svc = service;
        if (svc != null) {
            mainHandler.post(() -> listener.onServiceChanged(svc));
        }
        ensureBound();
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }

    public IAvbService getService() {
        return service;
    }

    public boolean isShizukuAvailable() {
        return Shizuku.pingBinder();
    }

    public boolean isShizukuGranted() {
        return Shizuku.pingBinder() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
    }

    public void requestPermission(int requestCode) {
        Shizuku.requestPermission(requestCode);
    }

    /** Bind the shared service if Shizuku is available and granted. */
    public void ensureBound() {
        if (service != null || binding || !isShizukuGranted()) {
            return;
        }
        var args = new Shizuku.UserServiceArgs(new ComponentName("xyz.cirno.avbsign", AvbService.class.getName()))
                .daemon(false)
                .processNameSuffix("service")
                .debuggable(false)
                .version(5);
        try {
            binding = true;
            Shizuku.bindUserService(args, serviceConnection);
        } catch (Throwable e) {
            binding = false;
        }
    }

    public <T> boolean run(ServiceAction<T> action, ResultHandler<T> handler) {
        if (!isShizukuGranted()) {
            return false;
        }
        var svc = service;
        if (svc == null) {
            ensureBound();
            return false;
        }
        executor.execute(() -> {
            try {
                var result = action.run(svc);
                mainHandler.post(() -> handler.onResult(result, null));
            } catch (Exception e) {
                mainHandler.post(() -> handler.onResult(null, e));
            }
        });
        return true;
    }

    private void notifyListeners() {
        mainHandler.post(() -> {
            var svc = service;
            for (var l : listeners) {
                l.onServiceChanged(svc);
            }
        });
    }
}
