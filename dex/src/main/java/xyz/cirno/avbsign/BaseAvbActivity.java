package xyz.cirno.avbsign;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.LinearLayout;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import rikka.shizuku.Shizuku;

/**
 * Registers for the shared Shizuku user-service connection held by
 * {@link AvbServiceManager}. Subclasses override the callbacks to react to
 * state changes; they never bind their own connections.
 */
public abstract class BaseAvbActivity extends Activity {

    protected static final int REQUEST_CODE_PERMISSION = 1;

    protected final Handler mainHandler = new Handler(Looper.getMainLooper());
    protected final ExecutorService executor = Executors.newSingleThreadExecutor();

    protected volatile IAvbService service;

    private final Shizuku.OnRequestPermissionResultListener permissionResultListener = (requestCode, grantResult) -> {
        if (requestCode == REQUEST_CODE_PERMISSION) {
            onShizukuAvailable();
        }
    };

    private final AvbServiceManager.Listener serviceListener = svc -> {
        var becameReady = service == null && svc != null;
        service = svc;
        onShizukuStateChanged();
        if (becameReady) {
            onServiceReady();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Shizuku.addRequestPermissionResultListener(permissionResultListener);
        AvbServiceManager.addListener(serviceListener);
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permissionResultListener);
        AvbServiceManager.removeListener(serviceListener);
        executor.shutdownNow();
        super.onDestroy();
    }

    protected void onShizukuAvailable() {
        AvbServiceManager.ensureBound();
        onShizukuStateChanged();
    }

    /** Called on the main thread whenever Shizuku availability, permission, or the service may have changed. */
    protected void onShizukuStateChanged() {
    }

    /** Called on the main thread when the privileged service becomes connected. */
    protected void onServiceReady() {
    }

    protected boolean isShizukuGranted() {
        return AvbServiceManager.isShizukuGranted();
    }

    protected void requestShizukuPermission() {
        if (!Shizuku.pingBinder()) {
            toast("Shizuku 未运行");
            return;
        }
        if (Shizuku.checkSelfPermission() != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            if (Shizuku.shouldShowRequestPermissionRationale()) {
                toast("需要 Shizuku 权限才能执行底层操作");
            }
            Shizuku.requestPermission(REQUEST_CODE_PERMISSION);
        } else {
            onShizukuAvailable();
        }
    }

    protected interface ServiceAction<T> {
        T run(IAvbService svc) throws Exception;
    }

    protected interface ResultHandler<T> {
        void onResult(T result, Exception error);
    }

    /** Run an action on a worker thread; the handler is invoked on the main thread. */
    protected <T> void runWithService(ServiceAction<T> action, ResultHandler<T> handler) {
        if (!isShizukuGranted()) {
            toast("Shizuku 不可用或未授权");
            return;
        }
        var svc = service;
        if (svc == null) {
            AvbServiceManager.ensureBound();
            toast("服务尚未连接，请稍后再试");
            return;
        }
        executor.execute(() -> {
            try {
                var result = action.run(svc);
                mainHandler.post(() -> handler.onResult(result, null));
            } catch (Exception e) {
                mainHandler.post(() -> handler.onResult(null, e));
            }
        });
    }

    /** Pad the content view so it is not covered by the system navigation bar. */
    protected void applySystemBarInsets(android.view.View root) {
        var initialPaddingLeft = root.getPaddingLeft();
        var initialPaddingTop = root.getPaddingTop();
        var initialPaddingRight = root.getPaddingRight();
        var initialPaddingBottom = root.getPaddingBottom();
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            var bars = insets.getInsets(android.view.WindowInsets.Type.systemBars()
                    | android.view.WindowInsets.Type.displayCutout());
            v.setPadding(initialPaddingLeft + bars.left, initialPaddingTop + bars.top,
                    initialPaddingRight + bars.right, initialPaddingBottom + bars.bottom);
            return insets;
        });
    }

    protected LinearLayout.LayoutParams lp() {
        return new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    protected int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    protected void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
