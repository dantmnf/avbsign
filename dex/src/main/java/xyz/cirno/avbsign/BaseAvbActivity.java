package xyz.cirno.avbsign;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import rikka.shizuku.Shizuku;

/**
 * Registers for the shared Shizuku user-service connection held by
 * {@link AvbServiceManager}. Subclasses override the callbacks to react to
 * state changes; they never bind their own connections.
 */
public abstract class BaseAvbActivity extends AppCompatActivity {

    protected static final int REQUEST_CODE_PERMISSION = 1;

    protected final Handler mainHandler = new Handler(Looper.getMainLooper());
    protected volatile IAvbService service;

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
        AvbServiceManager.getInstance().addListener(serviceListener);
    }

    @Override
    protected void onDestroy() {
        AvbServiceManager.getInstance().removeListener(serviceListener);
        super.onDestroy();
    }

    protected void onShizukuAvailable() {
        AvbServiceManager.getInstance().ensureBound();
        onShizukuStateChanged();
    }

    /** Called on the main thread whenever Shizuku availability, permission, or the service may have changed. */
    protected void onShizukuStateChanged() {
    }

    /** Called on the main thread when the privileged service becomes connected. */
    protected void onServiceReady() {
    }

    protected boolean isShizukuGranted() {
        return AvbServiceManager.getInstance().isShizukuGranted();
    }

    protected void requestShizukuPermission() {
        if (!AvbServiceManager.getInstance().isShizukuAvailable()) {
            toast("Shizuku 未运行");
            return;
        }
        if (!isShizukuGranted()) {
            if (Shizuku.shouldShowRequestPermissionRationale()) {
                toast("需要 Shizuku 权限才能执行底层操作");
            }
            AvbServiceManager.getInstance().requestPermission(REQUEST_CODE_PERMISSION);
        } else {
            onShizukuAvailable();
        }
    }

    /** Run an action on a worker thread; the handler is invoked on the main thread. */
    protected <T> boolean runWithService(AvbServiceManager.ServiceAction<T> action,
                                         AvbServiceManager.ResultHandler<T> handler) {
        if (!isShizukuGranted()) {
            toast("Shizuku 不可用或未授权");
            return false;
        }
        if (service == null) {
            AvbServiceManager.getInstance().ensureBound();
            toast("服务尚未连接，请稍后再试");
            return false;
        }
        return AvbServiceManager.getInstance().run(action, handler);
    }

    /** Pad the content view so it is not covered by the system navigation bar. */
    protected void applySystemBarInsets(View root) {
        var initialPaddingLeft = root.getPaddingLeft();
        var initialPaddingTop = root.getPaddingTop();
        var initialPaddingRight = root.getPaddingRight();
        var initialPaddingBottom = root.getPaddingBottom();
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            var bars = insets.getInsets(WindowInsets.Type.systemBars()
                    | WindowInsets.Type.displayCutout());
            v.setPadding(initialPaddingLeft + bars.left, initialPaddingTop + bars.top,
                    initialPaddingRight + bars.right, initialPaddingBottom + bars.bottom);
            return insets;
        });
    }

    protected void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
