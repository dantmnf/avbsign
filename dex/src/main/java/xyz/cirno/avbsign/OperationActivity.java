package xyz.cirno.avbsign;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;

public class OperationActivity extends BaseAvbActivity {
    static final String EXTRA_OPERATION = "operation";
    static final String EXTRA_PATTERN = "pattern";
    static final String EXTRA_ROOT_KEY = "root_key";
    static final String EXTRA_BACKUP = "backup";
    static final String EXTRA_CURRENT = "current";
    static final String EXTRA_PARTITIONS = "partitions";
    static final String EXTRA_REPLACE_BOOTLOADER = "replace_bootloader";
    static final String EXTRA_SLOT = "slot";
    static final String CHECK = "check";
    static final String FIX = "fix";
    static final String BACKUP = "backup";
    static final String RESTORE = "restore";

    private OperationModel model;
    private ImageButton backButton;
    private TextView logView;
    private ScrollView scrollView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_operation);
        applySystemBarInsets(findViewById(R.id.operation_root));
        backButton = findViewById(R.id.operation_back);
        logView = findViewById(R.id.operation_log);
        scrollView = findViewById(R.id.operation_scroll);
        model = new ViewModelProvider(this).get(OperationModel.class);
        backButton.setOnClickListener(v -> getOnBackPressedDispatcher().onBackPressed());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (model.state.isFinished()) {
                    finish();
                }
            }
        });
        model.observer = this::render;
        model.start(getIntent(), savedInstanceState != null);
        render();
    }

    private void render() {
        logView.setText(model.state.log());
        backButton.setEnabled(model.state.isFinished());
        scrollView.post(() -> scrollView.fullScroll(View.FOCUS_DOWN));
    }

    @Override
    protected void onDestroy() {
        model.observer = null;
        super.onDestroy();
    }

    public static class OperationModel extends ViewModel {
        private final Handler handler = new Handler(Looper.getMainLooper());
        private final OperationState state = new OperationState();
        private Runnable observer;
        private String orderingError;
        private String operationResult;
        private boolean operationEnded;

        private void start(Intent intent, boolean restored) {
            if (!state.start()) {
                return;
            }
            if (restored) {
                complete("运行状态已丢失，请检查操作结果后再试。");
                return;
            }
            var svc = AvbServiceManager.getInstance().getService();
            if (!AvbServiceManager.getInstance().isShizukuGranted() || svc == null) {
                complete("服务不可用，操作未开始。");
                return;
            }
            append("正在运行...");
            new Thread(() -> run(svc, intent)).start();
        }

        private void run(IAvbService svc, Intent intent) {
            var operation = intent.getStringExtra(EXTRA_OPERATION);
            var failure = CHECK.equals(operation) ? "检查失败："
                    : FIX.equals(operation) ? "修复失败：" : BACKUP.equals(operation) ? "备份失败："
                    : RESTORE.equals(operation) ? "恢复失败：" : "操作失败：";
            var callback = new IAvbLogCallback.Stub() {
                @Override
                public void onLog(long sequence, int level, String message) {
                    handler.post(() -> appendLog(sequence, message));
                }
            };
            String result;
            try {
                int uid = svc.getUid();
                if (uid != 0) {
                    handler.post(() -> append("警告：服务未以 root 运行（uid=" + uid
                            + "），无法读写块设备。请使用由 root 启动的 Shizuku。"));
                }
                svc.setLogCallback(callback);
                var backup = intent.getStringExtra(EXTRA_BACKUP);
                if (CHECK.equals(operation)) {
                    result = svc.check(intent.getStringExtra(EXTRA_PATTERN));
                } else if (FIX.equals(operation)) {
                    result = svc.fix(intent.getStringExtra(EXTRA_PATTERN), AvbPaths.KEYS_DIR,
                            intent.getStringExtra(EXTRA_ROOT_KEY), backup,
                            intent.getBooleanExtra(EXTRA_REPLACE_BOOTLOADER, false),
                            intent.getBooleanExtra(EXTRA_CURRENT, false),
                            intent.getStringArrayExtra(EXTRA_PARTITIONS));
                } else if (BACKUP.equals(operation)) {
                    result = svc.createBackup(intent.getStringArrayExtra(EXTRA_PARTITIONS),
                            intent.getStringExtra(EXTRA_SLOT));
                } else if (RESTORE.equals(operation)) {
                    result = svc.restoreBackup(backup, intent.getStringExtra(EXTRA_SLOT));
                } else {
                    throw new IllegalArgumentException("未知操作：" + operation);
                }
            } catch (Exception e) {
                result = failure + e;
            }
            try {
                long lastSequence = svc.setLogCallback(null);
                var finalResult = result;
                handler.post(() -> finishAfterLogs(lastSequence, finalResult));
            } catch (Exception e) {
                var finalResult = result + "\n停止接收日志失败，日志可能不完整：" + e;
                handler.post(() -> complete(finalResult));
            }
        }

        private void appendLog(long sequence, String message) {
            if (state.isFinished() || orderingError != null) {
                return;
            }
            try {
                state.appendLog(sequence, message);
            } catch (IllegalArgumentException e) {
                orderingError = e.getMessage();
                if (operationEnded) {
                    complete(operationResult + "\n日志接收失败：" + orderingError);
                }
                return;
            }
            if (observer != null) {
                observer.run();
            }
        }

        private void finishAfterLogs(long lastSequence, String result) {
            if (state.isFinished()) {
                return;
            }
            operationEnded = true;
            operationResult = result;
            if (orderingError != null) {
                complete(result + "\n日志接收失败：" + orderingError);
                return;
            }
            try {
                state.finishAfterLogs(lastSequence, result);
            } catch (IllegalArgumentException e) {
                complete(result + "\n日志接收失败：" + e.getMessage());
                return;
            }
            if (observer != null) {
                observer.run();
            }
        }

        private void append(String message) {
            state.append(message);
            if (observer != null) {
                observer.run();
            }
        }

        private void complete(String result) {
            state.complete(result);
            if (observer != null) {
                observer.run();
            }
        }
    }
}
