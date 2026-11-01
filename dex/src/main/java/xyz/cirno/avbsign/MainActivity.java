package xyz.cirno.avbsign;

import android.content.Intent;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import rikka.shizuku.Shizuku;

public class MainActivity extends BaseAvbActivity {

    private TextView statusView;
    private EditText patternInput;
    private TextView keysSummary;
    private TextView imagesSummary;
    private Spinner rootKeySpinner;
    private CheckBox backupCheck;
    private TextView logView;

    private int keyCount = -1;
    private int imageCount = -1;
    private final List<String> keyNames = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        applySystemBarInsets(findViewById(R.id.main_root));

        statusView = findViewById(R.id.status_view);
        patternInput = findViewById(R.id.pattern_input);
        keysSummary = findViewById(R.id.keys_summary);
        imagesSummary = findViewById(R.id.images_summary);
        rootKeySpinner = findViewById(R.id.root_key_spinner);
        backupCheck = findViewById(R.id.backup_check);
        logView = findViewById(R.id.log_view);

        findViewById(R.id.request_permission_button).setOnClickListener(v -> requestShizukuPermission());
        findViewById(R.id.manage_keys_button).setOnClickListener(v -> startActivity(new Intent(this, ManageFilesActivity.class)
                .putExtra(ManageFilesActivity.EXTRA_DIR, AvbPaths.KEYS_DIR)
                .putExtra(ManageFilesActivity.EXTRA_TITLE, "签名密钥")));
        findViewById(R.id.manage_images_button).setOnClickListener(v -> startActivity(new Intent(this, ManageFilesActivity.class)
                .putExtra(ManageFilesActivity.EXTRA_DIR, AvbPaths.BOOTLOADER_DIR)
                .putExtra(ManageFilesActivity.EXTRA_TITLE, "bootloader 镜像")));
        findViewById(R.id.check_button).setOnClickListener(v -> runCheck());
        findViewById(R.id.fix_button).setOnClickListener(v -> runFix());
        findViewById(R.id.flash_button).setOnClickListener(v -> runFlash());

        onShizukuAvailable();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshManagedFiles();
    }

    @Override
    protected void onShizukuStateChanged() {
        if (!Shizuku.pingBinder()) {
            statusView.setText("Shizuku 未运行");
        } else if (!isShizukuGranted()) {
            statusView.setText("Shizuku 正在运行，但尚未授权");
        } else {
            statusView.setText("Shizuku 已就绪（API " + Shizuku.getVersion() + "）");
        }
    }

    @Override
    protected void onServiceReady() {
        try {
            service.setLogCallback(logCallback);
            int uid = service.getUid();
            if (uid != 0) {
                log("警告：服务未以 root 运行（uid=" + uid + "），无法读写块设备。请使用由 root 启动的 Shizuku。");
            }
            if (patternInput.getText().toString().isEmpty()) {
                patternInput.setText("/dev/block/by-name/{}" + service.getSlotSuffix());
            }
        } catch (Exception e) {
            log("服务初始化失败：" + e);
        }
        refreshManagedFiles();
    }

    private final IAvbLogCallback.Stub logCallback = new IAvbLogCallback.Stub() {
        @Override
        public void onLog(int level, String msg) {
            log(msg);
        }
    };

    private void refreshManagedFiles() {
        var svc = service;
        if (svc == null) {
            return;
        }
        executor.execute(() -> {
            try {
                final var keys = svc.listFiles(AvbPaths.KEYS_DIR);
                final var images = svc.listFiles(AvbPaths.BOOTLOADER_DIR).length;
                mainHandler.post(() -> {
                    keyCount = keys.length;
                    imageCount = images;
                    keysSummary.setText("已导入 " + keys.length + " 个签名密钥");
                    imagesSummary.setText("已导入 " + images + " 个 bootloader 镜像");
                    updateRootKeySpinner(keys);
                });
            } catch (Exception ignored) {
            }
        });
    }

    private void updateRootKeySpinner(String[] keys) {
        var previous = rootKeySpinner.getSelectedItemPosition() > 0
                ? (String) rootKeySpinner.getSelectedItem()
                : null;
        keyNames.clear();
        keyNames.add("不替换根密钥");
        keyNames.addAll(Arrays.asList(keys));
        var adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, keyNames);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        rootKeySpinner.setAdapter(adapter);
        if (previous != null) {
            var index = keyNames.indexOf(previous);
            if (index > 0) {
                rootKeySpinner.setSelection(index);
            }
        }
    }

    private void runCheck() {
        var pattern = patternInput.getText().toString().trim();
        if (pattern.isEmpty()) {
            toast("请先填写路径模板");
            return;
        }
        runWithService(svc -> svc.check(pattern), (result, error) -> log(error != null ? "检查失败：" + error.getMessage() : result));
    }

    private void runFix() {
        var pattern = patternInput.getText().toString().trim();
        if (keyCount <= 0) {
            toast("请先导入签名密钥");
            return;
        }
        var backup = backupCheck.isChecked() ? AvbService.defaultBackupDir() : null;
        var selection = rootKeySpinner.getSelectedItemPosition();
        var rootKey = selection > 0 && selection < keyNames.size()
                ? AvbPaths.KEYS_DIR + "/" + keyNames.get(selection)
                : null;
        runWithService(svc -> svc.fix(pattern, AvbPaths.KEYS_DIR, rootKey, backup),
                (result, error) -> log(error != null ? "修复失败：" + error.getMessage() : result));
    }

    private void runFlash() {
        if (imageCount <= 0) {
            toast("请先导入要刷入的镜像");
            return;
        }
        var backup = backupCheck.isChecked() ? AvbService.defaultBackupDir() : null;
        runWithService(svc -> svc.replaceBootloaderImages(AvbPaths.BOOTLOADER_DIR, svc.getSlotSuffix(), backup),
                (result, error) -> log(error != null ? "刷写失败：" + error.getMessage() : result));
    }

    private void log(String msg) {
        mainHandler.post(() -> logView.append(msg + "\n"));
    }
}
