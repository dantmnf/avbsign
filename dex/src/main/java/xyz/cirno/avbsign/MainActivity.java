package xyz.cirno.avbsign;

import android.content.Intent;
import android.os.Bundle;
import android.os.SystemProperties;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.widget.SwitchCompat;

import rikka.shizuku.Shizuku;

public class MainActivity extends BaseAvbActivity {

    private TextView statusView;
    private EditText patternInput;
    private TextView keysSummary;
    private int keyCount = -1;
    private TextView nextSlotView;
    private TextView currentSlotView;
    private SwitchCompat replaceSwitch;
    private TextView sourceSummary;
    private TextView partitionsSummary;
    private TextView rootKeySummary;
    private boolean launchingOperation;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        applySystemBarInsets(findViewById(R.id.main_root));

        statusView = findViewById(R.id.status_view);
        patternInput = findViewById(R.id.pattern_input);
        keysSummary = findViewById(R.id.keys_summary);
        currentSlotView = findViewById(R.id.currentSlotView);
        nextSlotView = findViewById(R.id.nextSlotView);
        replaceSwitch = findViewById(R.id.replaceBootloaderSwitch);
        sourceSummary = findViewById(R.id.replacement_source_summary);
        partitionsSummary = findViewById(R.id.replacement_partitions_summary);
        rootKeySummary = findViewById(R.id.replacement_key_summary);
        replaceSwitch.setChecked(BootloaderSettings.preferences(this).getBoolean(BootloaderSettings.ENABLED, false));
        replaceSwitch.setOnCheckedChangeListener((button, checked) ->
                BootloaderSettings.preferences(this).edit().putBoolean(BootloaderSettings.ENABLED, checked).apply());

        currentSlotView.setText(SystemProperties.get("ro.boot.slot_suffix", ""));

        findViewById(R.id.request_permission_button).setOnClickListener(v -> requestShizukuPermission());
        findViewById(R.id.manage_keys_button).setOnClickListener(v -> startActivity(new Intent(this, ManageFilesActivity.class)
                .putExtra(ManageFilesActivity.EXTRA_DIR, AvbPaths.KEYS_DIR)
                .putExtra(ManageFilesActivity.EXTRA_TITLE, "签名密钥")));
        findViewById(R.id.replacement_settings_button).setOnClickListener(v ->
                startActivity(new Intent(this, BootloaderSettingsActivity.class)));
        findViewById(R.id.check_button).setOnClickListener(v -> runCheck());
        findViewById(R.id.fix_button).setOnClickListener(v -> runFix());
        findViewById(R.id.start_backup_button).setOnClickListener(v ->
                startActivity(new Intent(this, BackupActivity.class)));
        findViewById(R.id.manage_backups_button).setOnClickListener(v ->
                startActivity(new Intent(this, BackupActivity.class).putExtra(BackupActivity.EXTRA_MANAGE, true)));

        onShizukuAvailable();
    }

    @Override
    protected void onResume() {
        super.onResume();
        launchingOperation = false;
        refreshManagedFiles();
        refreshReplacementSummary();
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
            int uid = service.getUid();
            if (uid != 0) {
                toast("警告：服务未以 root 运行（uid=" + uid + "），无法读写块设备。请使用由 root 启动的 Shizuku。");
            }
            var nextSlot = service.getSlotSuffix();
            nextSlotView.setText(nextSlot);
            if (patternInput.getText().toString().isEmpty()) {
                patternInput.setText("/dev/block/by-name/{}" + nextSlot);
            }
        } catch (Exception e) {
            toast("服务初始化失败：" + e);
        }
        refreshManagedFiles();
    }

    private void refreshManagedFiles() {
        var svc = service;
        if (svc == null) {
            return;
        }
        executor.execute(() -> {
            try {
                final var keys = svc.listFiles(AvbPaths.KEYS_DIR);
                mainHandler.post(() -> {
                    keyCount = keys.length;
                    keysSummary.setText("已导入 " + keys.length + " 个签名密钥");
                });
            } catch (Exception e) {
                mainHandler.post(() -> {
                    keyCount = -1;
                    keysSummary.setText("读取密钥失败：" + e.getMessage());
                });
            }
        });
    }

    private void refreshReplacementSummary() {
        var prefs = BootloaderSettings.preferences(this);
        var current = BootloaderSettings.CURRENT.equals(prefs.getString(BootloaderSettings.SOURCE,
                BootloaderSettings.CURRENT));
        sourceSummary.setText(current ? "当前启动槽位" : "外部文件");
        partitionsSummary.setText(current ? String.join(", ", BootloaderSettings.partitions(prefs)) : "外部 .img 文件");
        var key = prefs.getString(BootloaderSettings.ROOT_KEY, null);
        rootKeySummary.setText(key == null || key.isEmpty() ? "未选择" : key);
    }

    private void runCheck() {
        var pattern = patternInput.getText().toString().trim();
        if (pattern.isEmpty()) {
            toast("请先填写路径模板");
            return;
        }
        launchOperation(new Intent(this, OperationActivity.class)
                .putExtra(OperationActivity.EXTRA_OPERATION, OperationActivity.CHECK)
                .putExtra(OperationActivity.EXTRA_PATTERN, pattern));
    }

    private void runFix() {
        var pattern = patternInput.getText().toString().trim();
        if (pattern.isEmpty()) {
            toast("请先填写路径模板");
            return;
        }
        if (keyCount <= 0) {
            toast("请先导入签名密钥");
            return;
        }
        var backup = getSharedPreferences(BackupSettings.PREFS, MODE_PRIVATE)
                .getBoolean(BackupSettings.AUTO, true) ? AvbService.defaultBackupDir() : null;
        var prefs = BootloaderSettings.preferences(this);
        var key = prefs.getString(BootloaderSettings.ROOT_KEY, null);
        var rootKey = replaceSwitch.isChecked() && key != null && !key.isEmpty()
                ? AvbPaths.KEYS_DIR + "/" + key : null;
        var current = BootloaderSettings.CURRENT.equals(prefs.getString(BootloaderSettings.SOURCE,
                BootloaderSettings.CURRENT));
        launchOperation(new Intent(this, OperationActivity.class)
                .putExtra(OperationActivity.EXTRA_OPERATION, OperationActivity.FIX)
                .putExtra(OperationActivity.EXTRA_PATTERN, pattern)
                .putExtra(OperationActivity.EXTRA_ROOT_KEY, rootKey)
                .putExtra(OperationActivity.EXTRA_REPLACE_BOOTLOADER, replaceSwitch.isChecked())
                .putExtra(OperationActivity.EXTRA_CURRENT, current)
                .putExtra(OperationActivity.EXTRA_PARTITIONS,
                        BootloaderSettings.partitions(prefs).toArray(new String[0]))
                .putExtra(OperationActivity.EXTRA_BACKUP, backup));
    }

    private void launchOperation(Intent intent) {
        if (launchingOperation) {
            return;
        }
        if (!isShizukuGranted()) {
            toast("Shizuku 不可用或未授权");
            return;
        }
        if (service == null) {
            AvbServiceManager.getInstance().ensureBound();
            toast("服务尚未连接，请稍后再试");
            return;
        }
        launchingOperation = true;
        startActivity(intent);
    }
}
