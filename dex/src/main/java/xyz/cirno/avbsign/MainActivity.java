package xyz.cirno.avbsign;

import android.content.Intent;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.SystemProperties;
import android.util.Log;
import android.view.Menu;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.widget.SwitchCompat;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.Arrays;

import rikka.shizuku.Shizuku;

public class MainActivity extends BaseAvbActivity {

    private TextView statusView;
    private TextView patternView;
    private TextView keysSummary;
    private int keyCount = -1;
    private TextView nextSlotView;
    private TextView currentSlotView;
    private SwitchCompat replaceSwitch;
    private TextView sourceSummary;
    private TextView partitionsSummary;
    private TextView rootKeySummary;
    private boolean launchingOperation;

    private String customPattern;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        applySystemBarInsets(findViewById(R.id.main_root));

        statusView = findViewById(R.id.status_view);
        patternView = findViewById(R.id.pattern_view);
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
    public boolean onCreateOptionsMenu(Menu menu) {
        var item = menu.add("分区路径模板");
        item.setOnMenuItemClickListener(v -> {
            var builder = new MaterialAlertDialogBuilder(this);
            var context = builder.getContext();
            var edit = new EditText(context);
            edit.setSingleLine(true);
            if (customPattern != null && !customPattern.isEmpty()) {
                edit.setText(customPattern);
            }
            var container = new LinearLayout(context);
            int inset = (int) (24 * context.getResources().getDisplayMetrics().density);
            container.setPadding(inset, 0, inset, 0);
            container.addView(edit, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
            builder.setTitle("分区路径模板");
            builder.setView(container);
            builder.setPositiveButton("确定", (dialog, which) -> {
                var pattern = edit.getText().toString().trim();
                if (!pattern.contains("{}")) {
                    new MaterialAlertDialogBuilder(MainActivity.this)
                            .setTitle("无效的路径模板")
                            .setMessage("路径模板必须包含 {} 占位符")
                            .setPositiveButton("确定", null)
                            .show();
                    return;
                }
                updatePartitionPattern(pattern);
            });
            builder.setNegativeButton("取消", null);
            builder.setNeutralButton("默认", (dialog, which) -> updatePartitionPattern(null));
            builder.show();
            return true;
        });
        return true;
    }

    @Override
    protected void onResume() {
        super.onResume();
        launchingOperation = false;
        refreshPatternView();
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
            findViewById(R.id.request_permission_button).setEnabled(false);
        }
    }

    @Override
    protected void onServiceReady() {
        try {
            int uid = service.getUid();
            if (uid != 0) {
                toast("警告：服务未以 root 运行（uid=" + uid + "），无法读写块设备。请使用由 root 启动的 Shizuku。");
            }
            mainHandler.post(() -> {
                refreshPatternView();
                refreshReplacementSummary();
            });
        } catch (Exception e) {
            toast("服务初始化失败：" + e);
        }
        refreshManagedFiles();
    }

    private void updatePartitionPattern(String value) {
        customPattern = (value == null || value.isEmpty()) ? null : value;
        refreshPatternView();
    }

    private String getActiveBootSlotOrDefault() {
        var svc = service;
        if (svc == null) {
            return "_a";
        }
        try {
            return svc.getActiveSlotSuffix();
        } catch (RemoteException e) {
            Log.e("MainActivity", "Failed to refresh active boot slot", e);
            return "_a";
        }
    }

    private String getEffectivePattern() {
        if (customPattern == null || customPattern.isEmpty()) {
            return "/dev/block/by-name/{}" + getActiveBootSlotOrDefault();
        }
        return customPattern;
    }

    private void refreshPatternView() {
        nextSlotView.setText(getActiveBootSlotOrDefault());
        patternView.setText(getEffectivePattern());
    }

    private void refreshManagedFiles() {
        AvbServiceManager.getInstance().run(svc -> svc.listFiles(AvbPaths.KEYS_DIR), (keys, error) -> {
            if (error != null) {
                keyCount = -1;
                keysSummary.setText("读取密钥失败：" + error.getMessage());
            } else {
                keyCount = keys.length;
                keysSummary.setText("已导入 " + keys.length + " 个签名密钥");
            }
        });
    }

    private String[] getBootloaderImageNames() {
        var svc = service;
        if (svc == null) {
            return new String[0];
        }
        try {
            return svc.listFiles(AvbPaths.BOOTLOADER_DIR);
        } catch (Exception e) {
            Log.e("MainActivity", "Failed to get bootloader image names", e);
            return new String[0];
        }
    }

    private void refreshReplacementSummary() {
        var prefs = BootloaderSettings.preferences(this);
        var current = BootloaderSettings.CURRENT.equals(prefs.getString(BootloaderSettings.SOURCE,
                BootloaderSettings.CURRENT));
        sourceSummary.setText(current ? "当前启动槽位" : "外部文件");
        if (current) {
            partitionsSummary.setText(String.join(", ", BootloaderSettings.partitions(prefs)));
        } else {
            var partitions = Arrays.stream(getBootloaderImageNames())
                    .map(x -> x.endsWith(".img") ? x.substring(0, x.length() - 4) : x)
                    .toArray(String[]::new);
            partitionsSummary.setText(partitions.length == 0 ? "无" : String.join(", ", partitions));
        }
        var key = prefs.getString(BootloaderSettings.ROOT_KEY, null);
        rootKeySummary.setText(key == null || key.isEmpty() ? "未选择" : key);
    }

    private void runCheck() {
        var pattern = getEffectivePattern();
        if (pattern.isEmpty()) {
            toast("请先填写路径模板");
            return;
        }
        launchOperation(new Intent(this, OperationActivity.class)
                .putExtra(OperationActivity.EXTRA_OPERATION, OperationActivity.CHECK)
                .putExtra(OperationActivity.EXTRA_PATTERN, pattern));
    }

    private void runFix() {
        var pattern = getEffectivePattern();
        if (pattern.isEmpty()) {
            toast("请先填写路径模板");
            return;
        }
        if (keyCount <= 0) {
            toast("请先导入签名密钥");
            return;
        }
        var autoBackup = getSharedPreferences(BackupSettings.PREFS, MODE_PRIVATE)
                .getBoolean(BackupSettings.AUTO, true);
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
                .putExtra(OperationActivity.EXTRA_AUTO_BACKUP, autoBackup));
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
