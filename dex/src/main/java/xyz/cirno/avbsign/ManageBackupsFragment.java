package xyz.cirno.avbsign;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

import androidx.annotation.Nullable;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.json.JSONException;
import org.json.JSONObject;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

public class ManageBackupsFragment extends BackupListFragment {
    private final ArrayList<JSONObject> backups = new ArrayList<>();

    @Override
    String pageTitle() {
        return "管理备份";
    }

    @Override
    public void onCreatePreferences(@Nullable Bundle state, @Nullable String rootKey) {
        var prefs = requireContext().getSharedPreferences(BackupSettings.PREFS, Context.MODE_PRIVATE);
        restoreSelection(state);
        var screen = getPreferenceManager().createPreferenceScreen(requireContext());
        setPreferenceScreen(screen);
        var settings = category("设置");
        screen.addPreference(settings);
        var auto = switchRow("修复签名时自动备份", "恢复自动备份后，还需要在 root 方案中还原对启动分区的修改");
        auto.setChecked(prefs.getBoolean(BackupSettings.AUTO, true));
        auto.setOnPreferenceChangeListener((p, value) -> {
            prefs.edit().putBoolean(BackupSettings.AUTO, (Boolean) value).apply();
            return true;
        });
        settings.addPreference(auto);
        listCategory = category("备份");
        screen.addPreference(listCategory);
        render();
    }

    @Override
    void refresh() {
        var activity = (BackupActivity) getActivity();
        if (activity == null || activity.service == null || busy || listCategory == null) return;
        int request = ++generation;
        loaded = false;
        status = "正在读取备份";
        render();
        activity.runWithService(IAvbService::listBackups, (result, error) -> {
            if (!isAdded() || activity.isFinishing() || request != generation) return;
            if (error != null) {
                status = "读取失败：" + error.getMessage();
            } else {
                try {
                    var parsed = new ArrayList<JSONObject>();
                    for (var entry : result) parsed.add(new JSONObject(entry));
                    parsed.sort((a, b) -> Long.compare(b.optLong("created"), a.optLong("created")));
                    backups.clear();
                    backups.addAll(parsed);
                    var ids = new ArrayList<String>();
                    for (var item : backups) ids.add(item.optString("id"));
                    selection.retainAll(ids);
                    loaded = true;
                    status = "";
                } catch (JSONException e) {
                    status = "读取备份失败：" + e.getMessage();
                }
            }
            render();
        });
    }

    @Override
    void render() {
        if (listCategory == null || !isAdded()) return;
        listCategory.removeAll();
        int order = 0;
        if (!loaded || backups.isEmpty()) {
            var info = row(!loaded ? status : "暂无备份", null);
            info.setSelectable(false);
            info.setOrder(order++);
            listCategory.addPreference(info);
        } else {
            for (var backup : backups) {
                var id = backup.optString("id");
                var fingerprint = backup.optString("fingerprint");
                var item = new SelectableRow(requireContext(), id, true);
                item.setLayoutResource(R.layout.backup_list_item);
                if (backup.has("error")) {
                    item.setTitle("备份损坏：" + id);
                    item.setSummary(backup.optString("error"));
                    item.setOrder(order++);
                    listCategory.addPreference(item);
                    continue;
                }
                item.setTitle(fingerprint.isEmpty() ? "未知 build fingerprint" : fingerprint);
                var current = backup.optString("currentSlot");
                var next = backup.optString("nextSlot");
                String ota = current.isEmpty() || next.isEmpty() ? "OTA 状态未知"
                        : current.equals(next) ? "" : "OTA 更新后备份";
                String match;
                if (backup.has("currentFingerprintError")) {
                    match = "读取当前槽位 vbmeta fingerprint 失败：" + backup.optString("currentFingerprintError");
                } else {
                    match = switch (backup.optString("fingerprintMatch")) {
                        case "MATCH" -> "与当前系统一致";
                        case "MISMATCH" -> "";
                        default -> "fingerprint 一致性未知";
                    };
                }
                var automatic = backup.has("automatic") && backup.optBoolean("automatic") ? "自动备份" : "";
                String[] summaryItems = {automatic, ota, backup.optJSONArray("partitions").length() + " 个分区", match};
                item.setSummary(String.join(" · ", Arrays.stream(summaryItems).filter(s -> !s.isEmpty()).toList()));
                item.setOrder(order++);
                item.setOnPreferenceClickListener(p -> { showBackup(backup); return true; });
                listCategory.addPreference(item);
            }
        }
        requireActivity().invalidateOptionsMenu();
    }

    private void showBackup(JSONObject backup) {
        var activity = (BackupActivity) requireActivity();
        var id = backup.optString("id");
        var names = backup.optJSONArray("partitions");
        var lines = new ArrayList<String>();
        for (int i = 0; i < names.length(); i++) lines.add(names.optString(i));
        var fingerprintLines = new ArrayList<String>();
        var fingerprintProperties = backup.optJSONArray("fingerprintProperties");
        if (fingerprintProperties != null) {
            for (int i = 0; i < fingerprintProperties.length(); i++) {
                var property = fingerprintProperties.optJSONObject(i);
                if (property != null) {
                    fingerprintLines.add(property.optString("name") + ": " + property.optString("value"));
                }
            }
        }
        var fingerprintText = !backup.optBoolean("fingerprintPropertiesAvailable")
                ? "旧备份未保存完整属性"
                : fingerprintLines.isEmpty() ? "无" : String.join("\n", fingerprintLines);
        var text = "创建时间：" + DateFormat.getDateTimeInstance().format(new Date(backup.optLong("created")))
                + "\n自动备份：" + (!backup.has("automatic") ? "未知" : backup.optBoolean("automatic") ? "是" : "否")
                + "\n当前启动槽位：" + backup.optString("currentSlot")
                + "\n下次启动槽位：" + backup.optString("nextSlot")
                + "\nBuild fingerprint：" + backup.optString("fingerprint", "")
                + "\nFingerprint 属性：\n" + fingerprintText
                + "\n来源路径模板：" + backup.optString("sourcePattern", "")
                + "\n备份分区：\n" + String.join("\n", lines);
        var message = new android.widget.TextView(requireContext());
        message.setText(text);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        message.setPadding(padding, padding, padding, padding);
        var scroll = new android.widget.ScrollView(requireContext());
        scroll.addView(message);
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle("备份详情")
                .setView(scroll)
                .setNegativeButton("关闭", null)
                .setPositiveButton("恢复备份", (dialog, which) -> activity.runWithService(
                        IAvbService::getCurrentSlot, (target, error) -> {
                            if (!isAdded()) return;
                            if (error != null || target == null || target.isEmpty()) {
                                activity.toast("读取当前启动槽位失败：" + (error == null ? "槽位为空" : error.getMessage()));
                                return;
                            }
                            new MaterialAlertDialogBuilder(requireContext())
                                    .setTitle("确认恢复")
                                    .setMessage("将覆盖当前启动槽位 " + target + " 的备份分区。恢复错误的备份可能导致设备无法启动。")
                                    .setNegativeButton("取消", null)
                                    .setPositiveButton("恢复", (d, w) -> startActivity(
                                            new Intent(requireContext(), OperationActivity.class)
                                                    .putExtra(OperationActivity.EXTRA_OPERATION, OperationActivity.RESTORE)
                                                    .putExtra(OperationActivity.EXTRA_BACKUP, id)
                                                    .putExtra(OperationActivity.EXTRA_SLOT, target)))
                                    .show();
                        }))
                .show();
    }

    @Override
    boolean canEditAction() {
        return super.canEditAction() && (!selection.isEditing() || loaded);
    }

    @Override
    void confirmDelete() {
        if (!canEditAction() || selection.isEmpty()) return;
        var selected = selection.snapshot();
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle("删除备份")
                .setMessage("所选备份将立即删除。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (d, w) -> {
                    var activity = (BackupActivity) requireActivity();
                    busy = true;
                    generation++;
                    render();
                    if (!activity.runWithService(svc -> ManagedFileDeleter.delete(selected, svc::deleteBackup),
                            (result, error) -> {
                                if (!isAdded()) return;
                                busy = false;
                                if (error == null) {
                                    selection.removeAll(result.deleted);
                                    if (result.errors.isEmpty()) selection.exit();
                                }
                                ManagedFileDeleter.showErrors(activity, result, error);
                                refresh();
                            })) {
                        busy = false;
                        render();
                    }
                }).show();
    }
}
