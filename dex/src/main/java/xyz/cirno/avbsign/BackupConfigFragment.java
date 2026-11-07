package xyz.cirno.avbsign;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

public class BackupConfigFragment extends BackupListFragment {
    private final ArrayList<String> partitions = new ArrayList<>();
    private final ArrayList<String> dependencies = new ArrayList<>();
    private String slot = "";
    private PreferenceCategory dependencyCategory;
    private Preference runPreference;

    @Override
    String pageTitle() {
        return "备份配置";
    }

    @Override
    public void onCreatePreferences(@Nullable Bundle state, @Nullable String rootKey) {
        var prefs = requireContext().getSharedPreferences(BackupSettings.PREFS, Context.MODE_PRIVATE);
        partitions.addAll(prefs.getStringSet(BackupSettings.PARTITIONS, Set.of("boot")));
        partitions.sort(String::compareTo);
        restoreSelection(state);
        var screen = getPreferenceManager().createPreferenceScreen(requireContext());
        setPreferenceScreen(screen);
        listCategory = category("备份分区");
        screen.addPreference(listCategory);
        dependencyCategory = category("关联的 vbmeta 分区");
        screen.addPreference(dependencyCategory);
        var actions = category("操作");
        screen.addPreference(actions);
        runPreference = row("开始备份", "读取下次启动槽位");
        runPreference.setOnPreferenceClickListener(p -> {
            if (!loaded || busy || selection.isEditing()) return true;
            var intent = new Intent(requireContext(), OperationActivity.class)
                    .putExtra(OperationActivity.EXTRA_OPERATION, OperationActivity.BACKUP)
                    .putExtra(OperationActivity.EXTRA_PARTITIONS, partitions.toArray(new String[0]))
                    .putExtra(OperationActivity.EXTRA_SLOT, slot);
            startActivity(intent);
            return true;
        });
        actions.addPreference(runPreference);
        render();
    }

    @Override
    void refresh() {
        var activity = (BackupActivity) getActivity();
        if (activity == null || activity.service == null || busy || listCategory == null) return;
        int request = ++generation;
        loaded = false;
        status = "正在读取 vbmeta";
        render();
        var names = partitions.toArray(new String[0]);
        activity.runWithService(svc -> {
            String next = svc.getBackupSlot();
            var related = svc.backupDependencies(names);
            if (!next.equals(svc.getBackupSlot())) throw new IllegalStateException("下次启动槽位已改变");
            var result = new String[related.length + 1];
            result[0] = next;
            System.arraycopy(related, 0, result, 1, related.length);
            return result;
        }, (result, error) -> {
            if (!isAdded() || activity.isFinishing() || request != generation) return;
            if (error != null) {
                status = "读取失败：" + error.getMessage();
            } else {
                slot = result[0];
                dependencies.clear();
                dependencies.addAll(Arrays.asList(result).subList(1, result.length));
                loaded = true;
                status = "";
            }
            render();
        });
    }

    @Override
    void render() {
        if (listCategory == null || !isAdded()) return;
        listCategory.removeAll();
        int order = 0;
        for (var name : partitions) {
            var item = new SelectableRow(requireContext(), name, false);
            item.setTitle(name);
            item.setLayoutResource(R.layout.list_item_row);
            item.setOrder(order++);
            listCategory.addPreference(item);
        }
        var add = row("添加分区", null);
        add.setLayoutResource(R.layout.preference_add_row);
        add.setEnabled(!selection.isEditing() && !busy);
        add.setOrder(Integer.MAX_VALUE);
        add.setOnPreferenceClickListener(p -> {
            PartitionNameDialog.show(requireContext(), partitions, name -> {
                partitions.add(name);
                savePartitions();
                render();
                refresh();
            });
            return true;
        });
        listCategory.addPreference(add);
        dependencyCategory.removeAll();
        if (!loaded || dependencies.isEmpty()) {
            var item = row(loaded ? "无" : status, null);
            item.setSelectable(false);
            dependencyCategory.addPreference(item);
        } else {
            for (var name : dependencies) {
                var item = row(name, null);
                item.setSelectable(false);
                dependencyCategory.addPreference(item);
            }
        }
        runPreference.setSummary(loaded ? "备份下次启动槽位 " + slot : status);
        runPreference.setEnabled(loaded && !busy && !selection.isEditing() && !partitions.isEmpty());
        requireActivity().invalidateOptionsMenu();
    }

    @Override
    void confirmDelete() {
        if (!canEditAction() || selection.isEmpty()) return;
        var selected = selection.snapshot();
        if (selected.size() >= partitions.size()) {
            ((BackupActivity) requireActivity()).toast("请至少保留一个分区");
            return;
        }
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle("删除分区")
                .setMessage("从备份列表中移除所选分区？")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (d, w) -> {
                    partitions.removeAll(selected);
                    savePartitions();
                    selection.exit();
                    render();
                    refresh();
                }).show();
    }

    private void savePartitions() {
        requireContext().getSharedPreferences(BackupSettings.PREFS, Context.MODE_PRIVATE).edit()
                .putStringSet(BackupSettings.PARTITIONS, new LinkedHashSet<>(partitions)).apply();
    }
}
