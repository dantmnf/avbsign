package xyz.cirno.avbsign;

import android.content.Context;
import android.content.Intent;
import android.app.Activity;
import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceViewHolder;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.listitem.ListItemCardView;
import com.google.android.material.listitem.ListItemLayout;

import java.util.ArrayList;
import java.util.Arrays;

public class BootloaderSettingsFragment extends PreferenceFragmentCompat {
    private static final int REQUEST_CODE_IMPORT_IMAGES = 11;
    private final ArrayList<String> partitions = new ArrayList<>();
    private final ArrayList<String> keyNames = new ArrayList<>();
    private final ArrayList<String> imageNames = new ArrayList<>();
    private final EditSelection selection = new EditSelection();
    private Preference sourcePreference;
    private Preference rootKeyPreference;
    private PreferenceCategory partitionCategory;
    private PreferenceCategory imagesCategory;
    private String source;
    private String selectedKey;
    private String matchingKey;
    private String matchingError;
    private String serviceStatus = "正在连接服务";
    private boolean keyChosen;
    private boolean keysLoaded;
    private boolean fileOperationInProgress;
    private int refreshGeneration;

    @Override
    public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey) {
        var context = requireContext();
        var preferences = BootloaderSettings.preferences(context);
        if (savedInstanceState != null) {
            partitions.addAll(savedInstanceState.getStringArrayList("partitions"));
            source = savedInstanceState.getString("source");
            selectedKey = savedInstanceState.getString("root_key");
            keyChosen = savedInstanceState.getBoolean("key_chosen");
            selection.restore(savedInstanceState.getBoolean("editing"),
                    savedInstanceState.getStringArrayList("selected_items"));
        } else {
            partitions.addAll(BootloaderSettings.partitions(preferences));
            source = preferences.getString(BootloaderSettings.SOURCE, BootloaderSettings.CURRENT);
            selectedKey = preferences.getString(BootloaderSettings.ROOT_KEY, null);
            keyChosen = selectedKey != null;
        }

        var screen = getPreferenceManager().createPreferenceScreen(context);
        setPreferenceScreen(screen);

        var replacementCategory = new PreferenceCategory(context);
        replacementCategory.setTitle("替换设置");
        replacementCategory.setLayoutResource(R.layout.preference_category_material3);
        replacementCategory.setIconSpaceReserved(false);
        screen.addPreference(replacementCategory);

        sourcePreference = newPreference(context, "替换来源");
        sourcePreference.setOnPreferenceClickListener(preference -> {
            showSourceDialog();
            return true;
        });
        replacementCategory.addPreference(sourcePreference);

        partitionCategory = new PreferenceCategory(context);
        partitionCategory.setTitle("替换分区");
        partitionCategory.setLayoutResource(R.layout.preference_category_material3);
        partitionCategory.setIconSpaceReserved(false);
        partitionCategory.setOrderingAsAdded(false);
        screen.addPreference(partitionCategory);
        renderPartitions();

        imagesCategory = new PreferenceCategory(context);
        imagesCategory.setTitle("外部镜像");
        imagesCategory.setLayoutResource(R.layout.preference_category_material3);
        imagesCategory.setIconSpaceReserved(false);
        imagesCategory.setOrderingAsAdded(false);
        screen.addPreference(imagesCategory);
        renderImages();

        var signingCategory = new PreferenceCategory(context);
        signingCategory.setTitle("签名设置");
        signingCategory.setLayoutResource(R.layout.preference_category_material3);
        signingCategory.setIconSpaceReserved(false);
        screen.addPreference(signingCategory);

        rootKeyPreference = newPreference(context, "根密钥");
        rootKeyPreference.setOnPreferenceClickListener(preference -> {
            showRootKeyDialog();
            return true;
        });
        signingCategory.addPreference(rootKeyPreference);
        persistSettings();
        updatePreferences();
    }

    private Preference newPreference(Context context, String title) {
        var preference = new ListPreference(context);
        preference.setTitle(title);
        preference.setLayoutResource(R.layout.preference_material3);
        preference.setIconSpaceReserved(false);
        preference.setPersistent(false);
        return preference;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        setDivider(null);
        var list = getListView();
        int horizontal = getResources().getDimensionPixelSize(R.dimen.expressive_list_horizontal_padding);
        list.setPaddingRelative(horizontal, list.getPaddingTop(), horizontal, list.getPaddingBottom());
        list.setClipToPadding(true);
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshFiles();
    }

    void onServiceStateChanged() {
        var activity = (BootloaderSettingsActivity) getActivity();
        if (activity != null && activity.service == null) {
            refreshGeneration++;
            keysLoaded = false;
            serviceStatus = activity.isShizukuGranted() ? "正在连接服务" : "请先在主界面授权 Shizuku";
            renderImages();
            updatePreferences();
            updateMenu();
        }
    }

    void refreshFiles() {
        var activity = (BootloaderSettingsActivity) getActivity();
        if (activity == null || activity.service == null || rootKeyPreference == null) {
            return;
        }
        var generation = ++refreshGeneration;
        keysLoaded = false;
        serviceStatus = "正在读取密钥和镜像";
        renderImages();
        updatePreferences();
        updateMenu();
        boolean started = activity.runWithService(svc -> {
            var keys = svc.listFiles(AvbPaths.KEYS_DIR);
            var images = svc.listFiles(AvbPaths.BOOTLOADER_DIR);
            String match = null;
            String error = null;
            try {
                match = svc.findCurrentSlotRootKey();
            } catch (Exception e) {
                error = e.getMessage() == null ? e.toString() : e.getMessage();
            }
            return new FileState(keys, images, match, error);
        }, (state, error) -> {
            if (!isAdded() || activity.isFinishing() || activity.isDestroyed()
                    || generation != refreshGeneration) {
                return;
            }
            if (error != null) {
                keysLoaded = false;
                serviceStatus = "读取文件失败：" + error.getMessage();
                renderImages();
                updatePreferences();
                updateMenu();
                return;
            }
            keyNames.clear();
            keyNames.addAll(Arrays.asList(state.keys));
            matchingKey = state.match;
            matchingError = state.error;
            imageNames.clear();
            imageNames.addAll(Arrays.asList(state.images));
            if (BootloaderSettings.EXTERNAL.equals(source)) {
                selection.retainAll(imageNames);
            }
            keysLoaded = true;
            renderImages();
            updateDefaultKey();
            persistSettings();
            updatePreferences();
            updateMenu();
        });
        if (!started) {
            serviceStatus = "服务不可用，请稍后再试";
            renderImages();
            updatePreferences();
            updateMenu();
        }
    }

    private void updateDefaultKey() {
        if (!keyChosen && keysLoaded) {
            selectedKey = BootloaderSettings.defaultRootKey(source, matchingKey, matchingError);
        }
    }

    private void updatePreferences() {
        if (sourcePreference == null) {
            return;
        }
        var current = BootloaderSettings.CURRENT.equals(source);
        sourcePreference.setSummary(current ? "当前启动槽位" : "外部文件");
        sourcePreference.setEnabled(!selection.isEditing() && !fileOperationInProgress);
        rootKeyPreference.setEnabled(!selection.isEditing() && !fileOperationInProgress);
        partitionCategory.setVisible(current);
        imagesCategory.setVisible(!current);

        if (!keysLoaded) {
            rootKeyPreference.setSummary(serviceStatus);
            return;
        }
        var summary = selectedKey == null ? "未确定"
                : selectedKey.isEmpty() ? "未选择（需要替换时会停止修复）"
                : keyNames.contains(selectedKey) ? selectedKey : selectedKey + "（文件不存在）";
        if (current && matchingError != null) {
            summary += "\n无法匹配当前槽位密钥：" + matchingError;
        } else if (current && matchingKey == null) {
            summary += "\n未找到与当前槽位 vbmeta 匹配的密钥";
        }
        summary += "\n所选密钥必须被替换后的 bootloader 信任";
        rootKeyPreference.setSummary(summary);
    }

    private void showSourceDialog() {
        var choices = getResources().getStringArray(R.array.replace_bootloader_choices);
        var selected = BootloaderSettings.CURRENT.equals(source) ? 0 : 1;
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle("替换来源")
                .setSingleChoiceItems(choices, selected, (dialog, which) -> {
                    var newSource = which == 0 ? BootloaderSettings.CURRENT : BootloaderSettings.EXTERNAL;
                    if (!newSource.equals(source)) {
                        source = newSource;
                        keyChosen = false;
                        selectedKey = null;
                        updateDefaultKey();
                        persistSettings();
                        updatePreferences();
                    }
                    dialog.dismiss();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void showRootKeyDialog() {
        if (!keysLoaded) {
            ((BootloaderSettingsActivity) requireActivity()).toast(serviceStatus);
            return;
        }
        var choices = new ArrayList<>(keyNames);
        var labels = new ArrayList<String>();
        labels.add("未选择（需要替换时会停止修复）");
        labels.addAll(choices);
        int selected = selectedKey == null || selectedKey.isEmpty() ? 0 : choices.indexOf(selectedKey) + 1;
        if (selectedKey != null && !selectedKey.isEmpty() && selected == 0) {
            labels.add(selectedKey + "（文件不存在）");
            selected = labels.size() - 1;
        }
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle("根密钥")
                .setSingleChoiceItems(labels.toArray(new String[0]), selected, (dialog, which) -> {
                    if (which <= choices.size()) {
                        selectedKey = which == 0 ? "" : choices.get(which - 1);
                        keyChosen = true;
                        persistSettings();
                        updatePreferences();
                    }
                    dialog.dismiss();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void showAddPartition() {
        PartitionNameDialog.show(requireContext(), partitions, name -> {
            partitions.add(name);
            persistSettings();
            renderPartitions();
        });
    }

    private void renderPartitions() {
        partitionCategory.removeAll();
        int order = 0;
        for (var name : partitions) {
            var preference = new PartitionPreference(requireContext(), name);
            preference.setOrder(order++);
            partitionCategory.addPreference(preference);
        }
        var add = newPreference(requireContext(), "添加分区");
        add.setOrder(Integer.MAX_VALUE);
        add.setLayoutResource(R.layout.preference_add_row);
        add.setEnabled(!selection.isEditing() && !fileOperationInProgress);
        add.setOnPreferenceClickListener(preference -> {
            showAddPartition();
            return true;
        });
        partitionCategory.addPreference(add);
    }

    private void renderImages() {
        if (imagesCategory == null) {
            return;
        }
        imagesCategory.removeAll();
        int order = 0;
        var info = newPreference(requireContext(), "仅刷写 .img 文件，导入和删除立即生效");
        info.setOrder(order++);
        info.setLayoutResource(R.layout.preference_info_row);
        info.setSelectable(false);
        imagesCategory.addPreference(info);
        if (!keysLoaded || fileOperationInProgress || imageNames.isEmpty()) {
            var message = newPreference(requireContext(), fileOperationInProgress ? "正在处理文件"
                    : !keysLoaded ? serviceStatus : "暂无文件");
            message.setOrder(order++);
            message.setLayoutResource(R.layout.list_item_row);
            message.setSelectable(false);
            imagesCategory.addPreference(message);
        }
        if (keysLoaded && !fileOperationInProgress) {
            for (var name : imageNames) {
                var preference = new ImagePreference(requireContext(), name);
                preference.setOrder(order++);
                imagesCategory.addPreference(preference);
            }
        }
        var add = newPreference(requireContext(), "导入文件（可多选）");
        add.setOrder(Integer.MAX_VALUE);
        add.setLayoutResource(R.layout.preference_add_row);
        add.setEnabled(!selection.isEditing() && !fileOperationInProgress);
        add.setOnPreferenceClickListener(preference -> {
            startImportImages();
            return true;
        });
        imagesCategory.addPreference(add);
    }

    private void startImportImages() {
        var activity = (BootloaderSettingsActivity) requireActivity();
        if (!activity.isShizukuGranted()) {
            activity.requestShizukuPermission();
            return;
        }
        if (activity.service == null) {
            activity.toast("服务尚未连接，请稍后再试");
            return;
        }
        startActivityForResult(ManagedFileImporter.createIntent(), REQUEST_CODE_IMPORT_IMAGES);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_CODE_IMPORT_IMAGES || resultCode != Activity.RESULT_OK || data == null) {
            return;
        }
        var uris = ManagedFileImporter.uris(data);
        var activity = (BootloaderSettingsActivity) requireActivity();
        if (uris.isEmpty()) {
            activity.toast("未选择文件");
            return;
        }
        if (!activity.isShizukuGranted() || activity.service == null) {
            activity.toast("Shizuku 服务不可用，请重新选择文件");
            return;
        }
        fileOperationInProgress = true;
        renderImages();
        updatePreferences();
        updateMenu();
        var context = activity.getApplicationContext();
        boolean started = activity.runWithService(svc -> ManagedFileImporter.importFiles(context, svc, uris,
                AvbPaths.BOOTLOADER_DIR, null), (result, error) -> {
            if (!isAdded() || activity.isFinishing() || activity.isDestroyed()) {
                return;
            }
            fileOperationInProgress = false;
            ManagedFileImporter.showResult(activity, result, error);
            refreshFiles();
            updateMenu();
        });
        if (!started) {
            fileOperationInProgress = false;
            renderImages();
            updatePreferences();
            updateMenu();
        }
    }

    private void deleteImages(ArrayList<String> names) {
        var activity = (BootloaderSettingsActivity) requireActivity();
        if (!activity.isShizukuGranted() || activity.service == null) {
            activity.toast("Shizuku 服务不可用，请稍后再试");
            return;
        }
        fileOperationInProgress = true;
        renderImages();
        updatePreferences();
        updateMenu();
        boolean started = activity.runWithService(svc -> {
            return ManagedFileDeleter.delete(names,
                    name -> svc.deleteFile(AvbPaths.BOOTLOADER_DIR, name));
        }, (result, error) -> {
            if (!isAdded() || activity.isFinishing() || activity.isDestroyed()) {
                return;
            }
            fileOperationInProgress = false;
            if (error == null) {
                selection.removeAll(result.deleted);
                if (result.errors.isEmpty()) {
                    selection.exit();
                }
            }
            ManagedFileDeleter.showErrors(activity, result, error);
            renderPartitions();
            refreshFiles();
            updatePreferences();
            updateMenu();
        });
        if (!started) {
            fileOperationInProgress = false;
            renderImages();
            updatePreferences();
            updateMenu();
        }
    }

    private void persistSettings() {
        BootloaderSettings.persist(BootloaderSettings.preferences(requireContext()),
                source, partitions, selectedKey);
    }

    boolean isEditing() {
        return selection.isEditing();
    }

    boolean canDeleteSelection() {
        return selection.isEditing() && !selection.isEmpty() && !fileOperationInProgress
                && (BootloaderSettings.CURRENT.equals(source) || keysLoaded);
    }

    boolean isFileOperationInProgress() {
        return fileOperationInProgress;
    }

    void enterEditMode() {
        if (fileOperationInProgress) {
            return;
        }
        selection.enter();
        renderPartitions();
        renderImages();
        updatePreferences();
        updateMenu();
    }

    void exitEditMode() {
        selection.exit();
        renderPartitions();
        renderImages();
        updatePreferences();
        updateMenu();
    }

    void confirmDeleteSelection() {
        if (!canDeleteSelection()) {
            return;
        }
        var names = selection.snapshot();
        boolean current = BootloaderSettings.CURRENT.equals(source);
        if (current && names.size() >= partitions.size()) {
            ((BootloaderSettingsActivity) requireActivity()).toast("请至少保留一个分区");
            return;
        }
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle(current ? "删除分区" : "删除文件")
                .setMessage(current ? "从替换列表中移除所选分区？"
                        : "删除所选文件？文件将立即删除。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (dialog, which) -> {
                    if (current) {
                        partitions.removeAll(names);
                        persistSettings();
                        exitEditMode();
                    } else {
                        deleteImages(names);
                    }
                })
                .show();
    }

    private void updateMenu() {
        if (getActivity() != null) {
            requireActivity().invalidateOptionsMenu();
        }
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        outState.putStringArrayList("partitions", new ArrayList<>(partitions));
        outState.putString("source", source);
        outState.putString("root_key", selectedKey);
        outState.putBoolean("key_chosen", keyChosen);
        outState.putBoolean("editing", selection.isEditing());
        outState.putStringArrayList("selected_items", selection.snapshot());
        super.onSaveInstanceState(outState);
    }

    private static class ListPreference extends Preference {
        ListPreference(Context context) {
            super(context);
        }

        @Override
        public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
            super.onBindViewHolder(holder);
            var layout = (ListItemLayout) holder.itemView;
            PreferenceListPosition.update(layout, this);
            ListItemCardView card = layout.findViewById(R.id.list_item_card);
            layout.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            layout.setFocusable(false);
            boolean actionable = isSelectable() && isEnabled();
            card.setFocusable(actionable);
            card.setOnClickListener(actionable ? v -> layout.performClick() : null);
            card.setClickable(actionable);
        }
    }

    private abstract class SelectablePreference extends ListPreference {
        final String name;

        SelectablePreference(Context context, String name) {
            super(context);
            this.name = name;
            setTitle(name);
            setLayoutResource(R.layout.list_item_row);
            setIconSpaceReserved(false);
            setPersistent(false);
        }

        @Override
        public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
            super.onBindViewHolder(holder);
            EditableListItem.bind((ListItemLayout) holder.itemView, selection.isEditing(),
                    selection.contains(name), () -> {
                        if (!selection.isEditing() || fileOperationInProgress
                                || (this instanceof ImagePreference && !keysLoaded)) {
                            return;
                        }
                        selection.toggle(name);
                        notifyChanged();
                        updateMenu();
                    });
        }
    }

    private final class PartitionPreference extends SelectablePreference {
        PartitionPreference(Context context, String name) {
            super(context, name);
        }
    }

    private final class ImagePreference extends SelectablePreference {
        ImagePreference(Context context, String name) {
            super(context, name);
        }
    }

    private static final class FileState {
        final String[] keys;
        final String[] images;
        final String match;
        final String error;

        FileState(String[] keys, String[] images, String match, String error) {
            this.keys = keys;
            this.images = images;
            this.match = match;
            this.error = error;
        }
    }
}
