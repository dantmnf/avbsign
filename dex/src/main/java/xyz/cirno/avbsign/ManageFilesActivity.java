package xyz.cirno.avbsign;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.listitem.ListItemCardView;
import com.google.android.material.listitem.ListItemLayout;
import com.google.android.material.listitem.ListItemViewHolder;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Import and delete managed files (signing keys or bootloader images) stored
 * under /data/adb. All filesystem access goes through the Shizuku service.
 */
public class ManageFilesActivity extends BaseAvbActivity {

    public static final String EXTRA_DIR = "dir";
    public static final String EXTRA_TITLE = "title";

    private static final int REQUEST_CODE_IMPORT = 10;

    private String dir;
    private TextView statusView;
    private final FileAdapter fileAdapter = new FileAdapter();
    private final EditSelection selection = new EditSelection();
    private boolean filesLoaded;
    private boolean fileOperationInProgress;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dir = getIntent().getStringExtra(EXTRA_DIR);
        if (savedInstanceState != null) {
            selection.restore(savedInstanceState.getBoolean("editing"),
                    savedInstanceState.getStringArrayList("selected_items"));
        }
        var title = getIntent().getStringExtra(EXTRA_TITLE);
        setContentView(R.layout.activity_manage_files);
        applySystemBarInsets(findViewById(R.id.files_root));
        MaterialToolbar toolbar = findViewById(R.id.files_toolbar);
        setSupportActionBar(toolbar);
        var actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
            actionBar.setTitle(title);
        }

        TextView pathView = findViewById(R.id.files_path);
        pathView.setText("存放位置：" + dir);
        statusView = findViewById(R.id.files_status);
        RecyclerView fileList = findViewById(R.id.files_list);
        fileList.setLayoutManager(new LinearLayoutManager(this));
        fileList.setItemAnimator(null);
        fileList.setAdapter(fileAdapter);
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (selection.isEditing()) {
                    if (fileOperationInProgress) {
                        toast("请等待文件操作完成");
                    } else {
                        selection.exit();
                        fileAdapter.notifyItemsChanged();
                        invalidateOptionsMenu();
                    }
                } else {
                    finish();
                }
            }
        });
        onShizukuAvailable();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.bootloader_settings, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        var action = menu.findItem(R.id.action_edit);
        if (action != null) {
            action.setTitle(selection.isEditing() ? "删除" : "编辑");
            action.setEnabled(!fileOperationInProgress
                    && (!selection.isEditing() || (filesLoaded && !selection.isEmpty())));
        }
        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            getOnBackPressedDispatcher().onBackPressed();
            return true;
        }
        if (item.getItemId() == R.id.action_edit) {
            if (selection.isEditing()) {
                confirmDeleteSelection();
            } else if (!fileOperationInProgress) {
                selection.enter();
                fileAdapter.notifyItemsChanged();
                invalidateOptionsMenu();
            }
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshList();
    }

    @Override
    protected void onShizukuStateChanged() {
        if (statusView != null && service == null) {
            filesLoaded = false;
            fileAdapter.names.clear();
            fileAdapter.notifyDataSetChanged();
            invalidateOptionsMenu();
            showStatus(!isShizukuGranted()
                    ? (rikka.shizuku.Shizuku.pingBinder() ? "Shizuku 正在运行，但尚未授权" : "Shizuku 未运行")
                    : "正在连接服务");
        }
    }

    @Override
    protected void onServiceReady() {
        refreshList();
    }

    private void startImport() {
        if (selection.isEditing() || fileOperationInProgress) {
            return;
        }
        if (!isShizukuGranted()) {
            requestShizukuPermission();
            return;
        }
        if (service == null) {
            toast("服务尚未连接，请稍后再试");
            return;
        }
        startActivityForResult(ManagedFileImporter.createIntent(), REQUEST_CODE_IMPORT);
    }

    private void refreshList() {
        if (service == null || statusView == null || fileOperationInProgress) {
            return;
        }
        filesLoaded = false;
        fileAdapter.notifyDataSetChanged();
        invalidateOptionsMenu();
        showStatus("正在读取文件");
        boolean started = runWithService(svc -> svc.listFiles(dir), (names, error) -> {
            if (isFinishing() || isDestroyed()) {
                return;
            }
            if (error != null) {
                showStatus("读取失败：" + error.getMessage());
                return;
            }
            fileAdapter.names.clear();
            fileAdapter.names.addAll(Arrays.asList(names));
            selection.retainAll(fileAdapter.names);
            filesLoaded = true;
            showStatus("");
            fileAdapter.notifyDataSetChanged();
            invalidateOptionsMenu();
        });
        if (!started) {
            showStatus("服务不可用，请稍后再试");
        }
    }

    private void showStatus(String message) {
        statusView.setText(message);
        statusView.setVisibility(message.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private void confirmDeleteSelection() {
        if (!selection.isEditing() || selection.isEmpty() || !filesLoaded || fileOperationInProgress) {
            return;
        }
        var names = selection.snapshot();
        new MaterialAlertDialogBuilder(this)
                .setTitle("删除文件")
                .setMessage("删除所选文件？文件将立即删除。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (dialog, which) -> deleteManagedFiles(names))
                .show();
    }

    private void setFileOperationInProgress(boolean inProgress) {
        fileOperationInProgress = inProgress;
        fileAdapter.notifyDataSetChanged();
        invalidateOptionsMenu();
    }

    private void deleteManagedFiles(ArrayList<String> names) {
        setFileOperationInProgress(true);
        showStatus("正在删除文件");
        boolean started = runWithService(svc -> ManagedFileDeleter.delete(names,
                name -> svc.deleteFile(dir, name)), (result, error) -> {
            if (isFinishing() || isDestroyed()) {
                return;
            }
            setFileOperationInProgress(false);
            if (error == null) {
                selection.removeAll(result.deleted);
                if (result.errors.isEmpty()) {
                    selection.exit();
                }
            }
            ManagedFileDeleter.showErrors(this, result, error);
            invalidateOptionsMenu();
            refreshList();
        });
        if (!started) {
            setFileOperationInProgress(false);
            showStatus("服务不可用，请稍后再试");
        }
    }

    private final class FileAdapter extends RecyclerView.Adapter<ListItemViewHolder> {
        private static final int FILE = 0;
        private static final int EMPTY = 1;
        private static final int IMPORT = 2;
        final ArrayList<String> names = new ArrayList<>();

        @Override
        public int getItemViewType(int position) {
            if (position < names.size()) {
                return FILE;
            }
            return filesLoaded && names.isEmpty() && position == 0 ? EMPTY : IMPORT;
        }

        @NonNull
        @Override
        public ListItemViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            int layout = viewType == FILE ? R.layout.list_item_row
                    : viewType == EMPTY ? R.layout.managed_files_empty : R.layout.preference_add_row;
            var view = LayoutInflater.from(parent.getContext()).inflate(layout, parent, false);
            view.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            return new ListItemViewHolder(view);
        }

        void notifyItemsChanged() {
            notifyItemRangeChanged(0, getItemCount(), Boolean.TRUE);
        }

        @Override
        public void onBindViewHolder(@NonNull ListItemViewHolder holder, int position) {
            holder.bind();
            ListItemCardView card = holder.itemView.findViewById(R.id.list_item_card);
            if (holder.getItemViewType() == FILE) {
                var name = names.get(position);
                TextView label = holder.itemView.findViewById(android.R.id.title);
                label.setText(name);
                EditableListItem.bind((ListItemLayout) holder.itemView,
                        selection.isEditing() && filesLoaded && !fileOperationInProgress,
                        selection.contains(name), () -> {
                    selection.toggle(name);
                    int currentPosition = holder.getBindingAdapterPosition();
                    if (currentPosition != RecyclerView.NO_POSITION) {
                        notifyItemChanged(currentPosition, Boolean.TRUE);
                    }
                    invalidateOptionsMenu();
                });
            } else if (holder.getItemViewType() == IMPORT) {
                TextView title = holder.itemView.findViewById(android.R.id.title);
                title.setText("导入文件（可多选）");
                boolean canImport = !selection.isEditing() && !fileOperationInProgress;
                holder.itemView.setEnabled(canImport);
                card.setEnabled(canImport);
                card.setOnClickListener(canImport ? v -> startImport() : null);
                card.setClickable(canImport);
                card.setFocusable(canImport);
            }
        }

        @Override
        public int getItemCount() {
            return names.size() + (filesLoaded && names.isEmpty() ? 1 : 0) + 1;
        }
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        outState.putBoolean("editing", selection.isEditing());
        outState.putStringArrayList("selected_items", selection.snapshot());
        super.onSaveInstanceState(outState);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_CODE_IMPORT || resultCode != RESULT_OK || data == null) {
            return;
        }
        var uris = ManagedFileImporter.uris(data);
        if (uris.isEmpty()) {
            toast("未选择文件");
            return;
        }
        var context = getApplicationContext();
        setFileOperationInProgress(true);
        showStatus("正在导入文件");
        boolean started = runWithService(svc -> ManagedFileImporter.importFiles(context, svc, uris, dir),
                (result, error) -> {
            if (isFinishing() || isDestroyed()) {
                return;
            }
            setFileOperationInProgress(false);
            ManagedFileImporter.showResult(this, result, error);
            refreshList();
        });
        if (!started) {
            setFileOperationInProgress(false);
            showStatus("服务不可用，请重新选择文件");
        }
    }
}
