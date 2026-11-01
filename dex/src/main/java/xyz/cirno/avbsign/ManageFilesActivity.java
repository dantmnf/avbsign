package xyz.cirno.avbsign;

import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Import and delete managed files (signing keys or bootloader images) stored
 * under /data/adb. All filesystem access goes through the Shizuku service.
 */
public class ManageFilesActivity extends BaseAvbActivity {

    public static final String EXTRA_DIR = "dir";
    public static final String EXTRA_TITLE = "title";
    /** When set, imported files are always stored under this fixed name. */
    public static final String EXTRA_FIXED_NAME = "fixed_name";

    private static final int REQUEST_CODE_IMPORT = 10;

    private String dir;
    private String fixedName;
    private LinearLayout fileList;
    private TextView statusView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dir = getIntent().getStringExtra(EXTRA_DIR);
        fixedName = getIntent().getStringExtra(EXTRA_FIXED_NAME);
        var title = getIntent().getStringExtra(EXTRA_TITLE);
        setTitle(title);
        var actionBar = getActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }

        int pad = dp(16);
        var root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        var pathView = new TextView(this);
        pathView.setText("存放位置：" + dir);
        pathView.setTextSize(12);
        root.addView(pathView, lp());

        statusView = new TextView(this);
        root.addView(statusView, lp());

        var importButton = new Button(this);
        importButton.setText(fixedName != null ? "导入并保存为 " + fixedName : "导入文件（可多选）");
        importButton.setOnClickListener(v -> startImport());
        root.addView(importButton, lp());

        var scroll = new ScrollView(this);
        fileList = new LinearLayout(this);
        fileList.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(fileList);
        root.addView(scroll, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));

        setContentView(root);
        applySystemBarInsets(root);
        onShizukuAvailable();
    }

    @Override
    public boolean onOptionsItemSelected(android.view.MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
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
        if (!isShizukuGranted()) {
            statusView.setText(rikka.shizuku.Shizuku.pingBinder() ? "Shizuku 正在运行，但尚未授权" : "Shizuku 未运行");
        } else {
            statusView.setText("");
        }
    }

    @Override
    protected void onServiceReady() {
        refreshList();
    }

    private void startImport() {
        if (!isShizukuGranted()) {
            requestShizukuPermission();
            return;
        }
        var intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        startActivityForResult(intent, REQUEST_CODE_IMPORT);
    }

    private void refreshList() {
        var svc = service;
        if (svc == null) {
            return;
        }
        runWithService(svc2 -> svc2.listFiles(dir), (names, error) -> {
            if (error != null) {
                statusView.setText("读取失败：" + error.getMessage());
                return;
            }
            fileList.removeAllViews();
            if (names.length == 0) {
                var empty = new TextView(this);
                empty.setText("（暂无文件）");
                fileList.addView(empty, lp());
                return;
            }
            for (var name : names) {
                if (fixedName != null && !fixedName.equals(name)) {
                    continue;
                }
                fileList.addView(fileRow(name), lp());
            }
        });
    }

    private View fileRow(String name) {
        var row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

        var label = new TextView(this);
        label.setText(name);
        label.setTextSize(14);
        row.addView(label, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));

        var delete = new Button(this);
        delete.setText("删除");
        delete.setOnClickListener(v -> runWithService(svc -> {
            svc.deleteFile(dir, name);
            return null;
        }, (r, error) -> {
            if (error != null) {
                toast("删除失败：" + error.getMessage());
            }
            refreshList();
        }));
        row.addView(delete);
        return row;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_CODE_IMPORT || resultCode != RESULT_OK || data == null) {
            return;
        }
        var uris = new ArrayList<Uri>();
        if (data.getClipData() != null) {
            for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                uris.add(data.getClipData().getItemAt(i).getUri());
            }
        } else if (data.getData() != null) {
            uris.add(data.getData());
        }
        if (uris.isEmpty()) {
            return;
        }
        executor.execute(() -> importUris(uris));
    }

    private void importUris(List<Uri> uris) {
        var staging = new File(getCacheDir(), "import");
        clearDir(staging);
        //noinspection ResultOfMethodCallIgnored
        staging.mkdirs();
        var imported = new ArrayList<String>();
        for (var uri : uris) {
            var displayName = displayName(uri);
            if (displayName == null) {
                continue;
            }
            final var name = fixedName != null ? fixedName : displayName;
            var staged = new File(staging, name);
            try (InputStream in = getContentResolver().openInputStream(uri);
                 FileOutputStream out = new FileOutputStream(staged)) {
                if (in == null) {
                    continue;
                }
                var buf = new byte[65536];
                int read;
                while ((read = in.read(buf)) != -1) {
                    out.write(buf, 0, read);
                }
            } catch (Exception e) {
                mainHandler.post(() -> toast("读取 " + name + " 失败：" + e));
                continue;
            }
            try {
                service.importFile(staged.getAbsolutePath(), dir, name);
                imported.add(name);
            } catch (Exception e) {
                var msg = e.getMessage();
                mainHandler.post(() -> toast("导入 " + name + " 失败：" + msg));
            }
            //noinspection ResultOfMethodCallIgnored
            staged.delete();
        }
        mainHandler.post(() -> {
            toast("已导入 " + imported.size() + " 个文件");
            refreshList();
        });
    }

    private String displayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (index >= 0) {
                    return new File(cursor.getString(index)).getName();
                }
            }
        }
        return null;
    }

    private void clearDir(File dir) {
        var files = dir.listFiles();
        if (files != null) {
            for (var f : files) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
        }
    }
}
