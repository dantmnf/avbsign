package xyz.cirno.avbsign;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.util.Log;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

final class ManagedFileImporter {
    static Intent createIntent() {
        var intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        return intent;
    }

    static List<Uri> uris(Intent data) {
        var result = new ArrayList<Uri>();
        if (data.getClipData() != null) {
            for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                result.add(data.getClipData().getItemAt(i).getUri());
            }
        } else if (data.getData() != null) {
            result.add(data.getData());
        }
        return result;
    }

    static Result importFiles(Context context, IAvbService service, List<Uri> uris,
                              String dir, String fixedName) {
        var result = new Result();
        for (var uri : uris) {
            if (uri == null) {
                result.errors.add("无法获取文件地址");
                continue;
            }
            String name = fixedName;
            File staged = null;
            try {
                if (name == null) {
                    name = displayName(context, uri);
                }
                if (name == null || name.isEmpty() || name.equals(".") || name.equals("..")) {
                    throw new IOException("无法获取有效文件名");
                }
                staged = File.createTempFile("avbsign-import-", ".tmp", context.getCacheDir());
                try (var in = context.getContentResolver().openInputStream(uri);
                     var out = new FileOutputStream(staged)) {
                    if (in == null) {
                        throw new IOException("无法打开文件");
                    }
                    var buffer = new byte[65536];
                    int count;
                    while ((count = in.read(buffer)) != -1) {
                        out.write(buffer, 0, count);
                    }
                }
                service.importFile(staged.getAbsolutePath(), dir, name);
                result.imported++;
            } catch (Exception e) {
                result.errors.add((name == null ? uri.toString() : name) + "：" + e.getMessage());
            } finally {
                if (staged != null && !staged.delete()) {
                    Log.w("ManagedFileImporter", "Failed to remove staging file " + staged);
                }
            }
        }
        return result;
    }

    static void showResult(BaseAvbActivity activity, Result result, Exception error) {
        if (error != null) {
            activity.toast("导入失败：" + error.getMessage());
        } else if (result.errors.isEmpty()) {
            activity.toast("已导入 " + result.imported + " 个文件");
        } else {
            new MaterialAlertDialogBuilder(activity)
                    .setTitle("部分文件导入失败")
                    .setMessage("已导入 " + result.imported + " 个文件\n\n" + String.join("\n", result.errors))
                    .setPositiveButton("确定", null)
                    .show();
        }
    }

    private static String displayName(Context context, Uri uri) {
        try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (index >= 0) {
                    var name = cursor.getString(index);
                    return name == null ? null : new File(name).getName();
                }
            }
        }
        return null;
    }

    static final class Result {
        int imported;
        final ArrayList<String> errors = new ArrayList<>();
    }

    private ManagedFileImporter() {
    }
}
