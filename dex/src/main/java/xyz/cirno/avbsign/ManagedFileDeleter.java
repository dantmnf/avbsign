package xyz.cirno.avbsign;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.ArrayList;
import java.util.List;

final class ManagedFileDeleter {
    interface DeleteAction {
        void delete(String name) throws Exception;
    }

    static Result delete(List<String> names, DeleteAction action) {
        var result = new Result();
        for (var name : names) {
            try {
                action.delete(name);
                result.deleted.add(name);
            } catch (Exception e) {
                result.errors.add(name + "：" + (e.getMessage() == null ? e.toString() : e.getMessage()));
            }
        }
        return result;
    }

    static void showErrors(BaseAvbActivity activity, Result result, Exception error) {
        if (error != null) {
            activity.toast("删除失败：" + error.getMessage());
        } else if (!result.errors.isEmpty()) {
            new MaterialAlertDialogBuilder(activity)
                    .setTitle(result.deleted.isEmpty() ? "删除失败" : "部分文件删除失败")
                    .setMessage(String.join("\n", result.errors))
                    .setPositiveButton("确定", null)
                    .show();
        }
    }

    static final class Result {
        final ArrayList<String> deleted = new ArrayList<>();
        final ArrayList<String> errors = new ArrayList<>();
    }

    private ManagedFileDeleter() {
    }
}
