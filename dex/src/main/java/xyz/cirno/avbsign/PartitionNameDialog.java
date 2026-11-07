package xyz.cirno.avbsign;

import android.content.Context;
import android.widget.EditText;
import android.widget.LinearLayout;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.Collection;
import java.util.function.Consumer;

final class PartitionNameDialog {
    static void show(Context context, Collection<String> names, Consumer<String> add) {
        var input = new EditText(context);
        input.setSingleLine(true);
        var container = new LinearLayout(context);
        int inset = (int) (24 * context.getResources().getDisplayMetrics().density);
        container.setPadding(inset, 0, inset, 0);
        container.addView(input, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        var dialog = new MaterialAlertDialogBuilder(context)
                .setTitle("添加分区")
                .setView(container)
                .setNegativeButton("取消", null)
                .setPositiveButton("添加", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(android.content.DialogInterface.BUTTON_POSITIVE)
                .setOnClickListener(v -> {
                    var name = input.getText().toString().trim();
                    if (!name.matches("[A-Za-z0-9][A-Za-z0-9_.-]*")) {
                        input.setError("分区名只能包含字母、数字、下划线、点和连字符");
                    } else if (names.contains(name)) {
                        input.setError("分区已存在");
                    } else {
                        add.accept(name);
                        dialog.dismiss();
                    }
                }));
        dialog.show();
    }

    private PartitionNameDialog() {
    }
}
