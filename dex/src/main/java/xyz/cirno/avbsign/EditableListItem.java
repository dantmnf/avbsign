package xyz.cirno.avbsign;

import android.view.View;

import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.listitem.ListItemCardView;
import com.google.android.material.listitem.ListItemLayout;

final class EditableListItem {
    static void bind(ListItemLayout layout, boolean editing, boolean selected, Runnable toggle) {
        ListItemCardView card = layout.findViewById(R.id.list_item_card);
        MaterialCheckBox checkbox = layout.findViewById(R.id.list_item_checkbox);
        if (!editing && card.isChecked()) {
            card.setChecked(false);
        }
        card.setCheckable(editing);
        if (editing) {
            card.setChecked(selected);
        }
        checkbox.setVisibility(editing ? View.VISIBLE : View.GONE);
        checkbox.setChecked(editing && selected);
        card.setFocusable(editing);
        card.setOnClickListener(editing ? v -> toggle.run() : null);
        card.setClickable(editing);
    }

    private EditableListItem() {
    }
}
