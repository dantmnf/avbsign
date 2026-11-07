package xyz.cirno.avbsign;

import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;

import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.listitem.ListItemCardView;
import com.google.android.material.listitem.ListItemLayout;

final class EditableListItem {
    static void bind(ListItemLayout layout, boolean editing, boolean selected, Runnable toggle) {
        ListItemCardView card = layout.findViewById(R.id.list_item_card);
        MaterialCheckBox checkbox = layout.findViewById(R.id.list_item_checkbox);
        card.setCheckable(true);
        card.setChecked(editing && selected);
        card.setCheckable(editing);
        layout.setActivated(editing && selected);
        checkbox.setVisibility(editing ? View.VISIBLE : View.GONE);
        checkbox.setChecked(editing && selected);
        card.setFocusable(editing);
        card.setOnClickListener(editing ? v -> toggle.run() : null);
        card.setClickable(editing);
        card.setOnTouchListener(editing ? new DragGuard(card) : null);
    }

    static boolean exceedsTouchSlop(float dx, float dy, int slop) {
        return dx * dx + dy * dy > (float) slop * slop;
    }

    private static final class DragGuard implements View.OnTouchListener {
        private final int slop;
        private float startX;
        private float startY;
        private boolean dragged;

        DragGuard(View view) {
            slop = ViewConfiguration.get(view.getContext()).getScaledTouchSlop();
        }

        @Override
        public boolean onTouch(View view, MotionEvent event) {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    startX = event.getRawX();
                    startY = event.getRawY();
                    dragged = false;
                    break;
                case MotionEvent.ACTION_MOVE:
                    dragged |= exceedsTouchSlop(event.getRawX() - startX, event.getRawY() - startY, slop);
                    break;
                case MotionEvent.ACTION_UP:
                    if (dragged) {
                        dragged = false;
                        var cancel = MotionEvent.obtain(event);
                        cancel.setAction(MotionEvent.ACTION_CANCEL);
                        view.onTouchEvent(cancel);
                        cancel.recycle();
                        return true;
                    }
                    break;
                case MotionEvent.ACTION_CANCEL:
                    dragged = false;
                    break;
                default:
                    break;
            }
            return false;
        }
    }

    private EditableListItem() {
    }
}
