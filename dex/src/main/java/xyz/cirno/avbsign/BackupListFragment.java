package xyz.cirno.avbsign;

import android.content.Context;
import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceViewHolder;
import androidx.preference.SwitchPreferenceCompat;

import com.google.android.material.listitem.ListItemCardView;
import com.google.android.material.listitem.ListItemLayout;

abstract class BackupListFragment extends PreferenceFragmentCompat {
    final EditSelection selection = new EditSelection();
    boolean loaded;
    boolean busy;
    String status = "正在连接服务";
    PreferenceCategory listCategory;

    void restoreSelection(@Nullable Bundle state) {
        if (state != null) {
            selection.restore(state.getBoolean("editing"), state.getStringArrayList("selected"));
        }
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle state) {
        super.onViewCreated(view, state);
        setDivider(null);
        var list = getListView();
        list.setItemAnimator(null);
        int horizontal = getResources().getDimensionPixelSize(R.dimen.expressive_list_horizontal_padding);
        list.setPaddingRelative(horizontal, list.getPaddingTop(), horizontal, list.getPaddingBottom());
        list.setClipToPadding(true);
    }

    @Override
    public void onResume() {
        super.onResume();
        requireActivity().setTitle(pageTitle());
        refresh();
    }

    void serviceDisconnected() {
        loaded = false;
        status = "服务不可用，请在主界面授权 Shizuku";
        render();
    }

    abstract void refresh();

    abstract String pageTitle();

    abstract void render();

    abstract void confirmDelete();

    boolean isEditing() {
        return selection.isEditing();
    }

    boolean canEditAction() {
        return !busy && (!selection.isEditing() || !selection.isEmpty());
    }

    void enterEditMode() {
        if (!busy) {
            selection.enter();
            render();
        }
    }

    void exitEditMode() {
        if (!busy) {
            selection.exit();
            render();
        }
    }

    PreferenceCategory category(String title) {
        var result = new PreferenceCategory(requireContext());
        result.setTitle(title);
        result.setLayoutResource(R.layout.preference_category_material3);
        result.setIconSpaceReserved(false);
        result.setOrderingAsAdded(false);
        return result;
    }

    Row row(String title, String summary) {
        var row = new Row(requireContext());
        row.setTitle(title);
        row.setSummary(summary);
        return row;
    }

    SwitchRow switchRow(String title, String summary) {
        var row = new SwitchRow(requireContext());
        row.setTitle(title);
        row.setSummary(summary);
        return row;
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle out) {
        out.putBoolean("editing", selection.isEditing());
        out.putStringArrayList("selected", selection.snapshot());
        super.onSaveInstanceState(out);
    }

    static class Row extends Preference {
        Row(Context context) {
            super(context);
            setLayoutResource(R.layout.preference_material3);
            setIconSpaceReserved(false);
            setPersistent(false);
        }

        @Override
        public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
            super.onBindViewHolder(holder);
            var layout = (ListItemLayout) holder.itemView;
            layout.setBackground(null);
            layout.setClickable(false);
            layout.setFocusable(false);
            PreferenceListPosition.update(layout, this);
            var card = (ListItemCardView) layout.findViewById(R.id.list_item_card);
            boolean actionable = isSelectable() && isEnabled();
            card.setOnClickListener(actionable ? v -> layout.performClick() : null);
            card.setClickable(actionable);
            card.setFocusable(actionable);
        }
    }

    static class SwitchRow extends SwitchPreferenceCompat {
        SwitchRow(Context context) {
            super(context);
            setLayoutResource(R.layout.preference_switch_material3);
            setIconSpaceReserved(false);
            setPersistent(false);
        }

        @Override
        public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
            super.onBindViewHolder(holder);
            var layout = (ListItemLayout) holder.itemView;
            layout.setBackground(null);
            layout.setClickable(false);
            layout.setFocusable(false);
            PreferenceListPosition.update(layout, this);
            var card = (ListItemCardView) layout.findViewById(R.id.list_item_card);
            boolean actionable = isSelectable() && isEnabled();
            card.setOnClickListener(actionable ? v -> layout.performClick() : null);
            card.setClickable(actionable);
            card.setFocusable(actionable);
        }
    }

    final class SelectableRow extends Row {
        private final String name;
        private final boolean opensDetails;

        SelectableRow(Context context, String name, boolean opensDetails) {
            super(context);
            this.name = name;
            this.opensDetails = opensDetails;
        }

        @Override
        public void onBindViewHolder(@NonNull PreferenceViewHolder holder) {
            super.onBindViewHolder(holder);
            if (opensDetails && !selection.isEditing()) {
                EditableListItem.bind((ListItemLayout) holder.itemView, false, false, this::toggle);
                var card = (ListItemCardView) holder.itemView.findViewById(R.id.list_item_card);
                boolean actionable = getOnPreferenceClickListener() != null;
                card.setOnClickListener(actionable ? v -> holder.itemView.performClick() : null);
                card.setClickable(actionable);
                card.setFocusable(actionable);
            } else {
                EditableListItem.bind((ListItemLayout) holder.itemView, !busy && selection.isEditing(),
                        selection.contains(name), this::toggle);
            }
        }

        private void toggle() {
            selection.toggle(name);
            notifyChanged();
            requireActivity().invalidateOptionsMenu();
        }
    }
}
