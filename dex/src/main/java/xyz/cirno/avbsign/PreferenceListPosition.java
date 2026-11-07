package xyz.cirno.avbsign;

import androidx.preference.Preference;

import com.google.android.material.listitem.ListItemLayout;

final class PreferenceListPosition {
    static void update(ListItemLayout layout, Preference preference) {
        var group = preference.getParent();
        int position = -1;
        int count = 0;
        if (group != null) {
            for (int i = 0; i < group.getPreferenceCount(); i++) {
                var sibling = group.getPreference(i);
                if (!sibling.isVisible()) {
                    continue;
                }
                if (sibling == preference) {
                    position = count;
                }
                count++;
            }
        }
        if (position >= 0) {
            layout.updateAppearance(position, count);
        } else {
            layout.updateAppearance(ListItemLayout.POSITION_SINGLE);
        }
    }

    private PreferenceListPosition() {
    }
}
