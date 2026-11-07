package xyz.cirno.avbsign;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

final class BootloaderSettings {
    static final String ENABLED = "enabled";
    static final String SOURCE = "source";
    static final String PARTITIONS = "partitions";
    static final String ROOT_KEY = "root_key";
    static final String CURRENT = "current";
    static final String EXTERNAL = "external";

    static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences("bootloader_settings", Context.MODE_PRIVATE);
    }

    static ArrayList<String> partitions(SharedPreferences preferences) {
        var result = new ArrayList<>(preferences.getStringSet(PARTITIONS, Set.of("abl")));
        Collections.sort(result);
        return result;
    }

    static String defaultRootKey(String source, String matchingKey, String matchingError) {
        if (CURRENT.equals(source)) {
            if (matchingError != null) {
                return null;
            }
            return matchingKey == null ? "" : matchingKey;
        }
        return "";
    }

    static void persist(SharedPreferences preferences, String source,
                        Collection<String> partitions, String rootKey) {
        var editor = preferences.edit()
                .putString(SOURCE, source)
                .putStringSet(PARTITIONS, new LinkedHashSet<>(partitions));
        if (rootKey == null) {
            editor.remove(ROOT_KEY);
        } else {
            editor.putString(ROOT_KEY, rootKey);
        }
        editor.apply();
    }

    private BootloaderSettings() {
    }
}
