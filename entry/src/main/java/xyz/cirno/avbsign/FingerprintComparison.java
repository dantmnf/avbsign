package xyz.cirno.avbsign;

import java.util.Map;

public final class FingerprintComparison {
    public enum Result { MATCH, MISMATCH, UNKNOWN }

    public static Result compare(Map<String, String> current, Map<String, String> backup,
                                 boolean backupPropertiesAvailable) {
        if (!backupPropertiesAvailable || current == null || current.isEmpty()) {
            return Result.UNKNOWN;
        }
        for (var entry : current.entrySet()) {
            if (!entry.getValue().equals(backup.get(entry.getKey()))) {
                return Result.MISMATCH;
            }
        }
        return Result.MATCH;
    }

    private FingerprintComparison() {
    }
}
