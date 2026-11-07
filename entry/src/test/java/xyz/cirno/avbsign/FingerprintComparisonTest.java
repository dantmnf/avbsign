package xyz.cirno.avbsign;

import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;

public class FingerprintComparisonTest {
    @Test
    public void comparesAllCurrentKeysAndAllowsExtraBackupProperties() {
        var current = Map.of("system.fingerprint", "system", "vendor.fingerprint", "vendor");
        assertEquals(FingerprintComparison.Result.MATCH, FingerprintComparison.compare(current,
                Map.of("system.fingerprint", "system", "vendor.fingerprint", "vendor",
                        "boot.fingerprint", "boot"), true));
        assertEquals(FingerprintComparison.Result.MISMATCH, FingerprintComparison.compare(current,
                Map.of("system.fingerprint", "system", "vendor.fingerprint", "other"), true));
        assertEquals(FingerprintComparison.Result.MISMATCH, FingerprintComparison.compare(current,
                Map.of("system.fingerprint", "system"), true));
        assertEquals(FingerprintComparison.Result.MISMATCH, FingerprintComparison.compare(current,
                Map.of("system.fingerprint", "vendor", "vendor.fingerprint", "system"), true));
        assertEquals(FingerprintComparison.Result.MISMATCH, FingerprintComparison.compare(current, Map.of(), true));
        assertEquals(FingerprintComparison.Result.MATCH, FingerprintComparison.compare(
                Map.of("system.fingerprint", ""), Map.of("system.fingerprint", ""), true));
    }

    @Test
    public void reportsUnknownWhenCurrentOrLegacyMetadataCannotBeCompared() {
        var current = Map.of("system.fingerprint", "system");
        assertEquals(FingerprintComparison.Result.UNKNOWN, FingerprintComparison.compare(null, current, true));
        assertEquals(FingerprintComparison.Result.UNKNOWN, FingerprintComparison.compare(Map.of(), current, true));
        assertEquals(FingerprintComparison.Result.UNKNOWN, FingerprintComparison.compare(current, Map.of(), false));
    }
}
