package xyz.cirno.avbsign;

/** Managed file locations, consistent with the Magisk module scripts. */
public final class AvbPaths {
    private AvbPaths() {
    }

    /** Private keys, same directory the module's action.sh passes via --keys. */
    public static final String KEYS_DIR = "/data/adb/modules/avbsign/keys";
    /** Root key override, same path action.sh checks. */
    public static final String ROOT_KEY_PATH = "/data/adb/avbsign/rootkey.pem";
    /** Bootloader images flashed by action.sh. */
    public static final String BOOTLOADER_DIR = "/data/adb/avbsign/bootloader";
    /** Backups created before in-place modifications. */
    public static final String BACKUP_BASE_DIR = "/data/adb/avbsign";
}
