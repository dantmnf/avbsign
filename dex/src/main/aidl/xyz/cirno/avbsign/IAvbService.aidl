package xyz.cirno.avbsign;

import xyz.cirno.avbsign.IAvbLogCallback;

interface IAvbService {
    void destroy() = 16777114;

    long setLogCallback(IAvbLogCallback callback) = 1;

    /** Current boot slot suffix (e.g. "_a"), or empty on non-A/B devices. */
    String getSlotSuffix() = 2;

    /** Service process uid; 0 means the service is running as root. */
    int getUid() = 3;

    String check(String pattern) = 4;

    String fix(String sourcePattern, String keysDir, String rootKeyPath, String backupDir,
               boolean replaceBootloader, boolean currentSource, in String[] partitions) = 5;

    /** List file names in a directory under /data/adb. */
    String[] listFiles(String dir) = 7;

    /** Copy a file staged by the app into a managed directory under /data/adb. */
    void importFile(String stagedPath, String destDir, String name) = 8;

    /** Delete a file from a managed directory under /data/adb. */
    void deleteFile(String dir, String name) = 9;

    String findCurrentSlotRootKey() = 10;

    String[] backupDependencies(in String[] partitions) = 12;

    String createBackup(in String[] partitions, String expectedSlot) = 13;

    String[] listBackups() = 14;

    void deleteBackup(String id) = 15;

    String restoreBackup(String id, String expectedSlot) = 16;

    String getBackupSlot() = 17;

    String getCurrentSlot() = 18;
}
