package xyz.cirno.avbsign;

import xyz.cirno.avbsign.IAvbLogCallback;

interface IAvbService {
    void destroy() = 16777114;

    void setLogCallback(IAvbLogCallback callback) = 1;

    /** Current boot slot suffix (e.g. "_a"), or empty on non-A/B devices. */
    String getSlotSuffix() = 2;

    /** Service process uid; 0 means the service is running as root. */
    int getUid() = 3;

    String check(String pattern) = 4;

    String fix(String sourcePattern, String keysDir, String rootKeyPath, String backupDir) = 5;

    /** Replace partitions with the .img files in imagesDir, backing up originals first. */
    String replaceBootloaderImages(String imagesDir, String slotSuffix, String backupDir) = 6;

    /** List file names in a directory under /data/adb. */
    String[] listFiles(String dir) = 7;

    /** Copy a file staged by the app into a managed directory under /data/adb. */
    void importFile(String stagedPath, String destDir, String name) = 8;

    /** Delete a file from a managed directory under /data/adb. */
    void deleteFile(String dir, String name) = 9;
}
