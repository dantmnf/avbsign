package xyz.cirno.avbsign;

import android.content.Context;
import android.os.RemoteException;
import android.os.SystemProperties;
import android.util.Log;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

import xyz.cirno.avb.util.Logger;

/**
 * Privileged service running under Shizuku (root or shell). All operations
 * that require elevated permissions are executed inside this process, so the
 * UI process never needs to invoke su or other root command lines.
 */
public class AvbService extends IAvbService.Stub {

    private volatile IAvbLogCallback callback;

    public AvbService() {
        attachLogger();
    }

    public AvbService(Context context) {
        attachLogger();
    }

    private void attachLogger() {
        Logger.setListener((level, msg) -> {
            var cb = callback;
            if (cb != null) {
                try {
                    cb.onLog(level, msg);
                } catch (RemoteException ignored) {
                }
            }
        });
    }

    @Override
    public void destroy() {
        System.exit(0);
    }

    @Override
    public void setLogCallback(IAvbLogCallback callback) {
        this.callback = callback;
    }

    @Override
    public String getSlotSuffix() {
        try {
            var aidl = BootControlAidl.getInstance();
            if (aidl != null) {
                var result = aidl.getSuffix(aidl.getActiveBootSlot());
                Log.i("AvbService", "get active slot from aidl: " + result);
            }
        } catch (Throwable ignored) {
        }
        try {
            var hidl = BootControlHidl.getInstance();
            if (hidl != null) {
                var result = hidl.getSuffix(hidl.getActiveBootSlot());
                Log.i("AvbService", "get active slot from hidl: " + result);
                return result;
            }
        } catch (Throwable ignored) {
        }
        var out = SystemProperties.get("ro.boot.slot_suffix", "");
        return out == null ? "" : out.trim();
    }

    @Override
    public int getUid() {
        return android.os.Process.myUid();
    }

    @Override
    public String check(String pattern) {
        try {
            var result = AvbTool.check(pattern);
            var sb = new StringBuilder();
            if (result.hasIssues()) {
                sb.append("验证未通过：\n");
                for (var issue : result.issues) {
                    sb.append("问题：").append(issue).append('\n');
                }
            } else {
                sb.append("验证通过，未发现问题。");
            }
            return sb.toString();
        } catch (Throwable e) {
            return "检查失败：" + e;
        }
    }

    @Override
    public String fix(String sourcePattern, String keysDir, String rootKeyPath, String backupDir) {
        try {
            var options = new AvbTool.FixOptions();
            options.sourcePattern = sourcePattern;
            options.keysDir = keysDir;
            options.rootKeyPath = rootKeyPath;
            options.backupDir = backupDir;
            var rebuilt = AvbTool.fix(options);
            if (rebuilt.isEmpty()) {
                return "验证通过，无需修复。";
            }
            return "已重建并写入分区：" + String.join(", ", rebuilt)
                    + (backupDir != null ? "\n备份目录：" + backupDir : "");
        } catch (Throwable e) {
            return "修复失败：" + e;
        }
    }

    @Override
    public String replaceBootloaderImages(String imagesDir, String slotSuffix, String backupDir) {
        var results = new ArrayList<String>();
        try {
            try (var stream = Files.list(Paths.get(imagesDir))) {
                for (var file : (Iterable<Path>) stream::iterator) {
                    var fileName = file.getFileName().toString();
                    if (!fileName.endsWith(".img")) {
                        continue;
                    }
                    var name = fileName.substring(0, fileName.length() - ".img".length());
                    var target = Paths.get("/dev/block/by-name/" + name + slotSuffix);
                    if (backupDir != null) {
                        Files.createDirectories(Paths.get(backupDir));
                        var backupPath = Paths.get(backupDir, name + ".img");
                        Logger.info("备份 %s -> %s", target, backupPath);
                        AvbTool.copyFile(target, backupPath);
                    }
                    if (AvbTool.isBlockDeviceReadOnly(target.toString())) {
                        Logger.info("设置 %s 为可写", target);
                        AvbTool.setBlockDeviceReadOnly(target.toString(), false);
                    }
                    Logger.info("写入 %s -> %s", fileName, target);
                    AvbTool.copyFile(file, target);
                    results.add(name);
                }
            }
            if (results.isEmpty()) {
                return "目录中没有 .img 文件。";
            }
            return "已刷入分区：" + String.join(", ", results)
                    + (backupDir != null ? "\n备份目录：" + backupDir : "");
        } catch (Throwable e) {
            return "刷写失败：" + e;
        }
    }

    @Override
    public String[] listFiles(String dir) {
        requireManagedDir(dir);
        try (var stream = Files.list(Paths.get(dir))) {
            return stream.filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .sorted()
                    .toArray(String[]::new);
        } catch (IOException e) {
            return new String[0];
        }
    }

    @Override
    public void importFile(String stagedPath, String destDir, String name) {
        requireManagedDir(destDir);
        requireSafeName(name);
        try {
            Files.createDirectories(Paths.get(destDir));
            var dest = Paths.get(destDir, name);
            Files.copy(Paths.get(stagedPath), dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Files.setPosixFilePermissions(dest, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
        } catch (IOException e) {
            throw new RuntimeException("导入失败：" + e);
        }
    }

    @Override
    public void deleteFile(String dir, String name) {
        requireManagedDir(dir);
        requireSafeName(name);
        try {
            Files.deleteIfExists(Paths.get(dir, name));
        } catch (IOException e) {
            throw new RuntimeException("删除失败：" + e);
        }
    }

    private static void requireManagedDir(String dir) {
        if (dir == null || !(dir.equals(AvbPaths.KEYS_DIR) || dir.equals(AvbPaths.BOOTLOADER_DIR)
                || dir.equals(Paths.get(AvbPaths.ROOT_KEY_PATH).getParent().toString()))) {
            throw new SecurityException("不允许访问的目录：" + dir);
        }
    }

    private static void requireSafeName(String name) {
        if (name == null || name.isEmpty() || name.contains("/") || name.equals(".") || name.equals("..")) {
            throw new SecurityException("非法文件名：" + name);
        }
    }

    public static String defaultBackupDir() {
        var ts = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
        return AvbPaths.BACKUP_BASE_DIR + "/backup-" + ts;
    }
}
