package xyz.cirno.avbsign;

import android.content.Context;
import android.os.RemoteException;
import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import xyz.cirno.avb.rebuild.AvbRebuilder;
import xyz.cirno.avb.util.Logger;

/**
 * Privileged service running under Shizuku (root or shell). All operations
 * that require elevated permissions are executed inside this process, so the
 * UI process never needs to invoke su or other root command lines.
 */
public class AvbService extends IAvbService.Stub {
    private final BackupStore backups = new BackupStore(Paths.get(AvbPaths.BACKUP_BASE_DIR));
    private volatile IAvbLogCallback callback;

    public AvbService() {
        attachLogger();
    }

    public AvbService(Context context) {
        attachLogger();
    }

    private void attachLogger() {
        Logger.setListener((level, msg) -> {
            Log.i("AvbService", msg);
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
    public String getActiveSlotSuffix() {
        try {
            var aidl = BootControlAidl.getInstance();
            if (aidl != null) {
                var result = aidl.getSuffix(aidl.getActiveBootSlot());
                Log.i("AvbService", "get active slot from aidl: " + result);
                return result;
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
    public String getBackupSlot() {
        Exception failure = null;
        try {
            var aidl = BootControlAidl.getInstance();
            if (aidl != null) {
                return aidl.getSuffix(aidl.getActiveBootSlot());
            }
        } catch (Exception e) {
            failure = e;
        }
        try {
            var hidl = BootControlHidl.getInstance();
            if (hidl != null) {
                return hidl.getSuffix(hidl.getActiveBootSlot());
            }
        } catch (Exception e) {
            if (failure != null) {
                e.addSuppressed(failure);
            }
            failure = e;
        }
        throw new IllegalStateException("无法确定下次启动槽位", failure);
    }

    @Override
    public String getCurrentSlot() {
        var current = SystemProperties.get("ro.boot.slot_suffix", "").trim();
        if (current.isEmpty()) {
            throw new IllegalStateException("无法确定当前启动槽位");
        }
        return current;
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
    public String fix(String sourcePattern, String keysDir, String rootKeyPath, boolean autoBackup,
                      boolean replaceBootloader, boolean currentSource, String[] partitions) {
        try {
            var options = new AvbTool.FixOptions();
            options.sourcePattern = sourcePattern;
            options.keysDir = keysDir;
            options.rootKeyPath = rootKeyPath;
            if (replaceBootloader) {
                options.bootloaderSources = () -> bootloaderSources(currentSource, partitions);
            }
            if (autoBackup) {
                options.backupAction = (names, pattern) -> createBackupForPattern(pattern, names, true);
            }
            var rebuilt = AvbTool.fix(options);
            if (rebuilt.isEmpty()) {
                return "验证通过，无需修复。";
            }
            return "已重建并写入分区：" + String.join(", ", rebuilt)
                    + (autoBackup ? "\n已创建自动备份。" : "");
        } catch (AvbRebuilder.MissingRootKeyException e) {
            return "修复失败：根 vbmeta 缺少匹配的私钥，请导入密钥或启用替换 bootloader。";
        } catch (Throwable e) {
            return "修复失败：" + e;
        }
    }

    @Override
    public String findCurrentSlotRootKey() {
        try {
            var current = getCurrentSlot();
            return AvbTool.findMatchingKey(Paths.get("/dev/block/by-name/vbmeta" + current),
                    Paths.get(AvbPaths.KEYS_DIR));
        } catch (Exception e) {
            throw new IllegalStateException("读取当前槽位 vbmeta 或密钥失败：" + e.getMessage(), e);
        }
    }

    private Map<String, Path> bootloaderSources(boolean currentSource, String[] partitions)
            throws IOException {
        var sources = new LinkedHashMap<String, Path>();
        if (currentSource) {
            if (partitions == null || partitions.length == 0) {
                throw new IllegalArgumentException("未选择分区");
            }
            var current = getCurrentSlot();
            for (var name : partitions) {
                sources.put(name, Paths.get("/dev/block/by-name/" + name + current));
            }
        } else {
            try (var files = Files.list(Paths.get(AvbPaths.BOOTLOADER_DIR))) {
                for (var file : files.filter(Files::isRegularFile)
                        .filter(p -> p.getFileName().toString().endsWith(".img")).sorted().toList()) {
                    var filename = file.getFileName().toString();
                    var name = filename.substring(0, filename.length() - 4);
                    sources.put(name, file);
                }
            }
        }
        return sources;
    }

    private String createBackupForPattern(String pattern, Collection<String> selected,
                                          boolean automatic) throws IOException {
        var current = getCurrentSlot();
        var next = getBackupSlot();
        Log.i("AvbService", "BackupGraph.read " + pattern);
        var graph = BackupGraph.read(pattern);
        var names = new LinkedHashSet<>(selected);
        names.addAll(graph.dependencies(selected));
        var sourceSlot = pattern.endsWith(current) ? current : pattern.endsWith(next) ? next : "";
        graph.scanEmbeddedFingerprints(pattern, names, sourceSlot);
        var currentFingerprints = readCurrentVbmetaFingerprints();
        if (currentFingerprints.isEmpty()) {
            Logger.warn("当前槽位 vbmeta 中没有 fingerprint 属性，无法比较当前系统。");
        }
        var id = backups.create(pattern, names, current, next, graph.fingerprint(currentFingerprints),
                graph.fingerprintProperties(), automatic);
        Logger.info("备份已保存：%s", id);
        return id;
    }

    @Override
    public String[] backupDependencies(String[] partitions) {
        try {
            var next = getBackupSlot();
            var pattern = "/dev/block/by-name/{}" + next;
            Log.i("AvbService", "BackupGraph.read " + pattern);
            return BackupGraph.read(pattern)
                    .dependencies(Arrays.asList(partitions)).toArray(new String[0]);
        } catch (IOException e) {
            throw new IllegalStateException("读取 vbmeta 失败：" + e.getMessage(), e);
        }
    }

    @Override
    public String createBackup(String[] partitions, String expectedSlot) {
        try {
            var id = createBackupForPattern("/dev/block/by-name/{}" + expectedSlot,
                    Arrays.asList(partitions), false);
            return "备份完成：" + id;
        } catch (Exception e) {
            return "备份失败：" + e;
        }
    }

    @Override
    public String[] listBackups() {
        try {
            var result = new ArrayList<String>();
            Map<String, String> currentFingerprints = null;
            String currentFingerprintError = null;
            try {
                currentFingerprints = readCurrentVbmetaFingerprints();
            } catch (IOException | RuntimeException e) {
                currentFingerprintError = e.toString();
                Log.e("AvbService", "读取当前槽位 vbmeta fingerprint 失败", e);
            }
            for (var id : backups.list()) {
                var json = new JSONObject();
                json.put("id", id);
                try {
                    var meta = backups.metadata(id);
                    var automatic = backups.automatic(meta);
                    if (automatic != null) {
                        json.put("automatic", automatic);
                    }
                    json.put("created", meta.getProperty("created", ""));
                    json.put("currentSlot", meta.getProperty("currentSlot", ""));
                    json.put("nextSlot", meta.getProperty("nextSlot", ""));
                    json.put("fingerprint", meta.getProperty("fingerprint", ""));
                    boolean propertiesAvailable = meta.containsKey("fingerprintProperty.count");
                    json.put("fingerprintPropertiesAvailable", propertiesAvailable);
                    var fingerprintProperties = new JSONArray();
                    var storedFingerprints = backups.fingerprintProperties(meta);
                    for (var property : storedFingerprints.entrySet()) {
                        var item = new JSONObject();
                        item.put("name", property.getKey());
                        item.put("value", property.getValue());
                        fingerprintProperties.put(item);
                    }
                    json.put("fingerprintProperties", fingerprintProperties);
                    json.put("fingerprintMatch",
                            FingerprintComparison.compare(currentFingerprints, storedFingerprints, propertiesAvailable).name());
                    if (currentFingerprintError != null) {
                        json.put("currentFingerprintError", currentFingerprintError);
                    }
                    json.put("sourcePattern", meta.getProperty("sourcePattern", ""));
                    json.put("partitions", new JSONArray(backups.partitions(meta)));
                } catch (IOException | RuntimeException e) {
                    Log.e("AvbService", "读取备份元数据失败：" + id, e);
                    json.put("error", e.toString());
                }
                result.add(json.toString());
            }
            return result.toArray(new String[0]);
        } catch (Exception e) {
            throw new IllegalStateException("读取备份失败：" + e.getMessage(), e);
        }
    }

    private Map<String, String> readCurrentVbmetaFingerprints() throws IOException {
        var current = getCurrentSlot();
        return BackupGraph.readRootFingerprintProperties(Paths.get("/dev/block/by-name/vbmeta" + current));
    }

    @Override
    public void deleteBackup(String id) {
        try {
            backups.delete(id);
        } catch (IOException e) {
            throw new IllegalStateException("删除备份失败：" + e.getMessage(), e);
        }
    }

    @Override
    public String restoreBackup(String id, String expectedSlot) {
        try {
            backups.restore(id, "/dev/block/by-name/{}" + expectedSlot);
            return "备份恢复完成。";
        } catch (Exception e) {
            return "恢复失败：" + e;
        }
    }

    @Override
    public String[] listFiles(String dir) {
        try (var stream = Files.list(Paths.get(dir))) {
            return stream.filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .sorted()
                    .toArray(String[]::new);
        } catch (NoSuchFileException e) {
            return new String[0];
        } catch (IOException e) {
            throw new IllegalStateException("读取目录失败：" + dir, e);
        }
    }

    @Override
    public void importFile(String stagedPath, String destDir, String name) {
        try {
            Files.createDirectories(Paths.get(destDir));
            var dest = Paths.get(destDir, name);
            Files.copy(Paths.get(stagedPath), dest, StandardCopyOption.REPLACE_EXISTING);
            Files.setPosixFilePermissions(dest, PosixFilePermissions.fromString("rw-r--r--"));
        } catch (IOException e) {
            throw new RuntimeException("导入失败：" + e);
        }
    }

    @Override
    public void deleteFile(String dir, String name) {
        try {
            Files.deleteIfExists(Paths.get(dir, name));
        } catch (IOException e) {
            throw new RuntimeException("删除失败：" + e);
        }
    }
}
