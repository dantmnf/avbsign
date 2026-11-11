package xyz.cirno.avbsign;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import xyz.cirno.avb.util.Logger;

final class BackupStore {
    private static final String METADATA = "metadata.properties";
    private final Path base;

    BackupStore(Path base) {
        this.base = base;
    }

    String create(String pattern, Collection<String> names, String current, String next,
                  String fingerprint, Map<String, String> fingerprintProperties,
                  boolean automatic) throws IOException {
        var unique = new LinkedHashSet<>(names);
        Files.createDirectories(base);
        String id = "backup-" + UUID.randomUUID();
        Path dir = base.resolve(id);
        Files.createDirectory(dir);
        var meta = new Properties();
        meta.setProperty("version", "1");
        meta.setProperty("created", Long.toString(System.currentTimeMillis()));
        meta.setProperty("currentSlot", current);
        meta.setProperty("nextSlot", next);
        meta.setProperty("fingerprint", fingerprint);
        meta.setProperty("automatic", Boolean.toString(automatic));
        meta.setProperty("fingerprintProperty.count", Integer.toString(fingerprintProperties.size()));
        int propertyIndex = 0;
        for (var property : fingerprintProperties.entrySet()) {
            var prefix = "fingerprintProperty." + propertyIndex++ + ".";
            meta.setProperty(prefix + "name", property.getKey());
            meta.setProperty(prefix + "value", property.getValue());
        }
        meta.setProperty("partitions", String.join(",", unique));
        try {
            for (var name : unique) {
                var source = Paths.get(pattern.replace("{}", name));
                long size = AvbTool.fileSize(source);
                Logger.info("备份 %s", source);
                try (var out = new GZIPOutputStream(Files.newOutputStream(dir.resolve(name + ".img.gz")))) {
                    Files.copy(source, out);
                }
                meta.setProperty("size." + name, Long.toString(size));
            }
            try (var out = Files.newOutputStream(dir.resolve(METADATA))) {
                meta.store(out, null);
            }
            return id;
        } catch (IOException | RuntimeException e) {
            try {
                deleteDirectory(dir);
            } catch (IOException cleanup) {
                e.addSuppressed(cleanup);
            }
            throw e;
        }
    }

    ArrayList<String> list() throws IOException {
        var ids = new ArrayList<String>();
        if (!Files.exists(base)) {
            return ids;
        }
        try (var entries = Files.list(base)) {
            entries.filter(Files::isDirectory)
                    .map(p -> p.getFileName().toString())
                    .filter(name -> name.startsWith("backup-"))
                    .forEach(ids::add);
        }
        Collections.sort(ids);
        return ids;
    }

    Properties metadata(String id) throws IOException {
        var result = new Properties();
        try (var in = Files.newInputStream(base.resolve(id).resolve(METADATA))) {
            result.load(in);
        }
        return result;
    }

    List<String> partitions(Properties meta) {
        var value = meta.getProperty("partitions", "");
        return value.isEmpty() ? List.of() : Arrays.asList(value.split(","));
    }

    Boolean automatic(Properties meta) {
        var value = meta.getProperty("automatic");
        return value == null ? null : Boolean.parseBoolean(value);
    }

    Map<String, String> fingerprintProperties(Properties meta) {
        var countText = meta.getProperty("fingerprintProperty.count");
        if (countText == null) {
            return Map.of();
        }
        int count = Integer.parseInt(countText);
        var result = new LinkedHashMap<String, String>();
        for (int i = 0; i < count; i++) {
            var prefix = "fingerprintProperty." + i + ".";
            var name = meta.getProperty(prefix + "name");
            var value = meta.getProperty(prefix + "value");
            if (name != null && value != null) {
                result.put(name, value);
            }
        }
        return result;
    }

    void restore(String id, String pattern) throws IOException {
        var dir = base.resolve(id);
        var meta = metadata(id);
        var names = partitions(meta);
        for (var name : names) {
            var target = Paths.get(pattern.replace("{}", name));
            long expected = Long.parseLong(meta.getProperty("size." + name, "0"));
            if (expected <= 0 || !Files.exists(target) || AvbTool.fileSize(target) != expected) {
                throw new IOException("目标分区不存在或大小不匹配：" + target);
            }
            if (!Files.isRegularFile(dir.resolve(name + ".img.gz"))) {
                throw new IOException("备份镜像缺失：" + name);
            }
        }
        for (var name : names) {
            var target = Paths.get(pattern.replace("{}", name));
            if (target.startsWith("/dev/") && AvbTool.isBlockDeviceReadOnly(target.toString())) {
                AvbTool.setBlockDeviceReadOnly(target.toString(), false);
            }
            Logger.info("恢复 %s -> %s", name, target);
            try (var in = new GZIPInputStream(Files.newInputStream(dir.resolve(name + ".img.gz")));
                 var out = Files.newOutputStream(target, StandardOpenOption.WRITE)) {
                var buffer = new byte[256 * 1024];
                int n;
                while ((n = in.read(buffer)) != -1) {
                    out.write(buffer, 0, n);
                }
            }
        }
    }

    void delete(String id) throws IOException {
        deleteDirectory(base.resolve(id));
    }

    private static void deleteDirectory(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (var entries = Files.list(dir)) {
            for (var entry : entries.toList()) {
                Files.deleteIfExists(entry);
            }
        }
        Files.deleteIfExists(dir);
    }
}
