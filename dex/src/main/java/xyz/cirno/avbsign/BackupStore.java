package xyz.cirno.avbsign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.LinkOption;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.LinkedHashMap;
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
        if (unique.isEmpty() || unique.size() != names.size()) {
            throw new IOException("No partitions or duplicate partition names");
        }
        for (var name : unique) {
            BackupGraph.requireName(name);
            if (!Files.exists(Paths.get(pattern.replace("{}", name)))) {
                throw new IOException("Partition not found: " + name);
            }
        }
        Files.createDirectories(base);
        String id = "backup-" + UUID.randomUUID();
        Path staging = base.resolve("." + id + ".tmp");
        Files.createDirectory(staging);
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
        meta.setProperty("sourcePattern", pattern);
        meta.setProperty("partitions", String.join(",", unique));
        try {
            for (var name : unique) {
                var source = Paths.get(pattern.replace("{}", name));
                long expected = AvbTool.fileSize(source);
                long count;
                Logger.info("备份 %s", source);
                try (var in = Files.newInputStream(source);
                     var channel = FileChannel.open(staging.resolve(name + ".img.gz"),
                             StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                     var out = new GZIPOutputStream(Channels.newOutputStream(channel))) {
                    count = transfer(in, out, expected);
                    out.finish();
                    channel.force(true);
                }
                if (count != expected) {
                    throw new IOException("Unexpected partition size: " + name);
                }
                meta.setProperty("size." + name, Long.toString(count));
            }
            try (var channel = FileChannel.open(staging.resolve(METADATA),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                 var out = Channels.newOutputStream(channel)) {
                meta.store(out, null);
                channel.force(true);
            }
            Files.move(staging, base.resolve(id), StandardCopyOption.ATOMIC_MOVE);
            return id;
        } catch (IOException | RuntimeException e) {
            try {
                deleteDirectory(staging);
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
            entries.filter(p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)
                    && p.getFileName().toString().matches("backup-[0-9a-f-]{36}"))
                    .forEach(p -> ids.add(p.getFileName().toString()));
        }
        Collections.sort(ids);
        return ids;
    }

    Properties metadata(String id) throws IOException {
        var dir = directory(id);
        var result = new Properties();
        if (!Files.isRegularFile(dir.resolve(METADATA), LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Backup metadata missing: " + id);
        }
        try (var in = Files.newInputStream(dir.resolve(METADATA))) {
            result.load(in);
        }
        if (!"1".equals(result.getProperty("version"))) {
            throw new IOException("Unsupported backup format: " + id);
        }
        partitions(result);
        return result;
    }

    ArrayList<String> partitions(Properties meta) throws IOException {
        var value = meta.getProperty("partitions", "");
        var result = new ArrayList<String>();
        for (var name : value.split(",", -1)) {
            try {
                BackupGraph.requireName(name);
            } catch (IllegalArgumentException e) {
                throw new IOException("Invalid backup partition name", e);
            }
            if (result.contains(name)) {
                throw new IOException("Duplicate backup partition: " + name);
            }
            result.add(name);
        }
        return result;
    }

    Boolean automatic(Properties meta) throws IOException {
        var value = meta.getProperty("automatic");
        if (value == null) return null;
        if ("true".equals(value)) return true;
        if ("false".equals(value)) return false;
        throw new IOException("Invalid automatic backup flag");
    }

    Map<String, String> fingerprintProperties(Properties meta) throws IOException {
        var countText = meta.getProperty("fingerprintProperty.count");
        if (countText == null) return Map.of();
        int count;
        try {
            count = Integer.parseInt(countText);
        } catch (NumberFormatException e) {
            throw new IOException("Invalid fingerprint property count", e);
        }
        if (count < 0 || count > meta.size() / 2) {
            throw new IOException("Invalid fingerprint property count");
        }
        var result = new LinkedHashMap<String, String>();
        for (int i = 0; i < count; i++) {
            var prefix = "fingerprintProperty." + i + ".";
            var name = meta.getProperty(prefix + "name");
            var value = meta.getProperty(prefix + "value");
            if (name == null || value == null || result.containsKey(name)) {
                throw new IOException("Invalid fingerprint property at index " + i);
            }
            result.put(name, value);
        }
        return result;
    }

    void restore(String id, String pattern) throws IOException {
        var dir = directory(id);
        var meta = metadata(id);
        var names = partitions(meta);
        for (var name : names) {
            var target = Paths.get(pattern.replace("{}", name));
            long expected;
            try {
                expected = Long.parseLong(meta.getProperty("size." + name, ""));
            } catch (NumberFormatException e) {
                throw new IOException("Invalid image size: " + name, e);
            }
            if (expected <= 0 || !Files.exists(target) || AvbTool.fileSize(target) != expected) {
                throw new IOException("Target partition missing or size differs: " + target);
            }
            long count;
            var image = dir.resolve(name + ".img.gz");
            if (!Files.isRegularFile(image, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Backup image missing: " + name);
            }
            try (var in = new GZIPInputStream(Files.newInputStream(image))) {
                count = transfer(in, null, expected);
            }
            if (count != expected) {
                throw new IOException("Backup integrity check failed: " + name);
            }
        }
        for (var name : names) {
            var target = Paths.get(pattern.replace("{}", name));
            long expected = Long.parseLong(meta.getProperty("size." + name));
            if (target.startsWith("/dev/") && AvbTool.isBlockDeviceReadOnly(target.toString())) {
                AvbTool.setBlockDeviceReadOnly(target.toString(), false);
            }
            Logger.info("恢复 %s -> %s", name, target);
            try (var in = new GZIPInputStream(Files.newInputStream(dir.resolve(name + ".img.gz")));
                 var channel = FileChannel.open(target, StandardOpenOption.WRITE)) {
                long count = transfer(in, Channels.newOutputStream(channel), expected);
                if (count != expected) {
                    throw new IOException("Backup changed during restore: " + name);
                }
                channel.force(true);
            }
        }
    }

    void delete(String id) throws IOException {
        deleteDirectory(directory(id));
    }

    private Path directory(String id) {
        if (id == null || !id.matches("backup-[0-9a-f-]{36}")) {
            throw new IllegalArgumentException("Invalid backup ID: " + id);
        }
        var path = base.resolve(id);
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Invalid backup directory: " + id);
        }
        return path;
    }

    private static void deleteDirectory(Path dir) throws IOException {
        try (var entries = Files.list(dir)) {
            for (var entry : entries.toList()) {
                Files.delete(entry);
            }
        }
        Files.delete(dir);
    }

    private static long transfer(InputStream in, OutputStream out, long maxSize) throws IOException {
        var buffer = new byte[256 * 1024];
        long count = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            if (n > maxSize - count) {
                throw new IOException("Image exceeds expected size");
            }
            if (out != null) out.write(buffer, 0, n);
            count += n;
        }
        return count;
    }
}
