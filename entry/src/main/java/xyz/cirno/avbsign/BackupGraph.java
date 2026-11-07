package xyz.cirno.avbsign;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import xyz.cirno.avb.ChainPartitionDescriptor;
import xyz.cirno.avb.HashDescriptor;
import xyz.cirno.avb.HashTreeDescriptor;
import xyz.cirno.avb.ParsedVerifiedBootMetaImage;
import xyz.cirno.avb.PropertyDescriptor;
import xyz.cirno.avb.util.Logger;

public final class BackupGraph {
    private final Map<String, Set<String>> parents = new HashMap<>();
    private final Map<String, String> properties = new HashMap<>();
    private final Set<String> unslotted = new HashSet<>();
    private final Set<PartitionCandidate> referencedPartitions = new LinkedHashSet<>();
    private final Set<PartitionCandidate> inspectedPartitions = new HashSet<>();
    private final Map<String, String> fingerprintProperties = new LinkedHashMap<>();
    private final Map<String, Set<String>> observedFingerprints = new HashMap<>();

    private record PartitionCandidate(String name, boolean slotted) {
    }

    public static BackupGraph read(String pattern) throws IOException {
        Logger.info("BackupGraph.read " + pattern);
        if (pattern == null || !pattern.contains("{}")) {
            throw new IllegalArgumentException("Invalid partition pattern: " + pattern);
        }
        var graph = new BackupGraph();
        graph.readPartition(pattern, "vbmeta", new HashSet<>());
        return graph;
    }

    public static Map<String, String> readRootFingerprintProperties(Path path) throws IOException {
        ParsedVerifiedBootMetaImage image;
        try (var channel = FileChannel.open(path, StandardOpenOption.READ)) {
            image = ParsedVerifiedBootMetaImage.parseFromPartition(channel);
        }
        if (image == null) {
            throw new IOException("Failed to parse vbmeta image in " + path);
        }
        var graph = new BackupGraph();
        graph.collectProperties("vbmeta", image);
        return graph.fingerprintProperties();
    }

    private void readPartition(String pattern, String name, Set<String> visited) throws IOException {
        Logger.info("readPartition %s %s", pattern, name);
        requireName(name);
        if (!visited.add(name)) {
            return;
        }
        ParsedVerifiedBootMetaImage image;
        try (var channel = FileChannel.open(Paths.get(pattern.replace("{}", name)), StandardOpenOption.READ)) {
            image = ParsedVerifiedBootMetaImage.parseFromPartition(channel);
        }

        if (image == null) {
            throw new IOException("Failed to parse vbmeta image in " + name);
        }

        inspectedPartitions.add(new PartitionCandidate(name, true));
        collectProperties(name, image);
        for (var descriptor : image.descriptors) {
            String child = null;
            int flags = 0;
            boolean chain = false;
            if (descriptor instanceof ChainPartitionDescriptor d) {
                child = d.partitionName;
                flags = d.flags;
                chain = true;
            } else if (descriptor instanceof HashDescriptor d) {
                child = d.partitionName;
                flags = d.flags;
            } else if (descriptor instanceof HashTreeDescriptor d) {
                child = d.partitionName;
                flags = d.flags;
            }
            if (child != null) {
                requireName(child);
                referencedPartitions.add(new PartitionCandidate(child, (flags & 1) == 0));
                if ((flags & 1) != 0) {
                    unslotted.add(child);
                    if (chain) {
                        throw new IOException("Non-A/B chain partition is not supported: " + child);
                    }
                }
                if (!child.equals(name)) {
                    parents.computeIfAbsent(child, ignored -> new LinkedHashSet<>()).add(name);
                }
                if (chain) {
                    readPartition(pattern, child, visited);
                }
            }
        }
    }

    private void collectProperties(String partition, ParsedVerifiedBootMetaImage image) {
        for (var descriptor : image.descriptors) {
            if (descriptor instanceof PropertyDescriptor d) {
                properties.putIfAbsent(d.name, d.value);
                if (d.name.equals("fingerprint") || d.name.endsWith(".fingerprint")) {
                    observedFingerprints.computeIfAbsent(d.name, ignored -> new HashSet<>()).add(d.value);
                    var previous = fingerprintProperties.putIfAbsent(d.name, d.value);
                    if (previous != null && !previous.equals(d.value)) {
                        Logger.warn("Fingerprint property %s in %s differs from the first value: %s != %s",
                                d.name, partition, d.value, previous);
                    }
                }
            }
        }
    }

    public void scanEmbeddedFingerprints(String pattern, Collection<String> selected, String slotSuffix) {
        var candidates = new ArrayDeque<>(referencedPartitions);
        for (var name : selected) {
            requireName(name);
            candidates.add(new PartitionCandidate(name, true));
        }
        while (!candidates.isEmpty()) {
            var entry = candidates.remove();
            var name = entry.name();
            var slotted = entry.slotted();
            if (!inspectedPartitions.add(entry)) {
                continue;
            }
            var sourcePattern = pattern;
            if (!slotted) {
                if (slotSuffix != null && !slotSuffix.isEmpty() && pattern.endsWith(slotSuffix)) {
                    sourcePattern = pattern.substring(0, pattern.length() - slotSuffix.length());
                } else if (pattern.startsWith("/dev/block/by-name/")) {
                    Logger.warn("Cannot locate non-A/B partition for fingerprint inspection: %s", name);
                    continue;
                }
            }
            var path = Paths.get(sourcePattern.replace("{}", name));
            if (sourcePattern.startsWith("/dev/block/by-name/") && !Files.exists(path)) {
                var mapperPath = Paths.get(sourcePattern.replace("/dev/block/by-name/", "/dev/block/mapper/")
                        .replace("{}", name));
                if (Files.exists(mapperPath)) path = mapperPath;
            }
            try (var channel = FileChannel.open(path, StandardOpenOption.READ)) {
                long size = AvbTool.fileSize(path);
                if (size < Integer.BYTES) continue;
                var image = ParsedVerifiedBootMetaImage.parseFromPartition(new SizedChannel(channel, size));
                if (image != null) {
                    collectProperties(name, image);
                    for (var descriptor : image.descriptors) {
                        String child = null;
                        int flags = 0;
                        if (descriptor instanceof ChainPartitionDescriptor d) {
                            child = d.partitionName;
                            flags = d.flags;
                        } else if (descriptor instanceof HashDescriptor d) {
                            child = d.partitionName;
                            flags = d.flags;
                        } else if (descriptor instanceof HashTreeDescriptor d) {
                            child = d.partitionName;
                            flags = d.flags;
                        }
                        if (child != null) {
                            requireName(child);
                            candidates.add(new PartitionCandidate(child, (flags & 1) == 0));
                        }
                    }
                }
            } catch (IOException e) {
                Logger.warn("Cannot inspect partition %s for fingerprint properties: %s", path, e);
            }
        }
    }

    public Map<String, String> fingerprintProperties() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(fingerprintProperties));
    }

    private static final class SizedChannel implements SeekableByteChannel {
        private final SeekableByteChannel channel;
        private final long size;

        SizedChannel(SeekableByteChannel channel, long size) {
            this.channel = channel;
            this.size = size;
        }

        @Override public int read(ByteBuffer dst) throws IOException { return channel.read(dst); }
        @Override public int write(ByteBuffer src) throws IOException { return channel.write(src); }
        @Override public long position() throws IOException { return channel.position(); }
        @Override public SeekableByteChannel position(long position) throws IOException {
            channel.position(position);
            return this;
        }
        @Override public long size() { return size; }
        @Override public SeekableByteChannel truncate(long size) throws IOException {
            channel.truncate(size);
            return this;
        }
        @Override public boolean isOpen() { return channel.isOpen(); }
        @Override public void close() throws IOException { channel.close(); }
    }

    public ArrayList<String> dependencies(Collection<String> partitions) {
        for (var name : partitions) {
            if (unslotted.contains(name)) {
                throw new IllegalArgumentException("Non-A/B partition is not supported: " + name);
            }
        }
        var pending = new ArrayDeque<>(partitions);
        var seen = new HashSet<>(partitions);
        var result = new LinkedHashSet<String>();
        while (!pending.isEmpty()) {
            for (var parent : parents.getOrDefault(pending.remove(), Set.of())) {
                if (seen.add(parent)) {
                    result.add(parent);
                    pending.add(parent);
                }
            }
        }
        var sorted = new ArrayList<>(result);
        sorted.sort(String::compareTo);
        return sorted;
    }

    public String fingerprint() {
        return fingerprint(Map.of());
    }

    public String fingerprint(Map<String, String> currentFingerprints) {
        for (var entry : currentFingerprints.entrySet()) {
            var value = entry.getValue();
            if (!value.isEmpty() && observedFingerprints.getOrDefault(entry.getKey(), Set.of()).contains(value)) {
                return value;
            }
        }
        for (var key : new String[]{"com.android.build.system.fingerprint",
                "com.android.build.boot.fingerprint", "com.android.build.vendor.fingerprint"}) {
            var value = properties.get(key);
            if (value != null && !value.isEmpty()) return value;
        }
        return "";
    }

    public static void requireName(String name) {
        if (name == null || !name.matches("[A-Za-z0-9][A-Za-z0-9_.-]*")) {
            throw new IllegalArgumentException("Invalid partition name: " + name);
        }
    }
}
