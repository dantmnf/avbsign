package xyz.cirno.avbsign;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.HashTreeDescriptor;
import xyz.cirno.avb.ParsedVerifiedBootMetaImage;
import xyz.cirno.avb.PartitionProvider;
import xyz.cirno.avb.VerifiedBootFooter;
import xyz.cirno.avb.rebuild.AvbRebuilder;
import xyz.cirno.avb.rebuild.VbmetaRebuildRequest;
import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.util.Logger;
import xyz.cirno.avb.verify.AvbVerifier;
import xyz.cirno.avb.verify.AvbVerifyResult;

/**
 * Reusable check/fix logic shared by the CLI entry point ({@link Main}) and
 * the Android GUI (through the Shizuku user service).
 */
public final class AvbTool {

    private AvbTool() {
    }

    public static final class FixOptions {
        /** Pattern for partition images, with {} as placeholder for the partition name. */
        public String sourcePattern;
        /** Pattern for output images. When null, partitions are fixed in place. */
        public String outputPattern;
        /** Directory containing private keys in PEM format. */
        public String keysDir;
        /** During in-place fix, save backups of modified images in this directory. */
        public String backupDir;
        /** Replace the root key with the specified key. */
        public String rootKeyPath;
        public BackupAction backupAction;
        public BootloaderSources bootloaderSources;
    }

    public interface BackupAction {
        void backup(List<String> partitionNames, String sourcePattern) throws IOException;
    }

    public interface BootloaderSources {
        Map<String, Path> prepare() throws IOException;
    }

    public static AvbVerifier newAvbVerifier(String pattern) {
        return newAvbVerifier(pattern, Map.of());
    }

    private static AvbVerifier newAvbVerifier(String pattern, Map<String, Path> replacements) {
        var prov = new PartitionProvider() {
            @Override
            public SeekableByteChannel openPartition(String name) {
                try {
                    var path = replacements.getOrDefault(name, Paths.get(pattern.replace("{}", name)));
                    return FileChannel.open(path, StandardOpenOption.READ);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
        return new AvbVerifier(prov);
    }

    public static AvbVerifyResult check(String pattern) throws IOException {
        return check(pattern, Map.of());
    }

    private static AvbVerifyResult check(String pattern, Map<String, Path> replacements) throws IOException {
        if (pattern == null || !pattern.contains("{}")) {
            throw new IllegalArgumentException("invalid pattern: " + pattern);
        }
        return newAvbVerifier(pattern, replacements).recursiveVerify("vbmeta");
    }

    public static String findMatchingKey(Path vbmetaPath, Path keysDir) throws IOException {
        final ParsedVerifiedBootMetaImage vbmeta;
        try (var channel = FileChannel.open(vbmetaPath, StandardOpenOption.READ)) {
            vbmeta = ParsedVerifiedBootMetaImage.parseFromPartition(channel);
        }
        if (vbmeta == null || vbmeta.publicKey == null) {
            throw new IOException("vbmeta has no public key: " + vbmetaPath);
        }
        if (Files.notExists(keysDir)) {
            return null;
        }
        try (var files = Files.list(keysDir)) {
            for (var file : files.filter(Files::isRegularFile).sorted().toList()) {
                AvbKeyPair key;
                try {
                    key = AvbKeyPair.fromPrivateKeyPem(file);
                } catch (IllegalArgumentException e) {
                    Logger.warn("Skipping unsupported key " + file + ": " + e.getMessage());
                    continue;
                }
                if (key != null && vbmeta.publicKey.equals(key.publicKey())) {
                    return file.getFileName().toString();
                }
            }
        }
        return null;
    }

    public static void printVerifyResult(AvbVerifyResult result) {
        if (result.hasIssues()) {
            System.out.println("Verification failed with issues:");
            for (var issue : result.issues) {
                System.out.println("Issue: " + issue);
            }
        } else {
            System.out.println("Verification succeeded with no issues.");
        }
    }

    /**
     * @return names of the partitions that were rebuilt
     */
    public static List<String> fix(FixOptions o) throws IOException {
        if (o.sourcePattern == null || !o.sourcePattern.contains("{}")) {
            throw new IllegalArgumentException("source pattern: " + o.sourcePattern);
        }
        if (o.keysDir == null || o.keysDir.isEmpty()) {
            throw new IllegalArgumentException("keys dir: " + o.keysDir);
        }
        var inPlace = o.outputPattern == null;
        if (!inPlace && !o.outputPattern.contains("{}")) {
            throw new IllegalArgumentException("output pattern: " + o.outputPattern);
        }

        var keyPairs = new ArrayList<AvbKeyPair>();
        try (var iter = Files.list(Paths.get(o.keysDir))) {
            iter.forEach(f -> {
                var keypair = AvbKeyPair.fromPrivateKeyPem(f);
                if (keypair != null) {
                    Logger.info("Loaded key with public key hash " + IOUtils.sha256ToHex(keypair.publicKey().toByteArray()));
                    keyPairs.add(keypair);
                }
            });
        }
        if (keyPairs.isEmpty()) {
            throw new IOException("No keys loaded from " + o.keysDir);
        }

        AvbKeyPair rootKey = null;
        if (o.bootloaderSources == null && o.rootKeyPath != null && !o.rootKeyPath.isEmpty()) {
            rootKey = AvbKeyPair.fromPrivateKeyPem(Paths.get(o.rootKeyPath));
            if (rootKey == null) {
                throw new IOException("Unable to load root key from " + o.rootKeyPath);
            }
        }
        var result = check(o.sourcePattern);
        var rebuilt = new ArrayList<String>();
        if (!result.hasIssues()) {
            System.out.println("Verification succeeded with no issues.");
            return rebuilt;
        }

        printVerifyResult(result);
        Map<String, Path> replacements = Map.of();
        List<VbmetaRebuildRequest> parts;
        try {
            parts = planRebuild(result, keyPairs, rootKey);
        } catch (AvbRebuilder.MissingRootKeyException e) {
            if (o.bootloaderSources == null) {
                throw e;
            }
            if (!inPlace) {
                throw new IOException("Bootloader replacement requires in-place repair", e);
            }
            if (o.rootKeyPath == null || o.rootKeyPath.isEmpty()) {
                throw new IOException("需要替换 bootloader，请先配置根密钥", e);
            }
            var replacementKey = AvbKeyPair.fromPrivateKeyPem(Paths.get(o.rootKeyPath));
            if (replacementKey == null) {
                throw new IOException("无法读取替换 bootloader 的根密钥：" + o.rootKeyPath);
            }
            replacements = new LinkedHashMap<>(o.bootloaderSources.prepare());
            validateReplacements(o.sourcePattern, replacements, result);
            Logger.info("根 vbmeta 缺少匹配的私钥，将替换 bootloader 并重新验证");
            var replacementResult = check(o.sourcePattern, replacements);
            parts = planRebuild(replacementResult, keyPairs, replacementKey);
            validateRebuiltWrites(o.sourcePattern, parts);
        }

        var backupNames = new LinkedHashSet<>(replacements.keySet());
        for (var part : parts) {
            backupNames.add(part.partitionName());
        }
        if (inPlace && !parts.isEmpty()) {
            if (o.backupAction != null) {
                o.backupAction.backup(new ArrayList<>(backupNames), o.sourcePattern);
            }
            if (o.backupDir != null && !o.backupDir.isEmpty()) {
                Files.createDirectories(Paths.get(o.backupDir));
                for (var name : backupNames) {
                    var oldPath = Paths.get(o.sourcePattern.replace("{}", name));
                    var backupPath = Paths.get(o.backupDir, name + ".img");
                    Logger.info("Creating backup at " + backupPath);
                    Files.copy(oldPath, backupPath);
                }
            }
        }

        for (var entry : replacements.entrySet()) {
            var target = Paths.get(o.sourcePattern.replace("{}", entry.getKey()));
            if (target.startsWith("/dev/") && isBlockDeviceReadOnly(target.toString())) {
                setBlockDeviceReadOnly(target.toString(), false);
            }
            Logger.info("写入 %s -> %s", entry.getValue(), target);
            copyFile(entry.getValue(), target);
        }
        for (var part : parts) {
            Logger.info("Rebuilding partition " + part.partitionName());
            var oldPath = Paths.get(o.sourcePattern.replace("{}", part.partitionName()));
            if (inPlace) {
                if (oldPath.startsWith("/dev/") && isBlockDeviceReadOnly(oldPath.toString())) {
                    Logger.info("Setting " + oldPath + " read-write");
                    setBlockDeviceReadOnly(oldPath.toString(), false);
                }
                try (var f = FileChannel.open(oldPath, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                    part.rebuildInplace(f);
                } catch (Exception e) {
                    Logger.error("Failed to rebuild partition " + part.partitionName() + ": " + e);
                    e.printStackTrace();
                    throw new IOException("Failed to rebuild partition " + part.partitionName(), e);
                }
            } else {
                var outfile = o.outputPattern.replace("{}", part.partitionName());
                try (var instream = FileChannel.open(oldPath, StandardOpenOption.READ);
                     var outstream = FileChannel.open(Paths.get(outfile), StandardOpenOption.WRITE)) {
                    part.rebuildCopy(instream, outstream);
                } catch (Exception e) {
                    Logger.error("Failed to rebuild partition " + part.partitionName() + ": " + e);
                    e.printStackTrace();
                    throw new IOException("Failed to rebuild partition " + part.partitionName(), e);
                }
            }
            rebuilt.add(part.partitionName());
        }
        return rebuilt;
    }

    private static List<VbmetaRebuildRequest> planRebuild(AvbVerifyResult result,
                                                          List<AvbKeyPair> keyPairs,
                                                          AvbKeyPair rootKey) throws IOException {
        var rebuilder = new AvbRebuilder(result);
        for (var keypair : keyPairs) {
            rebuilder.addKeyPair(keypair);
        }
        if (rootKey != null) {
            Logger.info("Overriding root key with " + rootKey.publicKey());
            rebuilder.setRootKey(rootKey);
        }
        return rebuilder.rebuildWithTrustedData();
    }

    private static void validateReplacements(String pattern, Map<String, Path> replacements,
                                             AvbVerifyResult result) throws IOException {
        if (replacements.isEmpty()) {
            throw new IOException("未选择 bootloader 替换镜像");
        }
        var referenced = new HashSet<>(result.partitionRecords.keySet());
        for (var reference : result.partitionReferences) {
            referenced.add(reference.partitionName());
        }
        for (var record : result.partitionRecords.values()) {
            for (var descriptor : record.vbmetaImage().descriptors) {
                if (descriptor instanceof HashTreeDescriptor tree
                        && replacements.containsKey(tree.partitionName)) {
                    throw new IOException("不支持替换受 AVB 哈希树保护的分区：" + tree.partitionName);
                }
            }
        }
        for (var entry : replacements.entrySet()) {
            var source = entry.getValue();
            var target = Paths.get(pattern.replace("{}", entry.getKey()));
            long sourceSize = fileSize(source);
            long targetSize = fileSize(target);
            if (sourceSize <= 0 || sourceSize > targetSize) {
                throw new IOException("替换来源大小无效或大于目标分区：" + entry.getKey());
            }
            if (referenced.contains(entry.getKey()) && sourceSize != targetSize) {
                throw new IOException("AVB 引用的替换镜像大小与目标分区不同：" + entry.getKey());
            }
        }
    }

    private static void validateRebuiltWrites(String pattern, List<VbmetaRebuildRequest> parts) throws IOException {
        for (var part : parts) {
            long size = fileSize(Paths.get(pattern.replace("{}", part.partitionName())));
            if (part.signKey() != null
                    && part.signKey().publicKey().keySizeBits != part.header().header.algorithmType.getKeySize()) {
                throw new IOException("签名密钥大小与 vbmeta 算法不匹配：" + part.partitionName());
            }
            long imageSize = part.header().toByteArray(part.signKey()).length;
            if (part.footer() == null) {
                if (imageSize > size) {
                    throw new IOException("重建后的 vbmeta 大于目标分区：" + part.partitionName());
                }
            } else if (part.footer().originalImageSize > size - VerifiedBootFooter.FOOTER_SIZE
                    || imageSize > size - VerifiedBootFooter.FOOTER_SIZE - part.footer().originalImageSize) {
                throw new IOException("重建后的 vbmeta 无法放入目标分区：" + part.partitionName());
            }
        }
    }

    private static boolean nativeLoaded;

    private static synchronized void loadNative() {
        if (!nativeLoaded) {
            System.loadLibrary("avbsign");
            nativeLoaded = true;
        }
    }

    private static native boolean nativeIsBlockDeviceReadOnly(String path) throws IOException;

    private static native void nativeSetBlockDeviceReadOnly(String path, boolean readOnly) throws IOException;

    public static boolean isBlockDeviceReadOnly(String path) throws IOException {
        loadNative();
        return nativeIsBlockDeviceReadOnly(path);
    }

    public static void setBlockDeviceReadOnly(String path, boolean readOnly) throws IOException {
        loadNative();
        nativeSetBlockDeviceReadOnly(path, readOnly);
    }

    public static long fileSize(Path path) throws IOException {
        try (var channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return channel.size();
        }
    }

    public static void copyFile(Path from, Path to) throws IOException {
        var options = to.startsWith("/dev")
                ? new StandardOpenOption[]{StandardOpenOption.WRITE}
                : new StandardOpenOption[]{StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE};
        try (var out = Files.newOutputStream(to, options)) {
            Files.copy(from, out);
        }
    }
}
