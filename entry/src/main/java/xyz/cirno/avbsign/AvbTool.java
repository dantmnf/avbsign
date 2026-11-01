package xyz.cirno.avbsign;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.PartitionProvider;
import xyz.cirno.avb.rebuild.AvbRebuilder;
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
    }

    public static AvbVerifier newAvbVerifier(String pattern) {
        var prov = new PartitionProvider() {
            @Override
            public SeekableByteChannel openPartition(String name) {
                try {
                    var path = Paths.get(pattern.replace("{}", name));
                    return FileChannel.open(path, StandardOpenOption.READ);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
        return new AvbVerifier(prov);
    }

    public static AvbVerifyResult check(String pattern) throws IOException {
        if (pattern == null || !pattern.contains("{}")) {
            throw new IllegalArgumentException("invalid pattern: " + pattern);
        }
        return newAvbVerifier(pattern).recursiveVerify("vbmeta");
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
        var inPlace = o.outputPattern == null;
        if (o.sourcePattern == null || !o.sourcePattern.contains("{}")) {
            throw new IllegalArgumentException("source pattern: " + o.sourcePattern);
        }
        if (o.keysDir == null || o.keysDir.isEmpty()) {
            throw new IllegalArgumentException("keys dir: " + o.keysDir);
        }
        if (!inPlace && !o.outputPattern.contains("{}")) {
            throw new IllegalArgumentException("output pattern: " + o.outputPattern);
        }

        var keyPairs = new ArrayList<AvbKeyPair>();
        try (var iter = Files.list(Paths.get(o.keysDir))) {
            iter.forEach(f -> {
                var keypair = AvbKeyPair.fromPrivateKeyPem(f);
                if (keypair != null) {
                    Logger.info("Loaded key with public key hash " + IOUtils.sha256ToHex(keypair.publicKey.toByteArray()));
                    keyPairs.add(keypair);
                }
            });
        }
        if (keyPairs.isEmpty()) {
            throw new IOException("No keys loaded from " + o.keysDir);
        }

        var result = check(o.sourcePattern);
        var rebuilt = new ArrayList<String>();
        if (result.hasIssues()) {
            printVerifyResult(result);
            var rebuilder = new AvbRebuilder(result);
            for (var keypair : keyPairs) {
                rebuilder.addKeyPair(keypair);
            }
            if (o.rootKeyPath != null && !o.rootKeyPath.isEmpty()) {
                var keypair = AvbKeyPair.fromPrivateKeyPem(Paths.get(o.rootKeyPath));
                if (keypair != null) {
                    Logger.info("Overriding root key with " + keypair.publicKey);
                    rebuilder.setRootKey(keypair);
                }
            }
            var parts = rebuilder.rebuildWithTrustedData();
            if (!parts.isEmpty() && o.backupDir != null && !o.backupDir.isEmpty()) {
                Files.createDirectories(Paths.get(o.backupDir));
            }
            for (var part : parts) {
                Logger.info("Rebuilding partition " + part.partitionName());
                var oldPath = Paths.get(o.sourcePattern.replace("{}", part.partitionName()));
                if (inPlace) {
                    if (o.backupDir != null) {
                        var backupPath = Paths.get(o.backupDir, part.partitionName() + ".img");
                        Logger.info("Creating backup at " + backupPath);
                        Files.copy(oldPath, backupPath);
                    }
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
        } else {
            System.out.println("Verification succeeded with no issues.");
        }
        return rebuilt;
    }

    public static boolean isBlockDeviceReadOnly(String path) throws IOException {
        var result = captureCommand("blockdev", "--getro", path);
        if (result == null) {
            throw new IOException("blockdev --getro failed");
        }
        result = result.trim();
        if (result.equals("0")) {
            return false;
        }
        if (result.equals("1")) {
            return true;
        }
        throw new IOException("blockdev --getro failed: " + result);
    }

    public static void setBlockDeviceReadOnly(String path, boolean readOnly) throws IOException {
        var status = runCommand("blockdev", readOnly ? "--setro" : "--setrw", path);
        if (status != 0) {
            throw new IOException("blockdev " + (readOnly ? "--setro" : "--setrw") + " failed");
        }
    }

    public static String captureCommand(String... args) {
        try {
            var process = Runtime.getRuntime().exec(args);
            var is = process.getInputStream();
            var ms = new ByteArrayOutputStream(8192);
            var buf = new byte[4096];
            int read;
            while ((read = is.read(buf)) != -1) {
                ms.write(buf, 0, read);
            }
            is.close();
            while (true) {
                try {
                    process.waitFor();
                    break;
                } catch (InterruptedException e) {
                    // retry
                }
            }
            return ms.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static int runCommand(String... args) {
        try {
            var process = Runtime.getRuntime().exec(args);
            while (true) {
                try {
                    return process.waitFor();
                } catch (InterruptedException e) {
                    // retry
                }
            }
        } catch (IOException e) {
            return -1;
        }
    }

    /**
     * Copy one partition image to another path (used for bootloader image
     * replacement and backups in the GUI).
     */
    public static void copyFile(Path from, Path to) throws IOException {
        try (var in = FileChannel.open(from, StandardOpenOption.READ);
             var out = FileChannel.open(to, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE)) {
            var buffer = java.nio.ByteBuffer.allocateDirect(4 * 1024 * 1024);
            while (in.position() < in.size()) {
                buffer.clear();
                IOUtils.readFully(in, buffer);
                buffer.flip();
                IOUtils.writeFully(out, buffer);
            }
        }
    }
}
