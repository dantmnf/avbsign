package xyz.cirno.avbsign;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Objects;

import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.PartitionProvider;
import xyz.cirno.avb.rebuild.AvbRebuilder;
import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.util.Logger;
import xyz.cirno.avb.verify.AvbVerifier;

public class Main {

    private static int runCommand(String... args) {
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

    private static String captureCommand(String... args) {
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

    public static byte[] hexStringToByteArray(String hexString) {
        Objects.requireNonNull(hexString);
        if (hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even number of characters.");
        }

        int len = hexString.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) Integer.parseInt(hexString.substring(i, i + 2), 16);
        }
        return data;
    }

    private static boolean isBlockDeviceReadOnly(String path) throws IOException {
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

    private static void setBlockDeviceReadOnly(String path, boolean readOnly) throws IOException {
        var status = runCommand("blockdev", readOnly ? "--setro" : "--setrw", path);
        if (status != 0) {
            throw new IOException("blockdev " + (readOnly ? "--setro" : "--setrw") + " failed");
        }
    }

    public static void main(String[] args) {
        try {
            main2(args);
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main2(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }
        var command = args[0];
        if ("check".equals(command)) {
            if (args.length != 2) {
                printUsage();
                System.exit(1);
            }
            check(args[1]);
        } else if ("fix".equals(command)) {
            var runner = new FixRunner();
            runner.inPlace = true;

            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                if (arg.startsWith("-")) {
                    if (i + 1 >= args.length) {
                        System.err.println("Missing value for " + arg);
                        System.exit(1);
                    }
                    switch (arg) {
                        case "--keys":
                            runner.keysDir = args[++i];
                            break;
                        case "--root-key":
                            runner.rootKeyPath = args[++i];
                            break;
                        case "--backup":
                            runner.backupDir = args[++i];
                            break;
                        case "--output":
                            runner.outputPattern = args[++i];
                            runner.inPlace = false;
                        default:
                            System.err.println("Unknown option: " + arg);
                            printUsage();
                            System.exit(1);
                    }
                } else {
                    if (runner.sourcePattern == null) {
                        runner.sourcePattern = arg;
                    } else {
                        System.err.println("Unexpected argument: " + arg);
                        printUsage();
                        System.exit(1);
                    }
                }
            }

            if (runner.sourcePattern == null || runner.keysDir == null) {
                printUsage();
                System.exit(1);
            }
            runner.run();
        } else {
            System.err.println("Unknown command: " + command);
            printUsage();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  app_process -cp avbsign.apk / xyz.cirno.avbsign.Main check <PATTERN>");
        System.out.println("  app_process -cp avbsign.apk / xyz.cirno.avbsign.Main fix --keys KEYS_DIR [--root-key ROOT_KEY] [--backup BACKUP_DIR] <PATTERN>");
        System.out.println("    PATTERN:              pattern for partition images, use {} as placeholder for partition name");
        System.out.println("                          e.g. `/dev/block/by-name/{}_a`, `{}.img`");
        System.out.println("    --keys KEYS_DIR       directory containing private keys in PEM format");
        System.out.println("    --root-key ROOT_KEY   replace root key with specified key");
        System.out.println("    --output OUT_PATTERN  write modified image to OUT_PATTERN, in-place fix if not specified");
        System.out.println("    --backup BACKUP_DIR   during in-place fix, save backup of modified image in BACKUP_DIR");
    }

    private static class FixRunner {
        public String sourcePattern;
        public String outputPattern;
        public String keysDir;
        public String backupDir;
        public String rootKeyPath;
        public boolean inPlace;

        private void run() {
            if (sourcePattern == null || !sourcePattern.contains("{}")) throw new IllegalArgumentException("source pattern: " + sourcePattern);
            if (keysDir == null || keysDir.isEmpty()) throw new IllegalArgumentException("keys dir: " + keysDir);
            if (!inPlace && (outputPattern == null || !outputPattern.contains("{}"))) throw new IllegalArgumentException();
            try {
                var keyPairs = new ArrayList<AvbKeyPair>();
                try (var iter = Files.list(Paths.get(keysDir))) {
                    iter.forEach(f -> {
                        var keypair = AvbKeyPair.fromPrivateKeyPem(f);
                        if (keypair != null) {
                            Logger.info("Loaded key with public key hash " + IOUtils.sha256ToHex(keypair.publicKey.toByteArray()));
                            keyPairs.add(keypair);
                        }
                    });
                }
                if (keyPairs.isEmpty()) {
                    Logger.error("No keys loaded from " + keysDir);
                    System.exit(1);
                }
                var verifier = newAvbVerifier(sourcePattern);
                var result = verifier.recursiveVerify("vbmeta");
                if (result.hasIssues()) {
                    System.out.println("Verification failed with issues:");
                    for (var issue : result.issues) {
                        System.out.println("Issue: " + issue);
                    }
                    var rebuilder = new AvbRebuilder(result);
                    for (var keypair : keyPairs) {
                        rebuilder.addKeyPair(keypair);
                    }
                    if (rootKeyPath != null && !rootKeyPath.isEmpty()) {
                        var keypair = AvbKeyPair.fromPrivateKeyPem(Paths.get(rootKeyPath));
                        if (keypair != null) {
                            Logger.info("Overriding root key with " + keypair.publicKey);
                            rebuilder.setRootKey(keypair);
                        }
                    }
                    var parts = rebuilder.rebuildWithTrustedData();
                    if (!parts.isEmpty() && backupDir != null && !backupDir.isEmpty()) {
                        Files.createDirectories(Paths.get(backupDir));
                    }
                    for (var part : parts) {
                        Logger.info("Rebuilding partition " + part.partitionName());
                        var old_path = Paths.get(sourcePattern.replace("{}", part.partitionName()));
                        if (inPlace) {
                            if (backupDir != null) {
                                var backup_path = Paths.get(backupDir, part.partitionName() + ".img");
                                Logger.info("Creating backup at " + backup_path);
                                Files.copy(old_path, backup_path);
                            }
                            if (isBlockDeviceReadOnly(old_path.toString())) {
                                Logger.info("Setting " + old_path + " read-write");
                                setBlockDeviceReadOnly(old_path.toString(), false);
                            }
                            try (var f = FileChannel.open(old_path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                                part.rebuildInplace(f);
                            } catch (Exception e) {
                                Logger.error("Failed to rebuild partition " + part.partitionName(), e);
                                e.printStackTrace();
                            }
                        } else {
                            var outfile = outputPattern.replace("{}", part.partitionName());
                            try (var instream = FileChannel.open(old_path, StandardOpenOption.READ);
                                 var outstream = FileChannel.open(Paths.get(outfile), StandardOpenOption.WRITE)) {
                                part.rebuildCopy(instream, outstream);
                            } catch (Exception e) {
                                Logger.error("Failed to rebuild partition " + part.partitionName(), e);
                                e.printStackTrace();
                            }
                        }
                    }

                } else {
                    System.out.println("Verification succeeded with no issues.");
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static void check(String pattern) {
        var verifier = newAvbVerifier(pattern);
        try {
            var result = verifier.recursiveVerify("vbmeta");
            if (result.hasIssues()) {
                System.out.println("Verification failed with issues:");
                for (var issue : result.issues) {
                    System.out.println("Issue: " + issue);
                }
            } else {
                System.out.println("Verification succeeded with no issues.");
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static AvbVerifier newAvbVerifier(String pattern) {
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
        var verifier = new AvbVerifier(prov);
        return verifier;
    }
}
