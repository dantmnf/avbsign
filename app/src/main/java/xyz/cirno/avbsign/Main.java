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
            System.out.println("Usage:");
            System.out.println("  app_process -cp avbsign.apk / xyz.cirno.avbsign.Main check <partition_pattern>");
            System.out.println("  app_process -cp avbsign.apk / xyz.cirno.avbsign.Main fix <partition_pattern> <keys_dir>");
            System.out.println("    partition_pattern: pattern for partition images, use {} as placeholder for partition name");
            System.out.println("                       e.g. `/dev/block/by-name/{}_a`, `{}.img`");
            System.out.println("    keys_dir:          directory containing private keys in PEM format");
            System.exit(1);
        }
        var command = args[0];
        var pattern = args[1];
        if ("check".equals(command)) {
            check(pattern);
        } else if ("fix".equals(command)) {
            var keysdir = args[2];
            fix(pattern, keysdir);
        }
    }

    private static void fix(String pattern, String keysdir) {
        try {
            var keyPairs = new ArrayList<AvbKeyPair>();
            try (var iter = Files.list(Paths.get(keysdir))) {
                iter.forEach(f -> {
                    var keypair = AvbKeyPair.fromPrivateKeyPem(f);
                    if (keypair != null) {
                        Logger.info("Loaded key with public key hash " + IOUtils.sha256ToHex(keypair.publicKey.toByteArray()));
                        keyPairs.add(keypair);
                    }
                });
            }
            if (keyPairs.isEmpty()) {
                Logger.error("No keys loaded from " + keysdir);
                System.exit(1);
            }
            var verifier = newAvbVerifier(pattern);
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
                var parts = rebuilder.rebuildWithTrustedData();
                for (var part : parts) {
                    Logger.info("Rebuilding partition " + part.partitionName());
                    try (var f = FileChannel.open(Paths.get(pattern.replace("{}", part.partitionName())), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                        part.rebuildInplace(f);
                    } catch (Exception e) {
                        Logger.error("Failed to write rebuilt partition " + part.partitionName(), e);
                        e.printStackTrace();
                    }
                }

            } else {
                System.out.println("Verification succeeded with no issues.");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
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
