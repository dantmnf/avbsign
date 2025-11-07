package xyz.cirno.avbsign;

import android.system.Os;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Objects;

import xyz.cirno.avbsign.avb.AvbPublicKey;
import xyz.cirno.avbsign.avb.VerifiedBootFooter;

public class Main {

    private static String bootSlotSuffix;
    private static String avbroot;
    private static File tempDir;

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
        var bootSlot = captureCommand("bootctl", "get-active-boot-slot");
        if (bootSlot == null) {
            throw new RuntimeException("Failed to get active boot slot");
        }
        bootSlot = bootSlot.trim();
        bootSlotSuffix = captureCommand("bootctl", "get-suffix", bootSlot);
        if (bootSlotSuffix == null) {
            throw new RuntimeException("Failed to get boot slot suffix");
        }
        bootSlotSuffix = bootSlotSuffix.trim();

        System.out.printf("Active boot slot: %s (suffix: %s)\n", bootSlot, bootSlotSuffix);

        tempDir = new File("/data/local/tmp/avbsign-" + Os.getpid());
        if (!tempDir.mkdirs()) {
            throw new RuntimeException("Failed to create temporary directory " + tempDir.getAbsolutePath());
        }

        var moduleDir = args[0];
        avbroot = moduleDir + "/tools/avbroot";

        System.out.println(" - Inspecting vbmeta...");

        var vbmetaToml = tempDir.getAbsolutePath() + "/avb.toml";
        if (runCommand(avbroot, "avb", "unpack", "--quiet", "--input",
                "/dev/block/by-name/vbmeta" + bootSlotSuffix, "--output", vbmetaToml) != 0) {
            throw new RuntimeException("Failed to unpack vbmeta");
        }

        JsonNode root;
        try (var is = new FileInputStream(vbmetaToml)) {
            root = new TomlMapper().readTree(is);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read vbmeta TOML: " + e.getMessage());
        }

        var avbPublicKeyString = Objects.requireNonNull(root.at("/header/public_key").textValue());
        var avbPublicKey = AvbPublicKey.readFrom(ByteBuffer.wrap(hexStringToByteArray(avbPublicKeyString)));


        // TODO: check if we have the corresponding private key

        var descriptors = root.at("/header/descriptors");
        if (descriptors == null || !descriptors.isArray() || descriptors.isEmpty()) {
            throw new RuntimeException("No descriptors found in vbmeta");
        }

        for (int i = 0; i < descriptors.size(); i++) {
            var descriptor = descriptors.get(i);
            if (!(descriptor instanceof ObjectNode obj)) {
                throw new RuntimeException("Malformed avb.toml");
            }
            var type = Objects.requireNonNull(obj.get("type").textValue());
            switch (type) {
                case "Property":
                    System.out.printf(" - Property: %s=%s", descriptor.get("key").textValue(),
                            descriptor.get("value").textValue());
                    break;
                case "Hash":
                    processHashDescriptor(obj);
                    break;
                case "ChainPartition":
                    processChainPartitionDescriptor(obj);
                    break;
                case "HashTree":
                    System.out.printf(" - HashTree: partition_name=%s (SKIPPED)\n",
                            descriptor.get("partition_name").textValue());
            }
        }

    }

    private static void processHashDescriptor(ObjectNode descriptor) {
        var partition = Objects.requireNonNull(descriptor.get("partition_name").textValue());
        System.out.printf(" - Hash: partition_name=%s\n", partition);
        var partitionPath = "/dev/block/by-name/" + partition + bootSlotSuffix;
        try (var f = new RandomAccessFile(partitionPath, "r")) {
            var imageSize = descriptor.get("image_size").asLong();
            var footer = VerifiedBootFooter.readFrom(f.getChannel());
            if (footer == null) {
                throw new RuntimeException("no avb footer");
            }
            if (footer.originalImageSize != imageSize) {
                System.out.printf("   + update image size in vbmeta: %d -> %d\n", imageSize, footer.originalImageSize);
                descriptor.put("image_size", footer.originalImageSize);
            }

            System.out.print("   + verifying image\n");

            if (runCommand(avbroot, "avb", "verify", "--input", partitionPath) != 0) {
                System.out.print("   + repacking image\n");
                var newimg = new File(tempDir, partition + bootSlotSuffix + ".img");
                var repackStatus = runCommand(avbroot, "avb", "repack", "--quiet",
                        "--input", partitionPath,
                        "--output", newimg.getCanonicalPath());
                if (repackStatus != 0) {
                    throw new RuntimeException("avbroot avb repack failed");
                }
                // flashPartition(partitionPath, newimg.getCanonicalPath());
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void processChainPartitionDescriptor(ObjectNode descriptor) {
    }


}
