package xyz.cirno.avbsign;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

import xyz.cirno.avb.AvbAlgorithmType;
import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.ChainPartitionDescriptor;
import xyz.cirno.avb.HashDescriptor;
import xyz.cirno.avb.PropertyDescriptor;
import xyz.cirno.avb.VerifiedBootFooter;
import xyz.cirno.avb.VerifiedBootHeader;
import xyz.cirno.avb.VerifiedBootMetaImage;
import xyz.cirno.avb.util.Logger;

import static org.junit.Assert.*;

public class BackupGraphTest {
    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void followsChainedDescriptorsAndFindsSystemFingerprint() throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        var key = AvbKeyPair.fromPrivateKeyPem(Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem"));
        var chain = new ChainPartitionDescriptor(1, "vbmeta_system", key.publicKey(), 0);
        write(root.resolve("vbmeta.img"), List.of(chain));
        var hash = new HashDescriptor(1, "sha256", "boot", new byte[0], new byte[32], 0);
        var unrelated = new HashDescriptor(1, "sha256", "shared", new byte[0], new byte[32], 1);
        write(root.resolve("vbmeta_system.img"), List.of(hash, unrelated,
                new PropertyDescriptor("com.android.build.system.fingerprint", "build/test")));
        var graph = BackupGraph.read(root.resolve("{}.img").toString());
        assertEquals(List.of("vbmeta", "vbmeta_system"), graph.dependencies(List.of("boot")));
        assertEquals(List.of("vbmeta"), graph.dependencies(List.of("vbmeta_system")));
        assertEquals(List.of(), graph.dependencies(List.of("other")));
        assertEquals("build/test", graph.fingerprint());
        assertEquals("build/test", graph.fingerprint(Map.of("com.android.build.system.fingerprint", "other")));
        assertEquals("build/test", graph.fingerprint(Map.of("com.android.build.system.fingerprint", "")));
        assertEquals("build/test", graph.fingerprint(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> graph.dependencies(List.of("shared")));
    }

    @Test
    public void fallsBackToBootFingerprint() throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        write(root.resolve("vbmeta.img"),
                List.of(new PropertyDescriptor("com.android.build.boot.fingerprint", "boot/build")));
        assertEquals("boot/build", BackupGraph.read(root.resolve("{}.img").toString()).fingerprint());
    }

    @Test
    public void scansNonAbReferencesInImageTemplatesWithoutSlotSuffix() throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        write(root.resolve("vbmeta.img"), List.of(
                new HashDescriptor(1, "sha256", "shared", new byte[0], new byte[32], 1)));
        writeEmbedded(root.resolve("shared.img"),
                List.of(new PropertyDescriptor("com.example.fingerprint", "shared")));
        var pattern = root.resolve("{}.img").toString();
        var graph = BackupGraph.read(pattern);
        graph.scanEmbeddedFingerprints(pattern, List.of("vbmeta"), "");
        assertEquals(Map.of("com.example.fingerprint", "shared"), graph.fingerprintProperties());
        assertEquals("shared", graph.fingerprint(Map.of("com.example.fingerprint", "shared")));
        assertEquals("", graph.fingerprint(Map.of("com.example.fingerprint", "different")));
        assertEquals("", graph.fingerprint(Map.of("other.fingerprint", "shared")));
    }

    @Test
    public void collectsAllFingerprintDescriptorsFromChainAndAccessibleEmbeddedImages() throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        var key = AvbKeyPair.fromPrivateKeyPem(Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem"));
        write(root.resolve("vbmeta_b"), List.of(
                new PropertyDescriptor("com.android.build.system.fingerprint", "root"),
                new ChainPartitionDescriptor(1, "vbmeta_system", key.publicKey(), 0),
                new HashDescriptor(1, "sha256", "boot", new byte[0], new byte[32], 0),
                new HashDescriptor(1, "sha256", "shared", new byte[0], new byte[32], 1),
                new HashDescriptor(1, "sha256", "missing", new byte[0], new byte[32], 0)));
        write(root.resolve("vbmeta_system_b"), List.of(
                new PropertyDescriptor("com.android.build.system.fingerprint", "chain"),
                new PropertyDescriptor("com.android.build.system.fingerprint", "root"),
                new PropertyDescriptor("other.property", "ignored")));
        writeEmbedded(root.resolve("boot_b"), List.of(
                new PropertyDescriptor("com.android.build.boot.fingerprint", "boot"),
                new PropertyDescriptor("com.android.build.boot.fingerprint", "boot-again"),
                new HashDescriptor(1, "sha256", "nested", new byte[0], new byte[32], 0),
                new HashDescriptor(1, "sha256", "boot", new byte[0], new byte[32], 0)));
        writeEmbedded(root.resolve("boot_a"),
                List.of(new PropertyDescriptor("com.android.build.boot.fingerprint", "wrong-slot")));
        writeEmbedded(root.resolve("shared"),
                List.of(new PropertyDescriptor("com.example.custom.fingerprint", "shared")));
        writeEmbedded(root.resolve("extra_b"),
                List.of(new PropertyDescriptor("fingerprint", "extra")));
        writeEmbedded(root.resolve("nested_b"),
                List.of(new PropertyDescriptor("com.example.nested.fingerprint", "nested")));

        var warnings = new ArrayList<String>();
        Logger.setListener((level, message) -> {
            if (level == Logger.WARN) warnings.add(message);
        });
        try {
            var graph = BackupGraph.read(root.resolve("{}_b").toString());
            graph.scanEmbeddedFingerprints(root.resolve("{}_b").toString(), List.of("boot", "extra"), "_b");
            graph.scanEmbeddedFingerprints(root.resolve("{}_b").toString(), List.of("boot", "extra"), "_b");
            assertEquals(Map.of(
                    "com.android.build.system.fingerprint", "root",
                    "com.android.build.boot.fingerprint", "boot",
                    "com.example.custom.fingerprint", "shared",
                    "fingerprint", "extra",
                    "com.example.nested.fingerprint", "nested"), graph.fingerprintProperties());
            assertEquals("root", graph.fingerprint());
            assertEquals("boot", graph.fingerprint(Map.of("com.android.build.boot.fingerprint", "boot")));
            assertEquals("chain", graph.fingerprint(Map.of("com.android.build.system.fingerprint", "chain")));
            assertEquals("boot-again", graph.fingerprint(Map.of("com.android.build.boot.fingerprint", "boot-again")));
            assertEquals("nested", graph.fingerprint(Map.of("com.example.nested.fingerprint", "nested")));
            assertEquals("root", graph.fingerprint(Map.of("com.android.build.boot.fingerprint", "wrong-slot")));
            assertEquals("root", graph.fingerprint(Map.of("com.android.build.boot.fingerprint", "different")));
            assertEquals("root", graph.fingerprint(Map.of("com.android.build.boot.fingerprint", "")));
            assertEquals("root", graph.fingerprint(Map.of()));
            assertEquals("root", graph.fingerprint(Map.of("com.example.custom.fingerprint", "boot")));
            assertTrue(warnings.stream().anyMatch(s -> s.contains("com.android.build.system.fingerprint")
                    && s.contains("chain") && s.contains("root")));
            assertTrue(warnings.stream().anyMatch(s -> s.contains("com.android.build.boot.fingerprint")
                    && s.contains("boot-again") && s.contains("boot")));
            assertEquals(1, warnings.stream().filter(s -> s.contains("com.android.build.system.fingerprint")).count());
        } finally {
            Logger.setListener(null);
        }
    }

    @Test
    public void readsCurrentRootFingerprintsWithoutFollowingChains() throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        var key = AvbKeyPair.fromPrivateKeyPem(Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem"));
        var vbmeta = root.resolve("vbmeta_a");
        write(vbmeta, List.of(
                new PropertyDescriptor("com.android.build.boot.fingerprint", "current-boot"),
                new PropertyDescriptor("com.android.build.system.fingerprint", "current-system"),
                new PropertyDescriptor("unrelated", "value"),
                new ChainPartitionDescriptor(1, "unavailable_chain", key.publicKey(), 0)));
        assertEquals(Map.of("com.android.build.boot.fingerprint", "current-boot",
                        "com.android.build.system.fingerprint", "current-system"),
                BackupGraph.readRootFingerprintProperties(vbmeta));
        assertThrows(java.io.IOException.class,
                () -> BackupGraph.readRootFingerprintProperties(root.resolve("missing")));
    }

    private static void writeEmbedded(Path path, List<xyz.cirno.avb.AvbDescriptor> descriptors) throws Exception {
        var image = new VerifiedBootMetaImage();
        image.header = new VerifiedBootHeader();
        image.descriptors = descriptors;
        var data = image.toUnsignedByteArray();
        var footer = new VerifiedBootFooter();
        footer.originalImageSize = 4;
        footer.vbmetaOffset = 4;
        footer.vbmetaSize = data.length;
        try (var out = Files.newOutputStream(path)) {
            out.write(new byte[4]);
            out.write(data);
            out.write(footer.toByteArray());
        }
    }

    private static void write(Path path, List<xyz.cirno.avb.AvbDescriptor> descriptors) throws Exception {
        var image = new VerifiedBootMetaImage();
        image.header = new VerifiedBootHeader();
        image.header.algorithmType = AvbAlgorithmType.NONE;
        image.descriptors = descriptors;
        Files.write(path, image.toUnsignedByteArray());
    }
}
