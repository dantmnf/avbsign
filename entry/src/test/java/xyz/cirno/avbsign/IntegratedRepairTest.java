package xyz.cirno.avbsign;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import xyz.cirno.avb.AvbAlgorithmType;
import xyz.cirno.avb.AvbDescriptor;
import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.ChainPartitionDescriptor;
import xyz.cirno.avb.HashDescriptor;
import xyz.cirno.avb.HashTreeDescriptor;
import xyz.cirno.avb.ParsedVerifiedBootMetaImage;
import xyz.cirno.avb.VerifiedBootHeader;
import xyz.cirno.avb.VerifiedBootMetaImage;
import xyz.cirno.avb.rebuild.AvbRebuilder;

import static org.junit.Assert.*;

public class IntegratedRepairTest {
    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void validImagesDoNotConsultReplacementSettings() throws Exception {
        var fixture = fixture(true, true);
        var calls = new AtomicInteger();
        fixture.options.rootKeyPath = fixture.root.resolve("missing-key.pem").toString();
        fixture.options.bootloaderSources = () -> {
            calls.incrementAndGet();
            throw new IOException("unexpected");
        };
        assertTrue(AvbTool.fix(fixture.options).isEmpty());
        assertEquals(0, calls.get());
        assertArrayEquals(fixture.originalVbmeta, Files.readAllBytes(fixture.vbmeta));
        assertArrayEquals(fixture.originalAbl, Files.readAllBytes(fixture.abl));
    }

    @Test
    public void matchingRootKeyRepairsWithoutReplacingBootloader() throws Exception {
        var fixture = fixture(true, false);
        var calls = new AtomicInteger();
        fixture.options.rootKeyPath = fixture.root.resolve("missing-key.pem").toString();
        fixture.options.bootloaderSources = () -> {
            calls.incrementAndGet();
            throw new IOException("unexpected");
        };
        assertEquals(List.of("vbmeta"), AvbTool.fix(fixture.options));
        assertEquals(0, calls.get());
        assertArrayEquals(fixture.originalAbl, Files.readAllBytes(fixture.abl));
        assertFalse(AvbTool.check(fixture.options.sourcePattern).hasIssues());
    }

    @Test
    public void missingRootKeyBacksUpBeforeReplacingAndRechecksReplacementImages() throws Exception {
        var fixture = fixture(false, false);
        var replacementBoot = fixture.root.resolve("new-boot.img");
        var replacementAbl = fixture.root.resolve("new-abl.img");
        Files.write(replacementBoot, new byte[]{8, 7, 6, 5});
        Files.write(replacementAbl, new byte[]{4, 3, 2, 1});
        var backupCalls = new AtomicInteger();
        fixture.options.rootKeyPath = fixture.replacementKey.toString();
        fixture.options.bootloaderSources = () -> Map.of("boot", replacementBoot, "abl", replacementAbl);
        fixture.options.backupAction = (names, pattern) -> {
            backupCalls.incrementAndGet();
            assertEquals(java.util.Set.of("vbmeta", "boot", "abl"), java.util.Set.copyOf(names));
            assertEquals(fixture.options.sourcePattern, pattern);
            assertArrayEquals(fixture.originalVbmeta, Files.readAllBytes(fixture.vbmeta));
            assertArrayEquals(fixture.originalBoot, Files.readAllBytes(fixture.boot));
            assertArrayEquals(fixture.originalAbl, Files.readAllBytes(fixture.abl));
        };

        assertEquals(List.of("vbmeta"), AvbTool.fix(fixture.options));
        assertEquals(1, backupCalls.get());
        assertArrayEquals(Files.readAllBytes(replacementBoot), Files.readAllBytes(fixture.boot));
        assertArrayEquals(Files.readAllBytes(replacementAbl), Files.readAllBytes(fixture.abl));
        assertFalse(AvbTool.check(fixture.options.sourcePattern).hasIssues());
        try (var channel = java.nio.channels.FileChannel.open(fixture.vbmeta)) {
            assertEquals(AvbKeyPair.fromPrivateKeyPem(fixture.replacementKey).publicKey(),
                    ParsedVerifiedBootMetaImage.parseFromPartition(channel).publicKey);
        }
    }

    @Test
    public void missingKeyOrFailedBackupLeavesAllTargetsUnchanged() throws Exception {
        var fixture = fixture(false, false);
        var replacement = fixture.root.resolve("new-abl.img");
        Files.write(replacement, new byte[]{1, 1, 1, 1});
        var prepares = new AtomicInteger();
        fixture.options.bootloaderSources = () -> {
            prepares.incrementAndGet();
            return Map.of("abl", replacement);
        };
        assertThrows(IOException.class, () -> AvbTool.fix(fixture.options));
        assertEquals(0, prepares.get());
        assertUnchanged(fixture);

        fixture.options.rootKeyPath = fixture.replacementKey.toString();
        fixture.options.backupAction = (names, pattern) -> { throw new IOException("backup failed"); };
        assertThrows(IOException.class, () -> AvbTool.fix(fixture.options));
        assertEquals(1, prepares.get());
        assertUnchanged(fixture);
    }

    @Test
    public void rejectsReplacementThatChangesAvbPartitionSizeOrIsEmpty() throws Exception {
        var fixture = fixture(false, false);
        fixture.options.rootKeyPath = fixture.replacementKey.toString();

        var shortBoot = fixture.root.resolve("short-boot.img");
        Files.write(shortBoot, new byte[]{1, 2, 3});
        fixture.options.bootloaderSources = () -> Map.of("boot", shortBoot);
        assertThrows(IOException.class, () -> AvbTool.fix(fixture.options));
        assertUnchanged(fixture);

        var empty = fixture.root.resolve("empty-abl.img");
        Files.write(empty, new byte[0]);
        fixture.options.bootloaderSources = () -> Map.of("abl", empty);
        assertThrows(IOException.class, () -> AvbTool.fix(fixture.options));
        assertUnchanged(fixture);
    }

    @Test
    public void rejectsIncompatibleRootKeyAndHashTreeReplacementBeforeWriting() throws Exception {
        var fixture = fixture(false, false);
        var replacement = fixture.root.resolve("new-abl.img");
        Files.write(replacement, new byte[]{1, 1, 1, 1});
        fixture.options.rootKeyPath = Path.of(System.getProperty("test.keysDir"), "testkey_rsa4096.pem").toString();
        fixture.options.bootloaderSources = () -> Map.of("abl", replacement);
        assertThrows(IOException.class, () -> AvbTool.fix(fixture.options));
        assertUnchanged(fixture);

        var tree = new HashTreeDescriptor();
        tree.partitionName = "abl";
        var rootKey = AvbKeyPair.fromPrivateKeyPem(
                Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem"));
        writeImage(fixture.vbmeta, rootKey, List.of(hash("boot", new byte[]{0, 0, 0, 0}), tree));
        var vbmetaBefore = Files.readAllBytes(fixture.vbmeta);
        fixture.options.rootKeyPath = fixture.replacementKey.toString();
        assertThrows(IOException.class, () -> AvbTool.fix(fixture.options));
        assertArrayEquals(vbmetaBefore, Files.readAllBytes(fixture.vbmeta));
        assertArrayEquals(fixture.originalBoot, Files.readAllBytes(fixture.boot));
        assertArrayEquals(fixture.originalAbl, Files.readAllBytes(fixture.abl));
    }

    @Test
    public void legacyRootKeyOverrideStillWorksWithoutIntegratedReplacement() throws Exception {
        var fixture = fixture(true, false);
        fixture.options.rootKeyPath = fixture.replacementKey.toString();
        assertEquals(List.of("vbmeta"), AvbTool.fix(fixture.options));
        try (var channel = java.nio.channels.FileChannel.open(fixture.vbmeta)) {
            assertEquals(AvbKeyPair.fromPrivateKeyPem(fixture.replacementKey).publicKey(),
                    ParsedVerifiedBootMetaImage.parseFromPartition(channel).publicKey);
        }
        assertFalse(AvbTool.check(fixture.options.sourcePattern).hasIssues());
    }

    @Test
    public void rebuildPlanningDoesNotMutateVerificationResult() throws Exception {
        var fixture = fixture(true, false);
        var result = AvbTool.check(fixture.options.sourcePattern);
        var descriptor = (HashDescriptor) result.partitionRecords.get("vbmeta").vbmetaImage().descriptors.get(0);
        var originalDigest = descriptor.digest.clone();
        var rebuilder = new AvbRebuilder(result);
        rebuilder.addKeyPair(AvbKeyPair.fromPrivateKeyPem(
                Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem")));
        rebuilder.rebuildWithTrustedData();
        assertArrayEquals(originalDigest, descriptor.digest);
        assertUnchanged(fixture);
    }

    @Test
    public void disabledReplacementDoesNotWriteWhenRootKeyIsMissing() throws Exception {
        var fixture = fixture(false, false);
        assertThrows(AvbRebuilder.MissingRootKeyException.class, () -> AvbTool.fix(fixture.options));
        assertUnchanged(fixture);
    }

    @Test
    public void missingChainedKeyDoesNotReplaceBootloaderWhenRootKeyIsAvailable() throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        var keyDir = Files.createDirectory(root.resolve("keys"));
        var rootKeyPath = Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem");
        Files.copy(rootKeyPath, keyDir.resolve("root.pem"));
        var rootKey = AvbKeyPair.fromPrivateKeyPem(rootKeyPath);
        var childPath = writeGeneratedKey(root.resolve("child-key.pem"));
        var childKey = AvbKeyPair.fromPrivateKeyPem(childPath);
        Files.write(root.resolve("boot.img"), new byte[]{1, 2, 3, 4});
        writeImage(root.resolve("vbmeta_system.img"), childKey, List.of(hash("boot", new byte[]{0, 0, 0, 0})));
        writeImage(root.resolve("vbmeta.img"), rootKey,
                List.of(new ChainPartitionDescriptor(1, "vbmeta_system", childKey.publicKey(), 0)));
        var options = new AvbTool.FixOptions();
        options.sourcePattern = root.resolve("{}.img").toString();
        options.keysDir = keyDir.toString();
        var calls = new AtomicInteger();
        options.bootloaderSources = () -> {
            calls.incrementAndGet();
            throw new IOException("unexpected");
        };
        var rebuilt = AvbTool.fix(options);
        assertEquals(java.util.Set.of("vbmeta", "vbmeta_system"), java.util.Set.copyOf(rebuilt));
        assertEquals(0, calls.get());
        assertFalse(AvbTool.check(options.sourcePattern).hasIssues());
    }

    @Test
    public void missingRootKeyDoesNotReplaceBootloaderWhenOnlyChildNeedsResigning() throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        var keyDir = Files.createDirectory(root.resolve("keys"));
        var rootKey = AvbKeyPair.fromPrivateKeyPem(
                Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem"));
        var childKey = AvbKeyPair.fromPrivateKeyPem(writeGeneratedKey(keyDir.resolve("child.pem")));
        Files.write(root.resolve("boot.img"), new byte[]{1, 2, 3, 4});
        writeImage(root.resolve("vbmeta_system.img"), childKey, List.of(hash("boot", new byte[]{0, 0, 0, 0})));
        var vbmeta = root.resolve("vbmeta.img");
        writeImage(vbmeta, rootKey, List.of(new ChainPartitionDescriptor(1, "vbmeta_system", childKey.publicKey(), 0)));
        var originalVbmeta = Files.readAllBytes(vbmeta);
        var options = new AvbTool.FixOptions();
        options.sourcePattern = root.resolve("{}.img").toString();
        options.keysDir = keyDir.toString();
        options.bootloaderSources = () -> { throw new IOException("unexpected"); };
        assertEquals(List.of("vbmeta_system"), AvbTool.fix(options));
        assertArrayEquals(originalVbmeta, Files.readAllBytes(vbmeta));
        assertFalse(AvbTool.check(options.sourcePattern).hasIssues());
    }

    private Fixture fixture(boolean includeRootKey, boolean valid) throws Exception {
        var root = temporaryFolder.getRoot().toPath();
        var keyDir = Files.createDirectory(root.resolve("keys"));
        var originalKeyPath = Path.of(System.getProperty("test.keysDir"), "testkey_rsa2048.pem");
        var originalKey = AvbKeyPair.fromPrivateKeyPem(originalKeyPath);
        var replacementKey = writeGeneratedKey(keyDir.resolve("replacement.pem"));
        if (includeRootKey) Files.copy(originalKeyPath, keyDir.resolve("original.pem"));
        var boot = root.resolve("boot.img");
        var abl = root.resolve("abl.img");
        var vbmeta = root.resolve("vbmeta.img");
        var bootBytes = new byte[]{1, 2, 3, 4};
        var ablBytes = new byte[]{4, 4, 4, 4};
        Files.write(boot, bootBytes);
        Files.write(abl, ablBytes);
        writeImage(vbmeta, originalKey,
                List.of(hash("boot", valid ? bootBytes : new byte[]{0, 0, 0, 0})));
        var options = new AvbTool.FixOptions();
        options.sourcePattern = root.resolve("{}.img").toString();
        options.keysDir = keyDir.toString();
        return new Fixture(root, boot, abl, vbmeta, replacementKey, bootBytes, ablBytes,
                Files.readAllBytes(vbmeta), options);
    }

    private static HashDescriptor hash(String partition, byte[] bytes) throws Exception {
        return new HashDescriptor(bytes.length, "sha256", partition, new byte[0],
                MessageDigest.getInstance("SHA-256").digest(bytes), 0);
    }

    private static void writeImage(Path path, AvbKeyPair key, List<AvbDescriptor> descriptors) throws Exception {
        var image = new VerifiedBootMetaImage();
        image.header = new VerifiedBootHeader();
        image.header.algorithmType = AvbAlgorithmType.SHA256_RSA2048;
        image.descriptors = new ArrayList<>(descriptors);
        Files.write(path, image.toSignedByteArray(key));
    }

    private static Path writeGeneratedKey(Path path) throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var encoded = Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        Files.writeString(path, "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----\n");
        return path;
    }

    private static void assertUnchanged(Fixture fixture) throws Exception {
        assertArrayEquals(fixture.originalVbmeta, Files.readAllBytes(fixture.vbmeta));
        assertArrayEquals(fixture.originalBoot, Files.readAllBytes(fixture.boot));
        assertArrayEquals(fixture.originalAbl, Files.readAllBytes(fixture.abl));
    }

    private record Fixture(Path root, Path boot, Path abl, Path vbmeta, Path replacementKey,
                           byte[] originalBoot, byte[] originalAbl, byte[] originalVbmeta,
                           AvbTool.FixOptions options) {
    }
}
