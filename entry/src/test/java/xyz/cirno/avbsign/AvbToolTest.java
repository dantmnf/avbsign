package xyz.cirno.avbsign;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Random;

import xyz.cirno.avb.AvbAlgorithmType;
import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.VerifiedBootHeader;
import xyz.cirno.avb.VerifiedBootMetaImage;

import static org.junit.Assert.*;

public class AvbToolTest {
    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void findsKeyMatchingVbmeta() throws Exception {
        var fixtureDir = Path.of(System.getProperty("test.keysDir"));
        var matching = fixtureDir.resolve("testkey_rsa2048.pem");
        var other = fixtureDir.resolve("testkey_rsa4096.pem");
        var image = new VerifiedBootMetaImage();
        image.header = new VerifiedBootHeader();
        image.header.algorithmType = AvbAlgorithmType.SHA256_RSA2048;
        image.descriptors = new ArrayList<>();
        var key = AvbKeyPair.fromPrivateKeyPem(matching);
        assertNotNull(key);
        var vbmeta = temporaryFolder.getRoot().toPath().resolve("vbmeta.img");
        Files.write(vbmeta, image.toSignedByteArray(key));
        var keys = temporaryFolder.newFolder("keys").toPath();
        Files.copy(other, keys.resolve("a-other.pem"));
        Files.writeString(keys.resolve("b-invalid.pem"), "not a private key");
        Files.copy(matching, keys.resolve("c-matching.pem"));

        assertEquals("c-matching.pem", AvbTool.findMatchingKey(vbmeta, keys));
        Files.delete(keys.resolve("c-matching.pem"));
        assertNull(AvbTool.findMatchingKey(vbmeta, keys));
        assertNull(AvbTool.findMatchingKey(vbmeta, keys.resolve("missing")));
    }

    @Test
    public void unsignedVbmetaReportsMissingPublicKey() throws Exception {
        var image = new VerifiedBootMetaImage();
        image.header = new VerifiedBootHeader();
        image.header.algorithmType = AvbAlgorithmType.NONE;
        image.descriptors = new ArrayList<>();
        var vbmeta = temporaryFolder.getRoot().toPath().resolve("unsigned.img");
        Files.write(vbmeta, image.toUnsignedByteArray());
        var keys = temporaryFolder.newFolder("keys").toPath();

        assertThrows(IOException.class, () -> AvbTool.findMatchingKey(vbmeta, keys));
    }

    @Test
    public void copiesFileTruncatingDestination() throws Exception {
        var content = new byte[4 * 1024 * 1024 + 17];
        new Random(1).nextBytes(content);
        var source = temporaryFolder.getRoot().toPath().resolve("source.img");
        var destination = temporaryFolder.getRoot().toPath().resolve("destination.img");
        Files.write(source, content);
        Files.write(destination, new byte[content.length + 100]);

        AvbTool.copyFile(source, destination);
        assertArrayEquals(content, Files.readAllBytes(destination));
    }

    @Test
    public void fixRejectsMissingRootKeyBeforeVerification() throws Exception {
        var options = new AvbTool.FixOptions();
        options.sourcePattern = temporaryFolder.getRoot().toPath().resolve("{}.img").toString();
        options.keysDir = System.getProperty("test.keysDir");
        options.rootKeyPath = temporaryFolder.getRoot().toPath().resolve("missing.pem").toString();

        assertThrows(IOException.class, () -> AvbTool.fix(options));
    }
}
