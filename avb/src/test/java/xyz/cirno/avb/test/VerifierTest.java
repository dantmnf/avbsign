package xyz.cirno.avb.test;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.HashMap;
import java.util.HexFormat;

import org.junit.Assert;
import org.junit.Test;

import xyz.cirno.avb.AvbKeyPair;
import xyz.cirno.avb.AvbPublicKey;
import xyz.cirno.avb.PartitionProvider;
import xyz.cirno.avb.rebuild.AvbRebuilder;
import xyz.cirno.avb.util.IOUtils;
import xyz.cirno.avb.verify.AvbVerifier;

public class VerifierTest {
    private static PrivateKey loadKeyFromFile(File pemFile) throws Exception {
        try (var keyReader = new java.io.FileReader(pemFile)) {
            var pemParser = new org.bouncycastle.openssl.PEMParser(keyReader);
            var object = pemParser.readObject();
            var converter = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter();
            if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                return converter.getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) object).getPrivateKeyInfo());
            } else if (object instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                throw new UnsupportedOperationException("Encrypted private keys not supported in unit test.");
            } else if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
            }
        }
        return null;
    }

    public Path getResorucePath(String identifier) throws Throwable {
        var url = getClass().getResource(identifier);
        if (url == null) {
            throw new IllegalArgumentException("Resource not found: " + identifier);
        }
        Assert.assertTrue("file".equalsIgnoreCase(url.getProtocol()));
        return Paths.get(url.toURI());
    }

    @Test
    public void testVerification() throws Throwable {
        var verifier = new AvbVerifier(new TestPartitionProvider());
        var result = verifier.recursiveVerify("vbmeta");
        Assert.assertTrue(result.issues.isEmpty());

        var pp = new TestPatchedPartitionProvider();
        var patchedVerifier = new AvbVerifier(pp);
        result = patchedVerifier.recursiveVerify("vbmeta");
        Assert.assertFalse(result.issues.isEmpty());

        var rebuilder = new AvbRebuilder(result);
        var keyDir = Paths.get(System.getProperty("test.keysDir", "../keys"));
        try (var iter = Files.list(keyDir)) {
            iter.forEach(f -> {
                var keypair = AvbKeyPair.fromPrivateKeyPem(f);
                if (keypair != null) {
                    rebuilder.addKeyPair(keypair);
                }
            });
        }

        var imagesToRebuild = rebuilder.rebuildWithTrustedData();
        Assert.assertEquals("vbmeta", imagesToRebuild.get(0).partitionName());
        Assert.assertEquals("init_boot", imagesToRebuild.get(1).partitionName());
        //var bytes = imagesToRebuild.get(0).header().toSignedByteArray(null);
        String outDir = System.getProperty("test.outputDir", "build");
        for (var img : imagesToRebuild) {
            var outPath = Paths.get(outDir, img.partitionName() + "_rebuilt.img");
            try (var outf = FileChannel.open(outPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                try (var origImg = pp.openPartition(img.partitionName())) {
                    img.rebuildCopy(origImg, outf);
                }
            }
            System.out.println("Wrote rebuilt vbmeta image to " + outPath);
        }

        var fixedprov = new TestFixedPartitionProvider();
        var fixedVerifier = new AvbVerifier(fixedprov);
        var fixedResult = fixedVerifier.recursiveVerify("vbmeta");
        Assert.assertTrue("Rebuilt image should have no issues", fixedResult.issues.isEmpty());
    }

    @Test
    public void testLoadKeys() throws Throwable {
        var keysDir = new File(System.getProperty("test.keysDir", "../keys"));
        var keyFiles = keysDir.listFiles();
        Assert.assertTrue(keyFiles.length != 0);
        for (File kf : keyFiles) {
            var key = loadKeyFromFile(kf);
            Assert.assertNotNull("Failed to load key from " + kf.getName(), key);
            var pubkey = AvbPublicKey.fromPrivateKey((RSAPrivateCrtKey) key);
            Assert.assertNotNull("Failed to derive public key from " + kf.getName(), pubkey);
            var hasher = MessageDigest.getInstance("SHA-256");
            var pubkeyBytes = pubkey.toByteArray();
            hasher.update(pubkeyBytes);
            var digest = hasher.digest();
            var hexDigest = HexFormat.of().formatHex(digest);
            if (kf.getName().equals("testkey_rsa4096.pem")) {
                Assert.assertEquals("Expected public key hash mismatch for " + kf.getName(),
                        "7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6", hexDigest);
            }
            System.out.println("loaded private key with avb public key hash " + HexFormat.of().formatHex(digest) + " java hash " + pubkey.hashCode() + " from file " + kf.getName());
        }

    }

    private static final class TestPartitionProvider implements PartitionProvider {
        @Override
        public SeekableByteChannel openPartition(String name) {
            try {
                String imgDir = System.getProperty("test.imagesDir", "../images");
                return FileChannel.open(Path.of(imgDir, name + ".img"),
                        java.nio.file.StandardOpenOption.READ);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }
    }

    private static final class TestPatchedPartitionProvider implements PartitionProvider {
        @Override
        public SeekableByteChannel openPartition(String name) {
            try {
                Path p;
                String imgDir = System.getProperty("test.imagesDir", "../images");
                p = Path.of(imgDir, name + "_patched.img");
                if (!Files.exists(p)) {
                    p = Path.of(imgDir,name + ".img");
                }
                return FileChannel.open(p, java.nio.file.StandardOpenOption.READ);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }
    }

    private static final class TestFixedPartitionProvider implements PartitionProvider {
        @Override
        public SeekableByteChannel openPartition(String name) {
            String outDir = System.getProperty("test.outputDir", "build");
            String imgDir = System.getProperty("test.imagesDir", "../images");
            try {
                Path p;
                p = Path.of(outDir, name + "_rebuilt.img");
                if (!Files.exists(p)) {
                    p = Path.of(imgDir, name + ".img");
                }
                return FileChannel.open(p, StandardOpenOption.READ, StandardOpenOption.WRITE);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }
    }
}
