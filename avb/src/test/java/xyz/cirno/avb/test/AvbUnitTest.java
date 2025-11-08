package xyz.cirno.avb.test;

import org.junit.Assert;
import org.junit.Test;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.FileReader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;

import xyz.cirno.avb.AvbPartitionInfo;
import xyz.cirno.avb.AvbPublicKey;
import xyz.cirno.avb.ParsedVerifiedBootMetaImage;
import xyz.cirno.avb.VerifiedBootMetaImage;

public class AvbUnitTest {
    @Test
    public void parseHeaderTest() throws Throwable {
        Assert.assertTrue(testLoadImage("/vbmeta.img").signatureValid);
    }

    @Test
    public void parseChainedPartitionTest() throws Throwable {
        try (var ch = FileChannel.open(getResorucePath("/boot.img"), StandardOpenOption.READ)) {
            var info = AvbPartitionInfo.ofPartition(ch);
            Assert.assertNotNull(info);
            Assert.assertNotNull(info.footer);
            ch.position(info.vbmetaOffset);
            var vbmeta = VerifiedBootMetaImage.parseFrom(ch);
            Assert.assertNotNull(vbmeta);
            Assert.assertTrue(vbmeta.signatureValid);
        }
    }

    @Test
    public void testVbmetaImageRoundTrip() throws Throwable {
        var parsed = testLoadImage("/vbmeta.img");
        Assert.assertTrue(parsed.signatureValid);
        var pubkey = parsed.publicKey;
        var pubkeyBytes = pubkey.toByteArray();
        var refPubkeyBytes = Files.readAllBytes(getResorucePath("/avb_pubkey.bin"));
        var refPubkey = AvbPublicKey.parseFrom(ByteBuffer.wrap(pubkeyBytes));
        Assert.assertArrayEquals(refPubkeyBytes, pubkeyBytes);
        Assert.assertEquals(pubkey, refPubkey);
        //System.out.println(parsed.descriptors.size());

        var privkey = readPrivateKey(getResorucePath("/testkey_rsa4096.pem").toString());
        Assert.assertNotNull(privkey);

        var resigned = parsed.toSignedByteArray((RSAPrivateCrtKey) privkey);
        var origArray = Files.readAllBytes(getResorucePath("/vbmeta.img"));
        if (origArray.length > resigned.length) {
            for (var i = resigned.length; i < origArray.length; i++) {
                if (origArray[i] != 0) {
                    throw new AssertionError("Original vbmeta image has non-zero padding byte at " + i);
                }
            }
            System.out.printf("ignoring extra %d padding bytes in original vbmeta image\n", origArray.length - resigned.length);
        }
        Assert.assertTrue(Arrays.equals(origArray, 0, resigned.length, resigned, 0, resigned.length));
    }

    public static PrivateKey readPrivateKey(String pemFilePath) throws Exception {
        try (FileReader keyReader = new FileReader(pemFilePath);
            var pemParser = new PEMParser(keyReader)) {
            var object = pemParser.readObject();
            var converter = new JcaPEMKeyConverter();
            if (object instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
            } else if (object instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                throw new UnsupportedOperationException("Encrypted private keys not supported in unit test.");
            } else if (object instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) object);
            }
        }
        return null;
    }


    public Path getResorucePath(String identifier) throws Throwable {
        var url = getClass().getResource(identifier);
        Assert.assertNotNull(url);
        Assert.assertTrue("file".equalsIgnoreCase(url.getProtocol()));
        return Paths.get(url.toURI());
    }

    public ParsedVerifiedBootMetaImage testLoadImage(String path) throws Throwable {
        var ch = FileChannel.open(getResorucePath(path), StandardOpenOption.READ);
        var parsed = VerifiedBootMetaImage.parseFrom(ch);
        Assert.assertNotNull(parsed);
        return parsed;
    }
}
