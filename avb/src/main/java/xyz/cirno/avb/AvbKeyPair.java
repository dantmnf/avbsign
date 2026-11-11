package xyz.cirno.avb;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.jetbrains.annotations.Nullable;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Objects;

public record AvbKeyPair(AvbPublicKey publicKey, PrivateKey privateKey) {

    @Nullable
    private static PrivateKey parsePrivateKeyFromPem(Path privateKeyPath) {
        try (var keyReader = new FileReader(privateKeyPath.toFile())) {
            var pemParser = new PEMParser(keyReader);
            var object = pemParser.readObject();
            var converter = new JcaPEMKeyConverter();
            if (object instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
            } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                return null;
            } else if (object instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) object);
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    public static AvbKeyPair fromPrivateKey(PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey rsaPrivateKey)) {
            throw new IllegalArgumentException("Only RSA private keys are supported");
        }
        var publicKey = AvbPublicKey.fromPrivateKey(rsaPrivateKey);
        return new AvbKeyPair(publicKey, privateKey);
    }

    @Nullable
    public static AvbKeyPair fromPrivateKeyPem(Path privateKeyPath) {
        var privateKey = parsePrivateKeyFromPem(privateKeyPath);
        if (privateKey == null) {
            return null;
        }
        return fromPrivateKey(privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass(), publicKey, privateKey);
    }
}
