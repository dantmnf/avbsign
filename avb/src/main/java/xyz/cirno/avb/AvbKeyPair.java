package xyz.cirno.avb;

import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Objects;

public final class AvbKeyPair {
    public final AvbPublicKey publicKey;
    public final PrivateKey privateKey;

    public AvbKeyPair(AvbPublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Nullable
    private static PrivateKey parsePrivateKeyFromPem(Path privateKeyPath) {
        try (var keyReader = new java.io.FileReader(privateKeyPath.toFile())) {
            var pemParser = new org.bouncycastle.openssl.PEMParser(keyReader);
            var object = pemParser.readObject();
            var converter = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter();
            if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                return converter.getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) object).getPrivateKeyInfo());
            } else if (object instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                return null;
            } else if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
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
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AvbKeyPair that = (AvbKeyPair) o;
        return Objects.equals(publicKey, that.publicKey) && Objects.equals(privateKey, that.privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass(), publicKey, privateKey);
    }
}
