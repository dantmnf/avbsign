package xyz.cirno.avb;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

public class AvbPublicKey {
    private final RSAPublicKey publicKey;
    public static final int EXPONENT = 65537;
    public final int keySizeBits;

    public AvbPublicKey(RSAPublicKey key) {
        publicKey = Objects.requireNonNull(key);
        if (!publicKey.getPublicExponent().equals(BigInteger.valueOf(EXPONENT))) {
            throw new IllegalArgumentException("Only exponent " + EXPONENT + " is supported");
        }
        keySizeBits = roundToPowerOf2(publicKey.getModulus().bitLength());
    }

    public static AvbPublicKey readFrom(ByteBuffer buf) {
        var bits = buf.getInt();
        // n0inv is stored but we don't need it to reconstruct the public key
        var n0inv = buf.getInt();
        int byteLen = bits / 8;
        var modulusBytes = new byte[byteLen];
        buf.get(modulusBytes);
        var r2modNBytes = new byte[byteLen];
        buf.get(r2modNBytes);
        var modulus = new BigInteger(1, modulusBytes);
        var exp = BigInteger.valueOf(EXPONENT);
        try {
            var spec = new RSAPublicKeySpec(modulus, exp);
            var kf = KeyFactory.getInstance("RSA");
            var pub = (RSAPublicKey) kf.generatePublic(spec);
            return new AvbPublicKey(pub);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to construct RSAPublicKey from buffer", e);
        }
    }

    public static AvbPublicKey fromPrivateKey(RSAPrivateCrtKey privateKey) {
        var modulus = privateKey.getModulus();
        var exp = BigInteger.valueOf(EXPONENT);
        try {
            var spec = new RSAPublicKeySpec(modulus, exp);
            var kf = KeyFactory.getInstance("RSA");
            var pub = (RSAPublicKey) kf.generatePublic(spec);
            return new AvbPublicKey(pub);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to construct RSAPublicKey from private key", e);
        }
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    private static int roundToPowerOf2(int n) {
        if (n <= 0) {
            throw new IllegalArgumentException("n must be positive");
        }
        // smallest power of two >= n
        int prev = Integer.highestOneBit(n - 1);
        return prev == 0 ? 1 : prev << 1;
    }

    public ByteBuffer asByteBuffer() {
        var modulus = publicKey.getModulus();
        var b = BigInteger.ONE.shiftLeft(32);
        // Use BigInteger.modInverse instead of custom implementation
        var n0inv = b.subtract(modulus.modInverse(b));
        var r = BigInteger.ONE.shiftLeft(modulus.bitLength());
        var r2modN = r.multiply(r).mod(modulus);
        var modulusBytes = modulus.toByteArray();
        var r2modNBytes = r2modN.toByteArray();
        var buf = ByteBuffer.allocate(4 + 4 + keySizeBits / 8 + keySizeBits / 8);
        buf.putInt(keySizeBits);
        buf.putInt(n0inv.intValue());
        var zeros = new byte[keySizeBits / 8];
        var padSize = keySizeBits / 8 - modulusBytes.length;
        if (padSize > 0) {
            buf.put(zeros, 0, padSize);
        }
        buf.put(modulusBytes, Math.max(0, modulusBytes.length - keySizeBits / 8), Math.min(modulusBytes.length, keySizeBits / 8));
        padSize = keySizeBits / 8 - r2modNBytes.length;
        if (padSize > 0) {
            buf.put(zeros, 0, padSize);
        }
        buf.put(r2modNBytes, Math.max(0, r2modNBytes.length - keySizeBits / 8), Math.min(r2modNBytes.length, keySizeBits / 8));
        buf.flip();
        return buf;
    }
}
