package xyz.cirno.avb;

public enum AvbAlgorithmType {
    NONE,
    SHA256_RSA2048,
    SHA256_RSA4096,
    SHA256_RSA8192,
    SHA512_RSA2048,
    SHA512_RSA4096,
    SHA512_RSA8192;

    public String getDigestAlgorithm() {
        return switch (this) {
            case NONE -> null;
            case SHA256_RSA2048, SHA256_RSA4096, SHA256_RSA8192 -> "SHA-256";
            case SHA512_RSA2048, SHA512_RSA4096, SHA512_RSA8192 -> "SHA-512";
        };
    }

    public int getAuthenticationBlockSize() {
        return switch (this) {
            case SHA256_RSA2048 -> 256 / 8 + 2048 / 8;
            case SHA256_RSA4096 -> 256 / 8 + 4096 / 8;
            case SHA256_RSA8192 -> 256 / 8 + 8192 / 8;
            case SHA512_RSA2048 -> 512 / 8 + 2048 / 8;
            case SHA512_RSA4096 -> 512 / 8 + 4096 / 8;
            case SHA512_RSA8192 -> 512 / 8 + 8192 / 8;
            default -> 0;
        };
    }

    public int getHashSize() {
        return switch (this) {
            case SHA256_RSA2048, SHA256_RSA4096, SHA256_RSA8192 -> 256 / 8;
            case SHA512_RSA2048, SHA512_RSA4096, SHA512_RSA8192 -> 512 / 8;
            default -> 0;
        };
    }

    public int getSignatureSize() {
        return switch (this) {
            case SHA256_RSA2048, SHA512_RSA2048 -> 2048 / 8;
            case SHA256_RSA4096, SHA512_RSA4096 -> 4096 / 8;
            case SHA256_RSA8192, SHA512_RSA8192 -> 8192 / 8;
            default -> 0;
        };
    }

    public String getSignatureAlgorithm() {
        return switch (this) {
            case SHA256_RSA2048, SHA256_RSA4096, SHA256_RSA8192 -> "SHA256withRSA";
            case SHA512_RSA2048, SHA512_RSA4096, SHA512_RSA8192 -> "SHA512withRSA";
            default -> null;
        };
    }

    public int getKeySize() {
        return switch (this) {
            case SHA256_RSA2048, SHA512_RSA2048 -> 2048;
            case SHA256_RSA4096, SHA512_RSA4096 -> 4096;
            case SHA256_RSA8192, SHA512_RSA8192 -> 8192;
            default -> 0;
        };
    }

    public static AvbAlgorithmType fromInt(int value) {
        return switch (value) {
            case 0 -> NONE;
            case 1 -> SHA256_RSA2048;
            case 2 -> SHA256_RSA4096;
            case 3 -> SHA256_RSA8192;
            case 4 -> SHA512_RSA2048;
            case 5 -> SHA512_RSA4096;
            case 6 -> SHA512_RSA8192;
            default -> throw new IllegalArgumentException("Unknown algorithm type: " + value);
        };
    }

}

