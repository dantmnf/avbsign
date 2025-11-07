package xyz.cirno.avb;

public enum AvbDigestType {
    SHA256,
    SHA512;

    public static AvbDigestType fromInt(int value) {
        return switch (value) {
            case 1 -> SHA256;
            case 2 -> SHA512;
            default -> throw new IllegalArgumentException("Unknown digest type: " + value);
        };
    }
}
