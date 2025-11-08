package xyz.cirno.avb;

public class InvalidAvbDataException extends RuntimeException {
    public InvalidAvbDataException(String message) {
        super(message);
    }

    public static void checkUnsignedOverflow(int x) {
        if (x < 0) {
            throw new InvalidAvbDataException("signed int32 overflow");
        }
    }

    public static void checkUnsignedOverflow(long x) {
        if (x < 0) {
            throw new InvalidAvbDataException("signed int64 overflow");
        }
    }
}
