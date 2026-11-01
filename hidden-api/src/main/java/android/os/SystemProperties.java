package android.os;

public class SystemProperties {
    public static native String get(String name);
    public static native String get(String name, String def);
}
