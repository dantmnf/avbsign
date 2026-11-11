# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

-repackageclasses

-keep class xyz.cirno.avbsign.Main {
    public static main(java.lang.String[]);
}

-assumenosideeffects class org.bouncycastle.crypto.NativeLoader { void loadDriver(); }

-keep class xyz.cirno.avbsign.AvbService { *; }
-keep class xyz.cirno.avbsign.IAvbService$* { *; }
-keep class xyz.cirno.avbsign.IAvbLogCallback$* { *; }
-keep class xyz.cirno.avbsign.AvbTool {
    private static native <methods>;
}
