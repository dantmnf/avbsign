package xyz.cirno.avb.util;

public class Logger {
    public static int TRACE = 0;
    public static int DEBUG = 1;
    public static int INFO = 2;
    public static int WARN = 3;
    public static int ERROR = 4;
    public static int FATAL = 5;

    private static String levelToString(int level) {
        return switch (level) {
            case 0 -> "TRACE";
            case 1 -> "DEBUG";
            case 2 -> "INFO";
            case 3 -> "WARN";
            case 4 -> "ERROR";
            case 5 -> "FATAL";
            default -> "UNKNOWN";
        };
    }

    public static void log(int level, String msg) {
        System.out.println("[" + levelToString(level) + "] " + msg);
    }

    public static void log(int level, String format, Object... args) {
        String msg = String.format(format, args);
        log(level, msg);
    }

    public static void trace(String msg) {
        log(TRACE, msg);
    }

    public static void trace(String format, Object... args) {
        log(TRACE, format, args);
    }

    public static void debug(String msg) {
        log(DEBUG, msg);
    }

    public static void debug(String format, Object... args) {
        log(DEBUG, format, args);
    }

    public static void info(String msg) {
        log(INFO, msg);
    }

    public static void info(String format, Object... args) {
        log(INFO, format, args);
    }

    public static void warn(String msg) {
        log(WARN, msg);
    }

    public static void warn(String format, Object... args) {
        log(WARN, format, args);
    }

    public static void error(String msg) {
        log(ERROR, msg);
    }

    public static void error(String format, Object... args) {
        log(ERROR, format, args);
    }

    public static void fatal(String msg) {
        log(FATAL, msg);
    }

    public static void fatal(String format, Object... args) {
        log(FATAL, format, args);
    }
}
