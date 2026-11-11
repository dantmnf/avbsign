package xyz.cirno.avbsign;

public class Main {

    public static void main(String[] args) {
        try {
            main2(args);
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main2(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }
        var command = args[0];
        if ("check".equals(command)) {
            if (args.length != 2) {
                printUsage();
                System.exit(1);
            }
            AvbTool.printVerifyResult(AvbTool.check(args[1]));
        } else if ("fix".equals(command)) {
            var options = new AvbTool.FixOptions();

            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                if (arg.startsWith("-")) {
                    if (i + 1 >= args.length) {
                        System.err.println("Missing value for " + arg);
                        System.exit(1);
                    }
                    switch (arg) {
                        case "--keys":
                            options.keysDir = args[++i];
                            break;
                        case "--root-key":
                            options.rootKeyPath = args[++i];
                            break;
                        case "--backup":
                            options.backupDir = args[++i];
                            break;
                        case "--output":
                            options.outputPattern = args[++i];
                            break;
                        default:
                            System.err.println("Unknown option: " + arg);
                            printUsage();
                            System.exit(1);
                    }
                } else {
                    if (options.sourcePattern == null) {
                        options.sourcePattern = arg;
                    } else {
                        System.err.println("Unexpected argument: " + arg);
                        printUsage();
                        System.exit(1);
                    }
                }
            }

            if (options.sourcePattern == null || options.keysDir == null) {
                printUsage();
                System.exit(1);
            }
            AvbTool.fix(options);
        } else {
            System.err.println("Unknown command: " + command);
            printUsage();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  app_process -cp avbsign.apk / xyz.cirno.avbsign.Main check <PATTERN>");
        System.out.println("  app_process -cp avbsign.apk / xyz.cirno.avbsign.Main fix --keys KEYS_DIR [--root-key ROOT_KEY] [--backup BACKUP_DIR] <PATTERN>");
        System.out.println("    PATTERN:              pattern for partition images, use {} as placeholder for partition name");
        System.out.println("                          e.g. `/dev/block/by-name/{}_a`, `{}.img`");
        System.out.println("    --keys KEYS_DIR       directory containing private keys in PEM format");
        System.out.println("    --root-key ROOT_KEY   replace root key with specified key");
        System.out.println("    --output OUT_PATTERN  write modified image to OUT_PATTERN, in-place fix if not specified");
        System.out.println("    --backup BACKUP_DIR   during in-place fix, save backup of modified image in BACKUP_DIR");
    }
}
