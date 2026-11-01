> [!WARNING]  
> Use at your own risk.


### Build Android binary

```console
$ ./gradlew dex:assembleRelease
```

### Build Java JAR (for Desktop)

```console
$ ./gradlew jar:jar
```

### CLI Usage

#### Desktop
```console
$ java -jar jar/build/libs/avbsign.jar check {}.img
$ java -jar jar/build/libs/avbsign.jar fix {}.img dir/to/keys
```

#### Android
```console
$ app_process -cp avbsign-release.apk / xyz.cirno.avbsign.Main check /dev/block/by-name/{}_a
$ app_process -cp avbsign-release.apk / xyz.cirno.avbsign.Main fix /dev/block/by-name/{}_a dir/to/keys
```

### Android GUI

The `avbsign-release.apk` built from the `dex` module also contains a launcher activity.

Requirements:

- Shizuku started with root (the privileged operations run inside a Shizuku user service, no `su` command lines are used)

Usage:

1. Install and open the app, grant the Shizuku permission when asked.
2. Import files from the management screens. Files are stored under /data/adb, consistent with the Magisk module scripts:
   - signing keys: `/data/adb/modules/avbsign/keys`
   - bootloader images: `/data/adb/avbsign/bootloader`
3. The partition path pattern defaults to `/dev/block/by-name/{}<slot>` with the current boot slot suffix detected automatically.
4. Use 检查签名 to verify, 修复并重签 to rebuild and re-sign in place with the imported keys, or 刷入镜像 to flash the imported bootloader images. Before fixing, you can optionally pick one of the imported keys as the root key replacement.
5. When 修改前备份原镜像 is enabled, backups are written to `/data/adb/avbsign/backup-<timestamp>`.

### Build Magisk Module

```console
$ ./gradlew magisk:packageMagisk
```

The Magisk module will be generated at `build/avbsign.zip`.

It will run `app_process -cp avbsign-release.apk / xyz.cirno.avbsign.Main fix /dev/block/by-name/{}${boot_slot_suffix} /data/adb/modules/avbsign/keys` on installation and `action.sh`.
