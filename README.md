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

### Build Magisk Module

```console
$ ./gradlew magisk:packageMagisk
```

The Magisk module will be generated at `build/avbsign.zip`.

It will run `app_process -cp avbsign-release.apk / xyz.cirno.avbsign.Main fix /dev/block/by-name/{}${boot_slot_suffix} /data/adb/modules/avbsign/keys` on installation and `action.sh`.
