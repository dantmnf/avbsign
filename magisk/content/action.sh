#!/bin/busybox sh

MODDIR="${0%/*}"

trap cleanup EXIT

PATH="$MODDIR/tools:$PATH"

pause_trap() {
  rv=$?
  if [ "$KSU" ] || [ "$APATCH" ]
  then
    sleep 300
  fi
  exit $rv
}

if ! [ "$_AVBSIGN_IN_CUSTOMIZE_SH" ]
then
  trap pause_trap EXIT
fi

boot_slot_suffix="$(sh "$MODDIR/tools/get_next_boot_slot.sh")"

if [ -z "$boot_slot_suffix" ]
then
  echo "Failed to get boot slot suffix"
  exit 1
fi

echo "Next boot slot: $boot_slot_suffix"

backup_dir="/data/adb/avbsign/backup-$(date +%Y%m%d-%H%M%S)"

if [ -d /data/adb/avbsign/bootloader ]
then
  echo "replacing bootloader"
  for file in /data/adb/avbsign/bootloader/*.img
  do
    # glob failure will return original pattern
    if [ -e "$file" ]
    then
      name="$(basename "$file" .img)"
      mkdir -p "$backup_dir"
      echo "/dev/block/by-name/${name}${boot_slot_suffix} -> ${backup_dir}/${name}.img"
      dd if="/dev/block/by-name/${name}${boot_slot_suffix}" of="${backup_dir}/${name}.img" bs=4M

      echo "${name}.img -> /dev/block/by-name/${name}${boot_slot_suffix}"
      dd if="$file" of="/dev/block/by-name/${name}${boot_slot_suffix}" bs=4M
    fi
  done
fi

# use $@ to pass extra args
set --
if [ -e /data/adb/avbsign/rootkey.pem ]
then
  set -- --root-key /data/adb/avbsign/rootkey.pem
fi

app_process -cp "$MODDIR/avbsign-release.apk" / xyz.cirno.avbsign.Main fix --keys "$MODDIR/keys" --backup "$backup_dir" "$@" "/dev/block/by-name/{}$boot_slot_suffix"  2>&1

if [ -e "$backup_dir" ]
then
  cp "$MODDIR/tools/restore.sh" "$backup_dir"
fi
