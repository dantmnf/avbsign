#!/system/bin/sh

basedir="$(dirname "$0")"

backup_dir="/data/adb/avbsign/backup-$(date +%Y%m%d-%H%M%S)"

slot="$(sh "$basedir/get_next_boot_slot.sh")"

echo "next boot slot: $slot"

for partition in vbmeta boot init_boot
do
  if [ -e "/dev/block/by-name/${partition}${slot}" ]
  then
    mkdir -p "$backup_dir"
    echo dd if="/dev/block/by-name/${partition}${slot}" of="${backup_dir}/${partition}.img"
    dd if="/dev/block/by-name/${partition}${slot}" of="${backup_dir}/${partition}.img" bs=4M
  fi
done

if [ -e "$backup_dir" ]
then
  cp "$basedir/restore.sh" "$backup_dir"
fi
