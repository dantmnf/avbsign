#!/bin/mksh

if ! [ "$(command -v awk)" = "awk" ]
then
  if ! command -v busybox >/dev/null 2>&1
  then
    PATH="/data/adb/magisk:/data/adb/ksu/bin:/data/adb/ap/bin"
  fi

  if ! command -v busybox >/dev/null 2>&1
  then
    echo "no busybox found"
    exit 1
  fi
  ASH_STANDALONE=1 exec busybox sh "$0" "$@"
fi

current_slot="$(getprop ro.boot.slot_suffix)"

basedir="${0%/*}"

for image in "$basedir"/*.img
do
  partition="$(basename "$image" .img)"
  echo "restoring ${partition}.img -> /dev/block/by-name/${partition}${current_slot}"
  dd if="$image" of="/dev/block/by-name/${partition}${current_slot}" bs=4M
done
