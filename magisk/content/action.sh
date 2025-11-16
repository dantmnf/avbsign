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

bootctl_aidl() {
  sh "$MODDIR/tools/bootctl-aidl.sh" "$@"
}

if bootctl_aidl is-aidl
then
  bootctl="bootctl_aidl"
  echo "using AIDL BootControl service"
else
  # HIDL BootControl
  echo "using HIDL BootControl service"
  bootctl="bootctl_$(getprop ro.product.cpu.abi)"
fi

boot_slot_suffix="$("$bootctl" get-suffix "$("$bootctl" get-active-boot-slot)")"

if [ -z "$boot_slot_suffix" ]
then
  echo "Failed to get boot slot suffix"
  exit 1
fi

echo "Next boot slot: $boot_slot_suffix"

app_process -cp "$MODDIR/avbsign.apk" / xyz.cirno.avbsign.Main fix "/dev/block/by-name/{}$boot_slot_suffix" "$MODDIR/keys"
