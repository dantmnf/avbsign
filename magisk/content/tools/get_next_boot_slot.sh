#!/system/bin/sh

basedir="$(dirname "$0")"

bootctl_aidl() {
  sh "$basedir/bootctl-aidl.sh" "$@"
}

if bootctl_aidl is-aidl
then
  bootctl="bootctl_aidl"
else
  # HIDL BootControl
  bootctl="$basedir/bootctl_$(getprop ro.product.cpu.abi)"
fi

boot_slot_suffix="$("$bootctl" get-suffix "$("$bootctl" get-active-boot-slot)")"

if [ -z "$boot_slot_suffix" ]
then
  echo "Failed to get boot slot suffix" >&2
  exit 1
fi

echo "$boot_slot_suffix"
