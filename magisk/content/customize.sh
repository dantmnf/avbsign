chmod +x "$MODPATH/tools/bootctl_arm64-v8a"
export _AVBSIGN_IN_CUSTOMIZE_SH=1
sh "$MODPATH/action.sh"
