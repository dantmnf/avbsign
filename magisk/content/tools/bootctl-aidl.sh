#!/bin/busybox ash

clean_result_parcel() { # stdin=service command output
  awk '/Result: Parcel\(/ {
      if(substr($0,16,1)=="E") {print; exit 1}
    }
    / [0-9a-f]{8} / {
      sub(/^0x[0-9a-f]{8}: /,"")
      sub(/^Result: Parcel\(\t/,"")
      sub(/ +\x27.*$/,"")
      print gensub(/([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/,"\\4\\3\\2\\1","g")
    }'
}

check() { # $1=status [$2=error msg]
  if [ "$1" != 0 ]
  then
    [ -n "$2" ] && echo "$2" >&2
    exit "$1"
  fi
}

get_int() { # $1=offset stdin=hexdump
  echo $(xxd -rp | od -vAn -td4 -j "$1" -N4) # strip spaces
}

slice() { # $1=offset [$2=length] stdin=hexdump stdout=hexdump
  if [ "$#" = 2 ]
  then
    xxd -rp | od -vAn -tx1 -j "$1" -N "$2"
  else
    xxd -rp | od -vAn -tx1 -j "$1"
  fi
}

to_bin() { # [$1=offset] [$2=length] stdin=hexdump
  slice "$@" | xxd -rp
}

is_aidl() {
  chk="$(service check android.hardware.boot.IBootControl/default)"
  [[ "$chk" != "*not found*" ]]
}

get_active_boot_slot() {
  parcel="$(service call android.hardware.boot.IBootControl/default 1 | clean_result_parcel)"
  check "$?" "binder transact error"
  code="$(echo "$parcel" | get_int 0)"
  check "$?" "AIDL error"
  slot="$(echo "$parcel" | get_int 4)"
  echo "$slot"
}

get_suffix() { # $1=slot_id
  parcel="$(service call android.hardware.boot.IBootControl/default 5 i32 "$1" | clean_result_parcel)"
  check "$?" "binder transact error"
  code="$(echo "$parcel" | get_int 0)"
  check "$?" "AIDL error"
  len="$(echo "$parcel" | get_int 4)"
  echo "$parcel" | slice 8 "$((len*2))" | xxd -rp | iconv -f utf-16le
  echo # newline
}

case "$1" in
  is-aidl)
    is_aidl
    ;;
  get-active-boot-slot)
    get_active_boot_slot
    ;;
  get-suffix)
    get_suffix "$2"
    ;;
  *)
    echo "usage: $0 COMMAND"
    echo "Commands:"
    echo "is-aidl"
    echo "get-active-boot-slot"
    echo "get-suffix SLOT"
    exit 1
    ;;
esac
