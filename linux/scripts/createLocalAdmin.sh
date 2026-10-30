#!/usr/bin/env bash
set -euo pipefail
die(){
  printf '[%s] %s\n' "${FUNCNAME[1]}" "$*" >&2
  exit 1
}

# check if script was run as root
(( $UID == 0 )) || die "This script must be run as root."

createUser(){
  (( $# == 0 )) && read -rp "Enter account username: " username || username="$1"
  if [ -z "$username" ]; then
    die "No input detected."
  fi

  adduser --gecos "" "${username}" || die "Failed to create user."
  printf '%s ALL=(ALL:ALL) ALL\n' "$username" > "/etc/sudoers.d/$username"
}

validate(){
  visudo -cf "/etc/sudoers.d/$username" || die "visudo check failed."
  sudo -l -U $username
}

main(){
  createUser "$@"
  validate
}; main "$@"