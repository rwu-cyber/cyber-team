#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"
die(){
  printf '[%s] %s\n' "${FUNCNAME[1]}" "$*" >&2
  exit 1
}

username="rwuhawks"

# check if script was run as root
(( $UID == 0 )) || die "This script must be run as root."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi

createUser(){
  read -rp "Enter account password: " password 
  if [ -z "$password" ];
   then
    bail "no password given."
  fi
# create user in accordance to distro
case $OS in
    "debian"|"ubuntu") adduser --gecos "" "${username}" || die "Failed to create user." ; usermod -aG sudo "${username}" ;;
    "rocky"|"almalinux"|"rhel"|"fedora"|"sles"|"opensuse-leap") useradd "${username}" || die "Failed to create user." ; usermod -aG wheel "${username}";;
    *) echo "Cannot add user to $OS system" ;;
esac

  printf '%s ALL=(ALL:ALL) ALL\n' "$username" > "/etc/sudoers.d/$username"
  chmod 0440 "/etc/sudoers.d/$username"
  passwd "$username" -s <<< "$password"
}

validate(){
  visudo -cf "/etc/sudoers.d/$username" || die "visudo check failed."
  sudo -l -U $username
}

main(){
  createUser "$@"
  validate
}; main "$@"
