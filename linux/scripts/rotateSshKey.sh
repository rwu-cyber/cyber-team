#!/usr/bin/env bash
##
# THIS SCRIPT IS DESTRUCTIVE!!! IT WILL NUKE ANY KEYS IN `authorized_keys`!!!
# 
# sleep deprived key rotation script. this will be improved on.     
# 	- generates a new key (with type based on `KEY_TYPE` env var)
# 	- uses `ssh-copy-id` to copy the key to the remote host
# 	- tests and NUKES `authorized_keys`         
# 	- post-verification by looking line-by-line for the expected key in `authorized_keys`
#
#want to rotate multiple hosts? throw it in a for ... do; loop!
#
# i probably should've vibecoded this
##
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"

PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwaopqu2HpokAg2trEQiYLwGs3PRC4oZEMdhQYNdXyh"

main(){
	local target
	(( $# == 0 )) && bail "no host provided."
	target="$1"
	ssh "$target" bash <<- EOF
		if [[ -e "\$HOME/.ssh/authorized_keys" ]]; then 
			cat \$HOME/.ssh/authorized_keys
			read -rp "Nuke existing authorized keys? (y/N)" nukekeys
			case "\$nukekeys" in
				y|Y)
					sudo rm -rf \$HOME/.ssh/authorized_keys
				;;
				*)
					echo "ignoring authorized_keys..."
				;;
			esac
		fi
		printf "$PUBKEY" >> \$HOME/.ssh/authorized_keys
	EOF
}
