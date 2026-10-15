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
: "${KEY_TYPE:=ed25519}"
main(){
	IFS='@' read -r remote_user host <<< $1
	if ping -c 1 $host; then
		## assumes you use some sort of agent, like bitwarden
		ssh-add -D
		ssh-keygen -N '' -f $HOME/.ssh/$host-$KEY_TYPE
		if ssh-copy-id $remote_user@$host; then
			ssh $remote_user@$host bash <<- EOF
				echo "connected to $host (\$(hostname))"...
				lineind=0
				cp \$HOME/.ssh/authorized_keys \$HOME/.ssh/authorized_keys.bak
				echo "$(cat $HOME/.ssh/$host-$KEY_TYPE.pub)" | tee \$HOME/.ssh/authorized_keys
				mapfile -t authorized_keys < \$HOME/.ssh/authorized_keys
				for line in "\${authorized_keys[@]}"; do
					((lineind++))
					if [[ \$line == "$(cat $HOME/.ssh/$host-$KEY_TYPE.pub)" ]]; then					
						echo "located roated key on line \$lineind in authorized_keys."
					else
						echo "WARN: found unknown key: '\$line'"
					fi
				done
			EOF
		fi
	fi
}; main "$@"
