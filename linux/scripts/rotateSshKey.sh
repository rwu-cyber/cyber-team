#!/usr/bin/env bash
set -euo pipefail
KEY_TYPE="ed25519"
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
