#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

(($UID == 0)) || bail "are you root?"

## bail if we dont have nmap to begin with
if ! command -v nmap 1>/dev/null; then
    bail "nmap is not installed!"
fi

## if SAVE_DIR is unset, `scan-results` does not already exist, and we can modify $PWD, then create the dir
if [[ ! -v SAVE_DIR && ! -e "$PWD/scan-results" && -w "$PWD" ]]; 
 then
    mkdir "$PWD/scan-results"
    SAVE_DIR="$PWD/scan-results"
 elif [[ -z ${SAVE_DIR:-} ]];
  then
	SAVE_DIR="$PWD/scan-results"
fi

main(){
	local target
	## make sure we're actually passed an argument
	if (($#==0)); 
	 then
		bail "expected target(s) to scan, but got nothing."
	 else
		target="$1"

		divider "$BLUE" "scan the network without reverse DNS resolution"
		nmap -sn -n -oA "${SAVE_DIR}/pingscan-nodns" "$target"
		
		divider "$BLUE" "perform host discovery on previous result"
		nmap -oA "${SAVE_DIR}/host-discovery" -O "$target" 
	fi
}; main "$@"