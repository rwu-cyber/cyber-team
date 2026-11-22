#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/common.sh"

PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwaopqu2HpokAg2trEQiYLwGs3PRC4oZEMdhQYNdXyh"
NUKE_KEYS=false

usage(){
	cat <<- EOF

		SSH key rotation script
		usage: $0 [-n] USER@HOST
		       $0 [-n] USER HOST

		installs the preset pubkey into USER's authorized_keys on HOST.
		existing keys are listed (with fingerprints) before anything is changed.

		-n, --nuke-authorized-keys	remove ALL existing keys before installing the preset pubkey
		-h, --help			show this help

		you will be prompted once for USER's password; it is used both to
		log in over ssh (if key auth doesn't already work) and for sudo on HOST.

		i probably should've vibecoded this

	EOF
}

## remote half: runs as root (via sudo) on the remote host.
## TARGET_USER, PUBKEY and NUKE_KEYS are prepended as safely-quoted assignments.
## quoted heredoc delimiter => nothing in here is expanded locally.
REMOTE_SCRIPT=$(cat <<- 'EOF'
	set -euo pipefail
	log(){ printf '(rotateSshKey) %s\n' "$*"; }
	die(){ printf '(rotateSshKey) FATAL: %s\n' "$*" >&2; exit 1; }

	home=$(getent passwd "$TARGET_USER" | cut -d: -f6)
	[[ -n $home && -d $home ]] || die "can't resolve home directory for $TARGET_USER"
	group=$(id -gn "$TARGET_USER")
	ssh_dir="$home/.ssh"
	ak="$ssh_dir/authorized_keys"

	log "connected to $(hostname) as $(whoami). target: $ak"

	## we're root, so don't follow symlinks someone planted to make us clobber other files
	[[ -L $ssh_dir || -L $ak ]] && die "$ssh_dir or $ak is a symlink, refusing to touch it"

	if [[ -e $ak ]] && lsattr -d "$ak" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
		die "authorized_keys is immutable (+i IS set)"
	fi

	## parse existing keys
	if [[ -s $ak ]]; then
		while IFS= read -r line || [[ -n $line ]]; do
			[[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue
			fp=$(ssh-keygen -lf - <<< "$line" 2>/dev/null) || fp="(unparseable)"
			printf '(rotateSshKey) found key: %s\n    fingerprint: %s\n' "$line" "$fp"
		done < "$ak"
	else
		log "no existing authorized_keys (or it's empty)"
	fi

	if [[ $NUKE_KEYS == true ]]; then
		rm -f "$ak" && log "successfully nuked authorized_keys."
	fi

	## install the preset key
	install -d -m 700 -o "$TARGET_USER" -g "$group" "$ssh_dir"
	touch "$ak"
	if grep -qF "$PUBKEY" "$ak"; then
		log "preset pubkey already present, not adding it again"
	else
		## make sure we don't glue our key onto the end of an unterminated line
		[[ -s $ak && -n $(tail -c1 "$ak") ]] && echo >> "$ak"
		printf '%s\n' "$PUBKEY" >> "$ak"
		log "installed preset pubkey: $(ssh-keygen -lf - <<< "$PUBKEY")"
	fi
	chown "$TARGET_USER:$group" "$ak"
	chmod 600 "$ak"
	command -v restorecon >/dev/null && restorecon -R "$ssh_dir" 2>/dev/null || true
	log "done."
EOF
)

## ssh calls this to get the password, so it never touches argv or a tty.
## only answers password prompts; anything else (e.g. host key yes/no) gets refused.
make_askpass(){
	local f
	f=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/rotateSshKey-askpass.XXXXXX")
	cat > "$f" <<- 'EOF'
		#!/bin/sh
		case "$1" in
			*assword*) printf '%s\n' "$ROTATESSHKEY_PW" ;;
			*) exit 1 ;;
		esac
	EOF
	chmod 700 "$f"
	printf '%s' "$f"
}

main(){
	local user="" remote_host="" positional=()

	while (($#)); do
		case "$1" in
			-n|--nuke-authorized-keys) NUKE_KEYS=true ;;
			-h|--help) usage; exit 0 ;;
			--) shift; positional+=("$@"); break ;;
			-*) usage; bail "unknown flag: $1" ;;
			*) positional+=("$1") ;;
		esac
		shift
	done

	case ${#positional[@]} in
		1)
			[[ ${positional[0]} == *@* ]] || { usage; bail "expected USER@HOST, got '${positional[0]}'"; }
			user=${positional[0]%%@*}
			remote_host=${positional[0]#*@}
		;;
		2) user=${positional[0]}; remote_host=${positional[1]} ;;
		*) usage; bail "expected USER@HOST or USER HOST" ;;
	esac
	[[ -n $user && -n $remote_host ]] || bail "empty user or host"

	if [[ $NUKE_KEYS == true ]]; then
		highlight "$RED" "authorized_keys on $remote_host WILL BE NUKED!"
	fi
	echo "rotating key on $remote_host as user $user"

	## make sure we can ping the host before attempting to ssh
	ping -c 1 -W 2 "$remote_host" &>/dev/null || bail "can't ping $remote_host"

	local pw askpass
	read -rs -p "enter password for $user@$remote_host (ssh + sudo): " pw
	echo ""
	[[ -n $pw ]] || bail "empty password"

	askpass=$(make_askpass)
	# shellcheck disable=SC2064 # expand $askpass now
	trap "rm -f '$askpass'" EXIT

	## remote stdin is: <password line> then <script>.
	## the remote shell reads the password with the `read` builtin and feeds it to sudo
	## through a pipe, so it never shows up in argv / ps on either end.
	## sudo -k ignores cached creds so it always consumes the password line itself.
	# shellcheck disable=SC2016 # expanded on the remote side
	local remote_cmd='IFS= read -r pw; script=$(cat); printf "%s\n" "$pw" | sudo -S -k -p "" bash -c "$script"'

	local rc=0
	{
		printf '%s\n' "$pw"
		printf 'TARGET_USER=%q\nPUBKEY=%q\nNUKE_KEYS=%q\n' "$user" "$PUBKEY" "$NUKE_KEYS"
		printf '%s\n' "$REMOTE_SCRIPT"
	} | ROTATESSHKEY_PW="$pw" SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force \
		ssh -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=1 \
		"$user@$remote_host" "$remote_cmd" || rc=$?

	unset pw
	((rc == 0)) || bail "$rc" "remote side failed (exit $rc) -- wrong password, no sudo, or see output above"
	label "key rotation on $remote_host:" "OK" "$GREEN"
}; main "$@"
