#!/usr/bin/env bash
# let the official installer handle wazuh, and keep our changes here
set -e
umask 077
setup_fail() { echo "Error: $*" >&2; exit 1; }
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    echo "Usage: sudo bash $0 [official Wazuh installer options]"
    echo 'Default: latest stable 4.x all-in-one install. Use -p PORT for a custom dashboard port.'
    exit 0
fi
[[ "$EUID" == 0 && -t 0 ]] || setup_fail 'Run with sudo from a terminal.'
if command -v dpkg >/dev/null; then
    command -v curl >/dev/null || { apt-get update -qq; apt-get install -y -qq curl ca-certificates; }
elif command -v rpm >/dev/null; then
    if ! command -v curl >/dev/null; then
        if command -v dnf >/dev/null; then dnf -q -y install curl ca-certificates
        else yum -q -y install curl ca-certificates; fi
    fi
else setup_fail 'A DEB or RPM system is required.'; fi
(( $# )) || set -- -a
setup_work=$(mktemp -d)
setup_log=/var/log/wazuh-setup.log
trap 'setup_exit=$?; rm -rf -- "$setup_work"; if (( setup_exit )); then echo "Setup stopped. Check $setup_log if installation started." >&2; fi' EXIT
setup_fetch() { curl -fsSL --connect-timeout 15 --max-time 120 --retry 2 "$1"; }

# use the latest stable release, not a hardcoded version or a release candidate
setup_version=$(setup_fetch https://api.github.com/repos/wazuh/wazuh/releases/latest |
    sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p')
[[ "$setup_version" =~ ^4\.[0-9]+\.[0-9]+$ ]] || setup_fail 'Could not find a stable Wazuh 4.x release.'
setup_script="$setup_work/wazuh-install.sh"
setup_fetch "https://packages.wazuh.com/${setup_version%.*}/wazuh-install.sh" > "$setup_script"
bash -n "$setup_script"
[[ "$(grep -Fxc 'main "$@"' "$setup_script")" == 1 ]] || setup_fail 'Official installer layout changed; review it before running.'

# load its functions without starting the install yet
source <(sed '/^main "\$@"$/d' "$setup_script")
[[ "$wazuh_version" == "$setup_version" ]] || setup_fail 'Latest release is not available in the official installer yet.'
declare -F passwords_generatePassword >/dev/null || setup_fail 'Official password setup changed.'
eval "$(declare -f passwords_generatePassword | sed '1s/passwords_generatePassword/setup_randomPasswords/')"

# keep the other accounts random, but use our password for admin
passwords_generatePassword() {
    setup_randomPasswords "$@"
    local setup_i
    if [[ -n "${setup_password:-}" ]]; then
        for setup_i in "${!users[@]}"; do
            [[ "${users[setup_i]}" != admin ]] || passwords[setup_i]="$setup_password"
        done
    fi
}
for setup_arg in "$@"; do
    case "$setup_arg" in
        -a|--all-in-one|-g|--generate-config-files)
            while true; do
                read -rsp 'Admin password (8-64 characters, letters/numbers/.+-): ' setup_password; echo
                # these symbols also work safely with the installer's shell commands
                [[ "$setup_password" =~ ^[A-Za-z0-9.+-]{8,64}$ && "$setup_password" =~ [A-Z] && "$setup_password" =~ [a-z] && "$setup_password" =~ [0-9] && "$setup_password" =~ [.+-] ]] || { echo 'Include uppercase, lowercase, a number, and . + or -.'; continue; }
                read -rsp 'Confirm password: ' setup_confirmation; echo
                [[ "$setup_password" == "$setup_confirmation" ]] && break
                echo 'Passwords do not match.'
            done
            break ;;
    esac
done

# its full output includes passwords, so keep the log readable only by root
echo "Installing Wazuh $setup_version. Log: $setup_log"
: > "$setup_log"
chmod 0600 "$setup_log"
# the official script checks its own errors, so do not change how it runs
set +e
main "$@" > "$setup_log" 2>&1
setup_result=$?
set -e
[[ "$setup_result" == 0 ]] || setup_fail "Installation failed; see $setup_log and /var/log/wazuh-install.log."
unset setup_password setup_confirmation

# only open ports for the components we installed
setup_public=() setup_private=()
[[ -z "${AIO:-}${wazuh:-}" ]] || setup_public+=(1514 1515)
[[ -z "${AIO:-}${dashboard:-}" ]] || setup_public+=("$http_port")
[[ -z "${indexer:-}" ]] || setup_private+=(9200 9300)
[[ -z "${wazuh:-}" || -n "${AIO:-}" ]] || setup_private+=(55000)
if [[ -n "${wazuh:-}" && "${#server_node_names[@]}" -gt 1 ]]; then setup_private+=(1516); fi
if (( ${#setup_public[@]} + ${#setup_private[@]} )); then
    read -rp "Open inbound TCP ports (${setup_public[*]} ${setup_private[*]})? [y/N]: " setup_answer
    if [[ "$setup_answer" == [yY] || "$setup_answer" == [yY][eE][sS] ]]; then
        setup_source=''
        if (( ${#setup_private[@]} )); then
            # do not expose the indexer, api, or cluster ports to everyone
            read -rp 'Trusted peer IP/CIDR for internal ports (blank skips them): ' setup_source
            [[ -z "$setup_source" || "$setup_source" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] || setup_fail 'Invalid source address.'
        fi
        setup_backend=none
        if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then setup_backend=ufw
        elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
            setup_backend=firewalld
            mapfile -t setup_zones < <(firewall-cmd --get-active-zones | awk '/^[^[:space:]]/ {print $1}')
            (( ${#setup_zones[@]} )) || setup_zones=("$(firewall-cmd --get-default-zone)")
        elif command -v nft >/dev/null && [[ -n "$(nft list ruleset)" ]]; then
            echo 'Custom nftables rules: allow the listed ports manually.'
        elif command -v iptables >/dev/null; then setup_backend=iptables
        else echo 'No supported active firewall found.'; fi
        setup_ports=("${setup_public[@]}")
        [[ -z "$setup_source" ]] || setup_ports+=("${setup_private[@]}")
        for setup_port in "${setup_ports[@]}"; do
            setup_from=''
            for setup_internal in "${setup_private[@]}"; do
                [[ "$setup_port" != "$setup_internal" ]] || setup_from="$setup_source"
            done
            case "$setup_backend" in
                ufw) ufw allow proto tcp from "${setup_from:-any}" to any port "$setup_port" ;;
                firewalld)
                    for setup_zone in "${setup_zones[@]}"; do
                        for setup_scope in runtime permanent; do
                            setup_flags=(); [[ "$setup_scope" != permanent ]] || setup_flags=(--permanent)
                            if [[ -z "$setup_from" ]]; then
                                firewall-cmd "${setup_flags[@]}" --zone="$setup_zone" --add-port="$setup_port/tcp" >/dev/null
                            else
                                setup_family=ipv4; [[ "$setup_from" != *:* ]] || setup_family=ipv6
                                firewall-cmd "${setup_flags[@]}" --zone="$setup_zone" --add-rich-rule="rule family=\"$setup_family\" source address=\"$setup_from\" port port=\"$setup_port\" protocol=\"tcp\" accept" >/dev/null
                            fi
                        done
                    done ;;
                iptables)
                    setup_flags=(); [[ -z "$setup_from" ]] || setup_flags=(-s "$setup_from")
                    for setup_tool in iptables ip6tables; do
                        [[ -z "$setup_from" || "$setup_from" != *:* || "$setup_tool" == ip6tables ]] || continue
                        [[ -z "$setup_from" || "$setup_from" == *:* || "$setup_tool" == iptables ]] || continue
                        command -v "$setup_tool" >/dev/null || continue
                        "$setup_tool" -C INPUT "${setup_flags[@]}" -p tcp --dport "$setup_port" -j ACCEPT 2>/dev/null ||
                            "$setup_tool" -I INPUT 1 "${setup_flags[@]}" -p tcp --dport "$setup_port" -j ACCEPT
                    done ;;
            esac
        done
        [[ "$setup_backend" != iptables ]] || echo 'iptables rules are for this boot only.'
    fi
    echo "Installed. IPs: $(hostname -I)"
    if [[ -n "${AIO:-}${dashboard:-}" ]]; then
        for setup_ip in $(hostname -I); do
            [[ "$setup_ip" != *:* ]] || setup_ip="[$setup_ip]"
            echo "Dashboard: https://$setup_ip:$http_port (user: admin)"
        done
    fi
fi
