#!/usr/bin/env bash
# new agents only, using the standard wazuh ports
set -euo pipefail
export LC_ALL=C
fail() { echo "Error: $*" >&2; exit 1; }
manager='' version='' password_file='' yes=no firewall=yes
while (( $# )); do
    case "$1" in
        --manager|--version|--password-file)
            [[ $# -ge 2 && "$2" != --* ]] || fail "Missing value for $1"
            case "$1" in
                --manager) manager="$2" ;;
                --version) version="$2" ;;
                --password-file) password_file="$2" ;;
            esac
            shift 2 ;;
        --yes|-y) yes=yes; shift ;;
        --no-firewall) firewall=no; shift ;;
        --help|-h)
            echo "Usage: sudo bash $0 [--manager IP] [--version 4.x.y] [--password-file PATH] [--yes] [--no-firewall]"
            exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
[[ "$EUID" == 0 ]] || fail 'Run with sudo.'
[[ ! -e /var/ossec/etc/ossec.conf ]] || fail 'Wazuh/OSSEC is already configured.'
if command -v dpkg >/dev/null; then
    pm=apt
elif command -v rpm >/dev/null; then
    if command -v dnf >/dev/null; then pm=dnf
    elif command -v yum >/dev/null; then pm=yum
    else fail 'RPM systems need DNF or YUM.'; fi
else fail 'A DEB or RPM system is required.'; fi
if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then init=systemd
elif command -v service >/dev/null && { command -v update-rc.d >/dev/null || command -v chkconfig >/dev/null; }; then init=sysv
else fail 'systemd or SysV services are required.'; fi

# only ask for things we cannot safely guess
if [[ -z "$manager" ]]; then
    [[ -t 0 && "$yes" == no ]] || fail 'Supply --manager.'
    read -rp 'Manager IP/DNS: ' manager
fi
[[ "$manager" =~ ^[A-Za-z0-9:][A-Za-z0-9.:-]*$ ]] || fail 'Invalid manager address.'
[[ -z "$version" || "$version" =~ ^4\.[0-9]+\.[0-9]+$ ]] || fail 'Version must be 4.x.y.'
export WAZUH_MANAGER="$manager" WAZUH_REGISTRATION_SERVER="$manager"
export WAZUH_AGENT_NAME="$(hostname -s)" WAZUH_REGISTRATION_PASSWORD=''
[[ "$WAZUH_AGENT_NAME" =~ ^[A-Za-z0-9_.-]{2,128}$ ]] || fail 'Set a valid hostname first.'
if [[ -n "$password_file" ]]; then
    WAZUH_REGISTRATION_PASSWORD=$(cat -- "$password_file")
elif [[ "$yes" == no && -t 0 ]]; then
    read -rsp 'Enrollment password (Enter for none): ' WAZUH_REGISTRATION_PASSWORD; echo
fi
[[ -z "$version" ]] && echo 'Using latest agent; manager must be equally new. Use --version for older managers.'
echo "$WAZUH_AGENT_NAME -> $manager | TCP 1514/1515 | firewall: $firewall"
if [[ "$yes" == no ]]; then
    [[ -t 0 ]] || fail 'Use --yes for unattended installs.'
    read -rp 'Install and allow outbound traffic? (may reload firewalld) [y/N]: ' answer
    [[ "$answer" == [yY] || "$answer" == [yY][eE][sS] ]] || exit 0
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
trap 'echo "Install failed; check the error above." >&2' ERR

# the package uses the deployment variables above to set up the agent
if [[ "$pm" == apt ]]; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates gnupg
else
    "$pm" -q -y install curl ca-certificates gnupg2
fi
curl -fsSL --connect-timeout 15 --max-time 120 --retry 2 https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "$work/key"
if [[ "$pm" == apt ]]; then
    gpg --batch --dearmor < "$work/key" > "$work/key.gpg"
    install -m 0644 "$work/key.gpg" /usr/share/keyrings/wazuh-agent.gpg
    repo='deb [signed-by=/usr/share/keyrings/wazuh-agent.gpg] https://packages.wazuh.com/4.x/apt/ stable main'
    file=/etc/apt/sources.list.d/wazuh-agent.list
    printf '%s\n' "$repo" > "$work/repo"
    [[ ! -e "$file" ]] || cmp -s "$file" "$work/repo" || fail "Custom repo exists: $file"
    install -m 0644 "$work/repo" "$file"
    apt-get update -qq
    package=wazuh-agent
    [[ -z "$version" ]] || package="wazuh-agent=$version-*"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$package"
else
    rpm --import "$work/key"
    dir=/etc/yum.repos.d

    mkdir -p "$dir"
    printf '%s\n' '[wazuh-agent]' 'name=Wazuh agent' 'baseurl=https://packages.wazuh.com/4.x/yum/' 'enabled=1' 'gpgcheck=1' 'gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH' > "$work/repo"
    [[ ! -e "$dir/wazuh-agent.repo" ]] || cmp -s "$dir/wazuh-agent.repo" "$work/repo" || fail 'Custom Wazuh repo exists.'
    install -m 0644 "$work/repo" "$dir/wazuh-agent.repo"
    package=wazuh-agent
    [[ -z "$version" ]] || package="wazuh-agent-$version-*"
    "$pm" -q -y install "$package"
fi
unset WAZUH_REGISTRATION_PASSWORD

# agents connect out, so do not open inbound ports
if [[ "$firewall" == yes ]]; then
    mapfile -t ips < <(getent ahosts "$manager" | awk '{print $1}' | sort -u)
    (( ${#ips[@]} )) || fail 'Cannot resolve manager address.'
    if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
        for ip in "${ips[@]}"; do ufw allow out to "$ip" port 1514:1515 proto tcp; done
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        if firewall-cmd --permanent --get-policies >/dev/null 2>&1; then
            policy=wazuh-agent-egress
            firewall-cmd --permanent --get-policies | tr ' ' '\n' | grep -qx "$policy" || firewall-cmd --permanent --new-policy="$policy"
            firewall-cmd --permanent --policy="$policy" --set-priority=-500
            firewall-cmd --permanent --policy="$policy" --add-ingress-zone=HOST
            firewall-cmd --permanent --policy="$policy" --add-egress-zone=ANY
            for ip in "${ips[@]}"; do
                family=ipv4; [[ "$ip" != *:* ]] || family=ipv6
                firewall-cmd --permanent --policy="$policy" --add-rich-rule="rule family=\"$family\" destination address=\"$ip\" port port=\"1514-1515\" protocol=\"tcp\" accept"
            done
            firewall-cmd --reload
        else echo 'Older firewalld: outbound rules unchanged.'; fi
    elif command -v nft >/dev/null && [[ -n "$(nft list ruleset)" ]]; then
        echo 'Custom nftables: allow outbound TCP 1514/1515 to the manager if blocked.'
    elif command -v iptables >/dev/null; then
        for ip in "${ips[@]}"; do
            tool=iptables; [[ "$ip" != *:* ]] || tool=ip6tables
            "$tool" -C OUTPUT -d "$ip" -p tcp --dport 1514:1515 -j ACCEPT 2>/dev/null || "$tool" -I OUTPUT 1 -d "$ip" -p tcp --dport 1514:1515 -j ACCEPT
        done
        echo 'iptables rules added for this boot; persist with your firewall tooling.'
    fi
fi
/var/ossec/bin/wazuh-agentd -t
if [[ "$init" == systemd ]]; then
    systemctl daemon-reload
    systemctl enable --now wazuh-agent
else
    if command -v update-rc.d >/dev/null; then update-rc.d wazuh-agent defaults
    else chkconfig wazuh-agent on; fi
    service wazuh-agent restart
fi
# check the connection, not just whether the service started
for (( n=0; n<12; n++ )); do
    if grep -Eq "^status=['\"]?connected['\"]?$" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null; then
        echo "Connected: $WAZUH_AGENT_NAME -> $manager"; exit 0
    fi
    sleep 5
done
fail 'Installed, but not connected yet. Check /var/ossec/logs/ossec.log and manager-side ports/password/version.'
