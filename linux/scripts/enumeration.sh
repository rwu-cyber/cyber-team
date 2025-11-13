#!/bin/bash
####################################
####### Written By Ryan Deyo #######
####################################

# Colors
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
BOLD='\e[1m'
END_COLOR='\e[0m'

# Function to display a colored divider
divider() {
    local color=$1
    local label=$2
    echo -e "\n${color}${BOLD}===============================================================${END_COLOR}"
    echo -e "${color}${BOLD}  ${label}${END_COLOR}"
    echo -e "${color}${BOLD}===============================================================${END_COLOR}"
}

# Function to display labeled output with color
# Usage: label "Label:" "value" "$COLOR"
label() {
    local text=$1
    local value=$2
    local color=${3:-$END_COLOR}
    echo -e "${BOLD}${text}${END_COLOR} ${color}${value}${END_COLOR}"
}

# Function to highlight suspicious items
highlight() {
    local color=$1
    local text=$2
    echo -e "${color}${BOLD}[!]${END_COLOR} ${color}${text}${END_COLOR}"
}

####################### Basic System Information #######################
divider "$CYAN" "Basic System Information"
label "Hostname:" "$(hostname)" "$GREEN"
label "Distro:" "$(grep -E -m 1 "^(PRETTY_NAME|NAME|ID)=" /etc/os-release | cut -d= -f2 | tr -d '"')" "$GREEN"
label "Uptime:" "$(uptime -p)" "$GREEN"
label "Kernel:" "$(uname -r)" "$GREEN"
label "Architecture:" "$(arch)" "$GREEN"

####################### User Accounts #######################
divider "$CYAN" "User Accounts Analysis"

echo -e "\n${BOLD}Users with /bin/bash shell:${END_COLOR}"
while IFS=: read -r username _ uid _ _ home shell; do
    if [[ "$shell" == "/bin/bash" ]]; then
        if [[ $uid -lt 1000 && $uid -ne 0 ]]; then
            highlight "$YELLOW" "$username (UID: $uid) - System user with bash shell"
        elif [[ $uid -eq 0 ]]; then
            echo -e "  ${GREEN}$username${END_COLOR} (UID: $uid) - Root"
        else
            echo -e "  ${GREEN}$username${END_COLOR} (UID: $uid)"
        fi
    fi
done < /etc/passwd

echo -e "\n${BOLD}All user accounts:${END_COLOR}"
cat /etc/passwd

echo -e "\n${BOLD}Sudo group members:${END_COLOR}"
if getent group sudo >/dev/null 2>&1; then
    getent group sudo | cut -d: -f4 | tr ',' '\n' | sed 's/^/  /' | while read -r user; do
        echo -e "${GREEN}${user}${END_COLOR}"
    done
else
    echo "  No sudo group found"
fi

####################### SSH Configuration & Keys #######################
divider "$CYAN" "SSH Configuration & Authorized Keys"

echo -e "\n${BOLD}Critical SSHD settings:${END_COLOR}"
if [[ -f /etc/ssh/sshd_config ]]; then
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        
        # Highlight security-relevant settings
        if echo "$line" | grep -qiE "(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding)"; then
            if echo "$line" | grep -qiE "(PermitRootLogin yes|PermitEmptyPasswords yes)"; then
                highlight "$RED" "$line"
            elif echo "$line" | grep -qiE "(PermitRootLogin no|PasswordAuthentication no|PubkeyAuthentication yes)"; then
                echo -e "  ${GREEN}$line${END_COLOR}"
            else
                echo -e "  ${YELLOW}$line${END_COLOR}"
            fi
        fi
    done < /etc/ssh/sshd_config
else
    echo "  ${RED}SSHD config not found${END_COLOR}"
fi

echo -e "\n${BOLD}Authorized SSH keys:${END_COLOR}"
found_keys=false
for home_dir in $(getent passwd | cut -d: -f6 | sort -u); do
    if [[ -d "$home_dir" ]]; then
        auth_keys="$home_dir/.ssh/authorized_keys"
        if [[ -s "$auth_keys" ]]; then
            found_keys=true
            username=$(getent passwd | grep ":$home_dir:" | cut -d: -f1 | head -1)
            echo -e "\n  ${MAGENTA}${username}${END_COLOR} (${home_dir}):"
            
            key_count=$(wc -l < "$auth_keys")
            echo -e "    Keys found: ${YELLOW}${key_count}${END_COLOR}"
            
            while read -r key; do
                [[ -z "$key" ]] && continue
                key_type=$(echo "$key" | awk '{print $1}')
                key_comment=$(echo "$key" | awk '{print $NF}')
                echo -e "      ${CYAN}${key_type}${END_COLOR} - ${key_comment}"
            done < "$auth_keys"
        fi
    fi
done
if ! $found_keys; then
    echo "  ${GREEN}No authorized_keys files found${END_COLOR}"
fi

####################### Network Information #######################
divider "$CYAN" "Network Configuration"
echo -e "\n${BOLD}Network interfaces:${END_COLOR}"
ip -br -c addr

echo -e "\n${BOLD}Listening services:${END_COLOR}"
if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | awk 'NR==1 {print "  " $0; next} {printf "  %-10s %-30s %s\n", $1, $4, $NF}'
else
    netstat -tlnp 2>/dev/null | grep LISTEN | awk '{printf "  %-10s %-30s %s\n", $1, $4, $NF}'
fi
