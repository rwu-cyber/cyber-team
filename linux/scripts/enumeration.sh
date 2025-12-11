#!/bin/bash
###################################################################
################## RWU NECCDC Enumeration Script ##################
####### Supports: Fedora, Ubuntu, Debian, CentOS, RHEL  ###########
###################################################################

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

####################### OS & Distro Detection #######################
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="unknown"
fi

divider "$CYAN" "Basic System Information"
label "Hostname:" "$(hostname)" "$GREEN"
label "Distro ID:" "$DISTRO" "$GREEN"
label "Pretty Name:" "${PRETTY_NAME:-Unknown}" "$GREEN"
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

echo -e "\n${BOLD}Privileged Group Check (Distro Specific):${END_COLOR}"

# CASE STATEMENT: Check specific groups based on Distro
case "$DISTRO" in
    fedora|centos|rhel)
        TARGET_GROUP="wheel"
        echo -e "  Detected Fedora/RHEL-based system. Checking group: ${BLUE}$TARGET_GROUP${END_COLOR}"
        ;;
    ubuntu|debian|kali|linuxmint)
        TARGET_GROUP="sudo"
        echo -e "  Detected Debian/Ubuntu-based system. Checking group: ${BLUE}$TARGET_GROUP${END_COLOR}"
        ;;
    *)
        TARGET_GROUP="sudo"
        echo -e "  ${YELLOW}Unknown distro. Defaulting to group: sudo${END_COLOR}"
        ;;
esac

if getent group "$TARGET_GROUP" >/dev/null 2>&1; then
    getent group "$TARGET_GROUP" | cut -d: -f4 | tr ',' '\n' | while read -r user; do
        [[ -n "$user" ]] && echo -e "    ${GREEN}${user}${END_COLOR} is in $TARGET_GROUP"
    done
else
    highlight "$YELLOW" "Group '$TARGET_GROUP' not found or empty."
fi

####################### SSH Configuration & Keys #######################
divider "$CYAN" "SSH Configuration & Authorized Keys"

echo -e "\n${BOLD}Critical SSHD settings:${END_COLOR}"
SSH_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONFIG" ]]; then
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        
        if echo "$line" | grep -qiE "(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding)"; then
            if echo "$line" | grep -qiE "(PermitRootLogin yes|PermitEmptyPasswords yes)"; then
                highlight "$RED" "$line"
            elif echo "$line" | grep -qiE "(PermitRootLogin no|PasswordAuthentication no|PubkeyAuthentication yes)"; then
                echo -e "  ${GREEN}$line${END_COLOR}"
            else
                echo -e "  ${YELLOW}$line${END_COLOR}"
            fi
        fi
    done < "$SSH_CONFIG"
else
    echo "  ${RED}SSHD config not found${END_COLOR}"
fi

echo -e "\n${BOLD}Active SSH Sessions (PID):${END_COLOR}"
ssh_sessions=$(ps -eo pid,user,args | grep "sshd: " | grep "@" | grep -v grep)
if [[ -n "$ssh_sessions" ]]; then
    printf "  %-10s %-15s %-30s\n" "PID" "USER" "CONNECTION"
    echo "$ssh_sessions" | while read -r pid user args; do
        connection=$(echo "$args" | sed 's/sshd: //')
        printf "  ${YELLOW}%-10s${END_COLOR} ${GREEN}%-15s${END_COLOR} %-30s\n" "$pid" "$user" "$connection"
    done
else
    echo -e "  ${GREEN}No active SSH sessions found${END_COLOR}"
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
        fi
    fi
done
if ! $found_keys; then
    echo "  ${GREEN}No authorized_keys files found${END_COLOR}"
fi

####################### File Permissions #######################
divider "$CYAN" "File System & Permissions"

echo -e "\n${BOLD}SUID Binaries (Potential Privilege Escalation):${END_COLOR}"
suid_files=$(find / -perm -4000 -type f 2>/dev/null)
if [[ -n "$suid_files" ]]; then
    echo "$suid_files" | while read -r file; do
        if echo "$file" | grep -qE "(nmap|vim|find|bash|cp|more|less|nano|awk|tar|python|perl|ruby)"; then
             highlight "$RED" "$file"
        else
             echo -e "  ${YELLOW}$file${END_COLOR}"
        fi
    done
else
    echo -e "  ${GREEN}No SUID files found (Rare)${END_COLOR}"
fi

echo -e "\n${BOLD}World Writable Directories (Sticky bit set - Top 10):${END_COLOR}"
find / -type d -perm -0002 -a ! -perm -1000 -ls 2>/dev/null | head -n 10 | awk '{print "  " $NF}'

####################### Scheduled Tasks #######################
divider "$CYAN" "Scheduled Tasks (Cron & Timers)"

echo -e "\n${BOLD}System Crontab (/etc/crontab):${END_COLOR}"
if [[ -f /etc/crontab ]]; then
    grep -v "^#" /etc/crontab | grep -v "^$" | sed 's/^/  /'
fi

echo -e "\n${BOLD}Cron Directories (Non-empty):${END_COLOR}"
for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
    if [[ -d "$cron_dir" ]] && [[ -n "$(ls -A $cron_dir 2>/dev/null)" ]]; then
         echo -e "  ${GREEN}$cron_dir${END_COLOR} contains scripts/jobs"
    fi
done

echo -e "\n${BOLD}Systemd Timers (Active):${END_COLOR}"
if command -v systemctl >/dev/null; then
    systemctl list-timers --all --no-pager | head -n -1 | awk 'NR>1 {print "  " $1, $NF}' | head -10
fi

####################### Firewall Security #######################
divider "$CYAN" "Firewall Configuration"

# CASE STATEMENT: Firewall check
case "$DISTRO" in
    ubuntu|debian|kali|linuxmint)
        echo -e "\n${BOLD}Checking UFW (Debian/Ubuntu Standard):${END_COLOR}"
        if command -v ufw >/dev/null; then
            ufw_status=$(sudo ufw status | head -1 2>/dev/null)
            if [[ "$ufw_status" == *"active"* ]]; then
                echo -e "  ${GREEN}$ufw_status${END_COLOR}"
            else
                highlight "$RED" "UFW is INACTIVE"
            fi
        else
            echo "  UFW not installed."
        fi
        ;;
        
    fedora|centos|rhel)
        echo -e "\n${BOLD}Checking Firewalld (Fedora/RHEL Standard):${END_COLOR}"
        if command -v firewall-cmd >/dev/null; then
            if systemctl is-active --quiet firewalld; then
                echo -e "  ${GREEN}Firewalld is Active${END_COLOR}"
                echo -e "  Zones: $(firewall-cmd --get-active-zones 2>/dev/null | xargs)"
            else
                highlight "$RED" "Firewalld is INACTIVE"
            fi
        else
            echo "  Firewalld not installed."
        fi
        ;;
        
    *)
        echo -e "  ${YELLOW}Distro '$DISTRO' not specific. Checking for standard tools...${END_COLOR}"
        if command -v ufw >/dev/null; then echo "  Found UFW"; fi
        if command -v firewall-cmd >/dev/null; then echo "  Found Firewalld"; fi
        ;;
esac

echo -e "\n${BOLD}Iptables Rules Count:${END_COLOR}"
if command -v iptables >/dev/null && sudo -n iptables -L 2>/dev/null >/dev/null; then
    rule_count=$(sudo iptables -L -n | grep -c "^[A-Z]")
    echo -e "  Total Rules: ${CYAN}$rule_count${END_COLOR}"
else
    echo -e "  ${YELLOW}Cannot read iptables (permission denied or not found)${END_COLOR}"
fi

####################### History Analysis #######################
divider "$CYAN" "History Analysis & Activity"

KEYWORDS="pass|pwd|ssh|key|token|cred|nano|vim|chmod|chown|wget|curl|nc|nmap|base64"

# 1. SCAN RUNNING PROCESSES (The "In-Memory" Workaround)
echo -e "\n${BOLD}Scanning Active Processes (Live Memory):${END_COLOR}"
# This finds commands that are currently running but not yet saved to history
suspicious_procs=$(ps -eo user,pid,lstart,cmd | grep -v "\[.*\]" | grep -iE "$KEYWORDS" | grep -v -E "grep|ps -eo|history_analysis")

if [[ -n "$suspicious_procs" ]]; then
    echo "$suspicious_procs" | while read -r proc_line; do
        highlight "$RED" "Active Suspicious Process: $proc_line"
    done
else
    echo -e "  ${GREEN}No suspicious active processes found matching keywords.${END_COLOR}"
fi

# 2. CHECK FOR HISTORY TAMPERING (Anti-Forensics)
echo -e "\n${BOLD}Checking for History Tampering:${END_COLOR}"
HISTORY_PATHS="/home/*/.bash_history /home/*/.zsh_history /root/.bash_history /root/.zsh_history"

for history_file in $HISTORY_PATHS; do
    if [[ -e "$history_file" || -L "$history_file" ]]; then
        # Check if symlinked to /dev/null
        if [[ -L "$history_file" && "$(readlink "$history_file")" == "/dev/null" ]]; then
             highlight "$RED" "TAMPERING DETECTED: $history_file is linked to /dev/null!"
             continue
        fi
        # Check if empty
        if [[ ! -s "$history_file" ]]; then
             echo -e "  ${YELLOW}Empty History File: $history_file (Suspicious if user is active)${END_COLOR}"
             continue
        fi
    fi
done

# 3. SCAN HISTORY FILES ON DISK
echo -e "\n${BOLD}Scanning History Files on Disk:${END_COLOR}"
echo -e "${YELLOW}NOTE: Run 'history -a' before this script to include your own recent commands.${END_COLOR}"

for history_file in $HISTORY_PATHS; do
    if [[ -f "$history_file" && -s "$history_file" ]]; then
        echo -e "${MAGENTA}File: $history_file${END_COLOR}"
        matches=$(tac "$history_file" 2>/dev/null | grep -iE "$KEYWORDS" | head -20)
        if [[ -n "$matches" ]]; then
            IFS=$'\n'
            for match in $matches; do
                clean_match=$(echo "$match" | sed 's/^#[0-9]* //')
                highlight "$RED" "Found: ${clean_match:0:150}"
            done
            unset IFS
        else
            echo -e "    ${GREEN}No suspicious keywords found in recent history${END_COLOR}"
        fi
    fi
done

####################### Software Audit #######################
divider "$CYAN" "Software & Binaries Audit"

echo -e "\n${BOLD}Compilers & Dev Tools:${END_COLOR}"
for tool in gcc g++ make python3 ruby nmap nc netcat; do
    if command -v "$tool" >/dev/null; then
        if [[ "$tool" == "nmap" || "$tool" == "nc" || "$tool" == "netcat" ]]; then
             highlight "$RED" "Found Security Tool: $tool"
        else
             echo -e "  ${YELLOW}Found: $tool${END_COLOR}"
        fi
    fi
done

echo -e "\n${BOLD}Package Manager Audit (${DISTRO}):${END_COLOR}"

# CASE STATEMENT: Package Manager
case "$DISTRO" in
    ubuntu|debian|kali|linuxmint)
        echo -e "  Using ${BLUE}APT/DPKG${END_COLOR} to check for hacking tools..."
        if command -v dpkg >/dev/null; then
            dpkg -l | grep -E "nmap|netcat|wireshark|tcpdump|john|hydra|metasploit" | awk '{print "    " $2 " - " $3}'
        fi
        ;;
        
    fedora|centos|rhel)
        echo -e "  Using ${BLUE}RPM/DNF${END_COLOR} to check for hacking tools..."
        if command -v rpm >/dev/null; then
            rpm -qa | grep -E "nmap|netcat|wireshark|tcpdump|john|hydra" | sed 's/^/    /'
        fi
        ;;
        
    *)
        echo "  Unknown package manager for distro: $DISTRO"
        ;;
esac

####################### Network Information #######################
divider "$CYAN" "Network Configuration"
ip -br -c addr

echo -e "\n${BOLD}Listening services:${END_COLOR}"
if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | grep LISTEN | head -10 | awk '{printf "  %-10s %-20s %s\n", $1, $4, $NF}'
elif command -v netstat &>/dev/null; then
    netstat -tlnp 2>/dev/null | grep LISTEN | head -10 | awk '{printf "  %-10s %-20s %s\n", $1, $4, $NF}'
else
    echo "  Neither ss nor netstat found."
fi