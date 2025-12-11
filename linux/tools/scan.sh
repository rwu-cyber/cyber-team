#!/bin/bash
set -e

#######################################
# CONFIGURATION
#######################################
TARGET="/"
YARA_DIR="./yara"
YARA_RULES="$YARA_DIR/rules"
CLAMAV_SIG_DIR="./clamav/signatures"
FAST_DIRS=(/tmp /var/tmp /var/www /home)
LOG_DIR="./logs"

mkdir -p "$LOG_DIR"
mkdir -p "$CLAMAV_SIG_DIR"

#######################################
# HELPER: Check / Install ClamAV
#######################################
install_clamav() {
    if ! command -v clamscan &> /dev/null; then
        echo "[*] ClamAV not found. Installing..."
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "$ID" in
                ubuntu|debian|pop|linuxmint)
                    sudo apt update && sudo apt install -y clamav clamav-daemon
                    ;;
                arch|manjaro)
                    sudo pacman -Sy --noconfirm clamav
                    ;;
                fedora)
                    sudo dnf install -y clamav clamav-update
                    ;;
                rhel|centos|almalinux|rocky)
                    sudo yum install -y epel-release
                    sudo yum install -y clamav clamav-update
                    ;;
                opensuse*)
                    sudo zypper install -y clamav
                    ;;
                *)
                    echo "[-] Unsupported distro. Please install ClamAV manually."
                    exit 1
                    ;;
            esac
        fi
    fi
}

#######################################
# HELPER: Download ClamAV signatures if missing
#######################################
download_signatures() {
    BASE_URL="https://database.clamav.net"
    FILES=("main.cvd" "daily.cvd" "bytecode.cvd")

    for FILE in "${FILES[@]}"; do
        if [ ! -f "$CLAMAV_SIG_DIR/$FILE" ]; then
            echo "[*] Downloading $FILE ..."
            wget -q -O "$CLAMAV_SIG_DIR/$FILE" "$BASE_URL/$FILE"
        fi
    done
}

#######################################
# RUN YARA
#######################################
run_yara() {
    echo "[*] Running high-value YARA scan..."
    "$YARA_DIR/yara" -r "$YARA_RULES" "$TARGET" \
        --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run \
        --exclude=/snap --exclude=/var/lib --exclude=/mnt --exclude=/media \
        2>/dev/null | tee "$LOG_DIR/yara_$(date +%H%M%S).txt"
}

#######################################
# RUN CLAMAV
#######################################
run_clamav() {
    echo ""
    echo "[*] Running LIGHT ClamAV scan..."
    for DIR in "${FAST_DIRS[@]}"; do
        if [ -d "$DIR" ]; then
            echo "[+] Scanning $DIR ..."
            clamscan -r -i --no-summary --database="$CLAMAV_SIG_DIR" "$DIR" \
                | tee -a "$LOG_DIR/clamav_$(date +%H%M%S).txt"
        fi
    done
}

#######################################
# MAIN
#######################################
install_clamav
download_signatures
run_yara
run_clamav

echo ""
echo "[+] Scans complete."
echo "[+] Logs saved in $LOG_DIR"

