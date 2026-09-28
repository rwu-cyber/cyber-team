#!/bin/sh
set -e
# Created For Roger Williams Cybersecurity Team

# get absolute path of the script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="/"

# configure yara 
YARA_DIR="$SCRIPT_DIR/yara"
YARA_BIN="$YARA_DIR/yara"
YARA_RULES="$YARA_DIR/rules/Cobalt_Strike_and_sliver.yara"

# clamav singatures
CLAMAV_SIG_DIR="$SCRIPT_DIR/clamav/signatures"

# log directories
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
mkdir -p "$CLAMAV_SIG_DIR"

# install ClamAV if missing
install_clamav() {
    if ! command -v clamscan >/dev/null 2>&1; then
        printf '%s\n' "ClamAV binary not found. Attempting install..."
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "$ID" in
                ubuntu|debian|pop|kali)
                    sudo apt update && sudo apt install -y clamav clamav-daemon ;;
                arch|manjaro)
                    sudo pacman -Sy --noconfirm clamav ;;
                fedora|centos|rhel)
                    sudo dnf install -y clamav ;;
                *)
                    printf '%s\n' "Unsupported distro. Install ClamAV manually." ;;
            esac
        fi
    else
        printf '%s\n' "ClamAV is already installed."
    fi
}

# update signatures 
update_signatures() {
    # check if we have valid local files (approx > 50MB)
    if [ -s "$CLAMAV_SIG_DIR/main.cvd" ] || [ -s "$CLAMAV_SIG_DIR/main.cld" ]; then
        SIZE=$(stat -c%s "$CLAMAV_SIG_DIR/main.cvd" 2>/dev/null || stat -c%s "$CLAMAV_SIG_DIR/main.cld" 2>/dev/null)
        if [ "$SIZE" -gt 50000000 ]; then
            printf '%s\n' "Valid local signatures detected. Skipping update."
            return
        fi
    fi

    printf '%s\n' "Local signatures missing or corrupt."
    
    if ping -c 1 database.clamav.net >/dev/null 2>&1; then
        printf '%s\n' "Internet detected. Updating via freshclam..."
        sudo systemctl stop clamav-freshclam 2>/dev/null || true
        if sudo freshclam; then
            printf '%s\n' "Freshclam update successful."
            printf '%s\n' "Copying signatures to local repo for portability..."
            cp /var/lib/clamav/*.cvd "$CLAMAV_SIG_DIR/" 2>/dev/null || true
            cp /var/lib/clamav/*.cld "$CLAMAV_SIG_DIR/" 2>/dev/null || true
        else
            printf '%s\n' "Freshclam failed. System may be rate-limited."
        fi
    else
        printf '%s\n' "No internet connection. Cannot update signatures."
    fi
}

# run YARA
run_yara() {
    printf '%s\n' "Running YARA scan..."
    chmod +x "$YARA_BIN" 2>/dev/null

    if [ -f "$YARA_RULES" ]; then
        "$YARA_BIN" -r "$YARA_RULES" "$TARGET" \
            --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run \
            --exclude=/snap --exclude=/var/lib --exclude=/mnt --exclude=/media \
            2>/dev/null | tee "$LOG_DIR/yara_$(date +%H%M%S).txt" || true
    else
        printf '%s\n' "YARA Rule file not found at: $YARA_RULES"
    fi
}

# run ClamAV
FAST_DIRS="/tmp /var/tmp /var/www /home /boot /etc"

run_clamav() {
    printf '%s\n' "Running ClamAV scan..."
    LOGFILE="$LOG_DIR/clamav_$(date +%H%M%S).txt"
    
    DB_FLAG=""
    if [ -s "$CLAMAV_SIG_DIR/main.cvd" ] || [ -s "$CLAMAV_SIG_DIR/main.cld" ]; then
        printf '%s\n' "Using LOCAL signatures from $CLAMAV_SIG_DIR"
        DB_FLAG="--database=$CLAMAV_SIG_DIR"
    else
        printf '%s\n' "Using SYSTEM signatures (Fallback)"
    fi

    for DIR in $FAST_DIRS; do
        if [ -d "$DIR" ]; then
            printf '%s\n' "Scanning $DIR ..."
            clamscan -r -i --no-summary $DB_FLAG "$DIR" | tee -a "$LOGFILE" || true
        fi
    done
}

# MAIN
install_clamav
update_signatures
run_yara
run_clamav

printf '%s\n' "Scans complete. Logs saved to $LOG_DIR."

