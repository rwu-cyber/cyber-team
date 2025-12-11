#!/bin/bash

TARGET="/"
YARA_RULES="yara/rules"

echo "[*] Running high-value YARA scan..."
./yara/yara -r "$YARA_RULES" "$TARGET" \
    --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run \
    --exclude=/snap --exclude=/var/lib --exclude=/mnt --exclude=/media \
    2>/dev/null

echo ""
echo "Running LIGHT ClamAV scan (fast directories only)..."

FAST_DIRS=(
    /tmp
    /var/tmp
    /var/www
    /home
)

for DIR in "${FAST_DIRS[@]}"; do
    if [ -d "$DIR" ]; then
        echo "Scanning $DIR ..."
        # Just call the package-installed clamscan
        clamscan -r -i --no-summary "$DIR"
    fi
done

echo ""
echo "Scans complete."

