#!/bin/bash

TARGET=$1
LOGFILE="output/vault_sweep.log"

mkdir -p output
touch "$LOGFILE"
chmod 600 "$LOGFILE"

timestamp() {
    date "+[%Y-%m-%d %H:%M:%S]"
}

log() {
    echo "$(timestamp) $1" >> "$LOGFILE"
}

warn_file() {
    file=$1
    reason=$2

    echo "[WARN] $file - Reason: $reason"
    log "[WARN] $file $reason"
}

fix_perm() {
    file=$1

    read -p "Fix permissions for $file? (yes/no): " ans
    if [[ "$ans" == "yes" ]]; then
        chmod o-w "$file"
        log "[FIX] $file removed world write permission"
    fi
}

echo "Scanning shell scripts..."

find "$TARGET" -type f -name "*.sh" | while read -r file; do

    # permissions check
    perm=$(stat -c "%a" "$file")
    if [[ $((perm % 10)) -ge 2 ]]; then
        warn_file "$file" "World writable permissions"
        fix_perm "$file"
    fi

    # destructive commands
    if grep -qE "rm -rf|mkfs|shutdown|reboot" "$file"; then
        warn_file "$file" "Destructive command detected"
    fi

    # curl/wget pipe
    if grep -qE "curl.*\|.*(sh|bash)|wget.*\|.*(sh|bash)" "$file"; then
        warn_file "$file" "Suspicious remote execution"
    fi

    # reverse shell
    if grep -q "/dev/tcp/" "$file"; then
        warn_file "$file" "Reverse shell detected"
    fi

done

echo "Scanning env files..."

find "$TARGET" -type f -name ".env*" | while read -r file; do

    valid_count=0
    invalid_count=0
    rejected=""

    out="${file}.sanitized"
    > "$out"

    while IFS= read -r line; do

        if [[ $line =~ ^[A-Z_][A-Z0-9_]*=[^[:space:]\"\'=]+$ ]] && \
           ! [[ $line =~ PASSWORD|SECRET|TOKEN|PATH ]]; then
            echo "$line" >> "$out"
            ((valid_count++))
        else
            rejected+="$line\n"
            ((invalid_count++))
        fi

    done < "$file"

    log "[INFO] $file Valid: $valid_count Invalid: $invalid_count"
    log "[SKIP] $file Rejected: $(echo -e "$rejected" | tr '\n' ',')"

done

echo "Scan complete."