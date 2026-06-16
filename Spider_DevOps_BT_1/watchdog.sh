#!/bin/bash

TARGET=$1

OUTPUT=$(./vault_sweep.sh "$TARGET")

echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "\[WARN\]"; then
    notify-send "Vault Sweep Alert" "Dangerous scripts detected!"
fi