#!/bin/bash
# BridgeIt DSC Helper — macOS postinstall script
# Called by the .pkg installer after files are placed.
# Installs the LaunchAgent for the current user and starts the helper.
set -euo pipefail

BINARY_SRC="/Library/BridgeIt/bridgeit-helper"
BINARY_DST="/usr/local/bin/bridgeit-helper"
PLIST_SRC="/Library/BridgeIt/com.bridgeit.helper.plist"
PLIST_DST="$HOME/Library/LaunchAgents/com.bridgeit.helper.plist"

# Copy binary
install -m 755 "$BINARY_SRC" "$BINARY_DST"

# Install LaunchAgent (per-user so it has access to ~/. and USB devices)
mkdir -p "$HOME/Library/LaunchAgents"
cp "$PLIST_SRC" "$PLIST_DST"

# Load (bootstrap) the agent — starts it immediately, also on future logins
launchctl bootstrap "gui/$(id -u)" "$PLIST_DST" 2>/dev/null || true

echo "BridgeIt DSC Helper installed."
echo "Next: visit https://127.0.0.1:7777/version in your browser and trust the certificate."
