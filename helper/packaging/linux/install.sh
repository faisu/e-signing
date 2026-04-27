#!/bin/bash
# BridgeIt DSC Helper — Linux install script
# Installs the binary and registers a systemd user service (no root needed).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_SRC="$SCRIPT_DIR/bridgeit-helper-linux"
BINARY_DST="/usr/local/bin/bridgeit-helper"
SERVICE_SRC="$SCRIPT_DIR/bridgeit-helper.service"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

echo "Installing BridgeIt DSC Helper..."

# Install binary (requires write access to /usr/local/bin — use sudo if needed)
if [ -w /usr/local/bin ]; then
  install -m 755 "$BINARY_SRC" "$BINARY_DST"
else
  sudo install -m 755 "$BINARY_SRC" "$BINARY_DST"
fi

# Install systemd user service
mkdir -p "$SYSTEMD_USER_DIR"
cp "$SERVICE_SRC" "$SYSTEMD_USER_DIR/bridgeit-helper.service"

systemctl --user daemon-reload
systemctl --user enable bridgeit-helper
systemctl --user start bridgeit-helper

# Enable lingering so the service starts even without a GUI login (e.g. SSH sessions)
loginctl enable-linger "$USER" 2>/dev/null || true

echo
echo "BridgeIt DSC Helper is running."
echo "Check status : systemctl --user status bridgeit-helper"
echo "View logs    : journalctl --user -u bridgeit-helper -f"
echo
echo "Next: visit https://127.0.0.1:7777/version in your browser and trust the certificate."
