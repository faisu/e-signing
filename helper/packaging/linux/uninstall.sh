#!/bin/bash
# BridgeIt DSC Helper — Linux uninstall script
set -euo pipefail

systemctl --user stop bridgeit-helper 2>/dev/null || true
systemctl --user disable bridgeit-helper 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/bridgeit-helper.service"
systemctl --user daemon-reload

if command -v sudo &>/dev/null; then
  sudo rm -f /usr/local/bin/bridgeit-helper
else
  rm -f /usr/local/bin/bridgeit-helper
fi

echo "BridgeIt DSC Helper uninstalled."
