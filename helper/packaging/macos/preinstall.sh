#!/bin/bash
# BridgeIt DSC Helper — macOS preinstall script
# Stops any running instance before replacing the binary.
set -euo pipefail

PLIST_DST="$HOME/Library/LaunchAgents/com.bridgeit.helper.plist"

if launchctl list com.bridgeit.helper &>/dev/null; then
  launchctl bootout "gui/$(id -u)" "$PLIST_DST" 2>/dev/null || true
fi

exit 0
