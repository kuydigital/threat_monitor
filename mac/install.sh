#!/bin/bash
# Installs the Threat Monitor screensaver for the current user (macOS 12+):
#   curl -fsSL https://raw.githubusercontent.com/kuydigital/threat_monitor/main/mac/install.sh | bash
# Downloads the latest release, puts "Threat Monitor.saver" in
# ~/Library/Screen Savers and opens the Screen Saver settings.
# Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
set -euo pipefail

URL="https://github.com/kuydigital/threat_monitor/releases/latest/download/ThreatMonitor-macOS.zip"
DEST="$HOME/Library/Screen Savers"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading Threat Monitor..."
curl -fL --progress-bar -o "$TMP/ThreatMonitor-macOS.zip" "$URL"
ditto -x -k "$TMP/ThreatMonitor-macOS.zip" "$TMP/unzipped"
SAVER="$(find "$TMP/unzipped" -maxdepth 3 -name 'Threat Monitor.saver' -type d | head -n 1)"
if [ -z "$SAVER" ]; then
  echo "The download did not contain Threat Monitor.saver." >&2
  exit 1
fi

mkdir -p "$DEST"
rm -rf "$DEST/Threat Monitor.saver"
ditto "$SAVER" "$DEST/Threat Monitor.saver"
xattr -dr com.apple.quarantine "$DEST/Threat Monitor.saver" 2>/dev/null || true
# An older version may still be loaded; macOS starts the screensaver again when needed.
killall legacyScreenSaver 2>/dev/null || true
echo "Installed: $DEST/Threat Monitor.saver"

open "x-apple.systempreferences:com.apple.ScreenSaver-Settings.extension" 2>/dev/null \
  || open -b com.apple.systempreferences /System/Library/PreferencePanes/DesktopScreenEffectsPref.prefPane 2>/dev/null \
  || true
echo "Now pick Threat Monitor in the Screen Saver settings."
