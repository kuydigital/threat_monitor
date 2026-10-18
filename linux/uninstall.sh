#!/usr/bin/env bash
# Removes the Threat Monitor screensaver for Linux (the packages it installed are left in place).
# Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run it with sudo:  sudo $0" >&2; exit 1; }

pkill -f "threat-monitor-screensaver session" 2>/dev/null || true
pkill -f "/opt/threat-monitor/threat_screensaver.py" 2>/dev/null || true
rm -f /usr/local/bin/threat-monitor-screensaver /etc/xdg/autostart/threat-monitor-screensaver.desktop \
      /etc/threat-monitor-screensaver.conf
rm -rf /opt/threat-monitor
echo "Removed. Saved scores and the log stay in ~/.local/share/threat-monitor (delete it if you like)."
echo "Screen blanking goes back to the system default at the next desktop login."
