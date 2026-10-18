#!/usr/bin/env bash
# Installs the Threat Monitor screensaver on a Linux desktop (Raspberry Pi OS, Debian, Ubuntu).
# Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
#
#   From a copy of this repository:   sudo linux/install.sh
#   Straight from GitHub:             curl -fsSL https://raw.githubusercontent.com/kuydigital/threat_monitor/main/linux/install.sh | sudo bash
#
# Running it again updates it and keeps your settings. Remove it with linux/uninstall.sh.
set -euo pipefail

RAW=https://raw.githubusercontent.com/kuydigital/threat_monitor/main
APP_DIR=/opt/threat-monitor
FILES=(threat_monitor.py threat_screensaver.py LICENSE linux/threat-monitor-screensaver
       linux/threat-monitor-screensaver.conf linux/threat-monitor-screensaver.desktop linux/uninstall.sh)

[ "$(id -u)" -eq 0 ] || { echo "Run it with sudo:  sudo $0" >&2; exit 1; }
USER_NAME="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
command -v apt-get >/dev/null || { echo "This installer needs apt (Raspberry Pi OS, Debian or Ubuntu)." >&2; exit 1; }

echo "== Packages"
pkgs=(python3 python3-pygame python3-requests xprintidle x11-xserver-utils x11-utils curl)
if command -v labwc >/dev/null || command -v wayfire >/dev/null || [ -n "${WAYLAND_DISPLAY:-}" ]; then
    pkgs+=(swayidle)
    apt-cache show wlopm >/dev/null 2>&1 && pkgs+=(wlopm)
fi
missing=()
for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
if [ ${#missing[@]} -gt 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
    echo "   installed: ${missing[*]}"
else
    echo "   all present"
fi

echo "== Files"
# Use this copy of the repository when there is one, otherwise download the latest from GitHub
SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")/.." 2>/dev/null && pwd)"
if [ ! -f "$SRC/threat_screensaver.py" ] || [ ! -f "$SRC/linux/threat-monitor-screensaver" ]; then
    SRC=$(mktemp -d)
    trap 'rm -rf "$SRC"' EXIT
    echo "   downloading from github.com/kuydigital/threat_monitor"
    for f in "${FILES[@]}"; do
        mkdir -p "$SRC/$(dirname "$f")"
        curl -fsSL "$RAW/$f" -o "$SRC/$f"
    done
fi
install -d "$APP_DIR"
install -m 644 "$SRC/threat_monitor.py" "$SRC/threat_screensaver.py" "$SRC/LICENSE" "$APP_DIR/"
install -m 755 "$SRC/linux/uninstall.sh" "$APP_DIR/uninstall.sh"
install -m 755 "$SRC/linux/threat-monitor-screensaver" /usr/local/bin/threat-monitor-screensaver
install -m 644 "$SRC/linux/threat-monitor-screensaver.desktop" /etc/xdg/autostart/threat-monitor-screensaver.desktop
if [ -e /etc/threat-monitor-screensaver.conf ]; then
    echo "   kept your settings in /etc/threat-monitor-screensaver.conf"
else
    install -m 644 "$SRC/linux/threat-monitor-screensaver.conf" /etc/threat-monitor-screensaver.conf
fi
echo "   $APP_DIR (the Threat Monitor itself, and uninstall.sh)"
echo "   /usr/local/bin/threat-monitor-screensaver"
echo "   /etc/xdg/autostart/threat-monitor-screensaver.desktop (starts it at every desktop login)"
echo "   /etc/threat-monitor-screensaver.conf (settings)"

echo "== Self-test"
if PYGAME_HIDE_SUPPORT_PROMPT=1 python3 "$APP_DIR/threat_screensaver.py" --selftest; then
    echo "   every screen draws correctly"
else
    echo "   self-test failed - see selftest.log in $(pwd)" >&2
    exit 1
fi

echo "== Starting it on the open desktop(s)"
# Restart any copy from an earlier install, then start one per desktop this user has open,
# using the display settings of that desktop's own session process
pkill -u "$USER_NAME" -f "threat-monitor-screensaver session" 2>/dev/null || true
started=0 seen=" "
for pid in $(pgrep -u "$USER_NAME" -x "lxsession|labwc|wayfire|gnome-session-b|xfce4-session|mate-session" || true); do
    envs=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null |
           grep -E '^(DISPLAY|XAUTHORITY|WAYLAND_DISPLAY|XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS)=' || true)
    key=$(echo "$envs" | grep -E '^(DISPLAY|WAYLAND_DISPLAY)=' | sort | tr '\n' ' ')
    [ -n "$key" ] && [[ "$seen" != *" $key"* ]] || continue
    seen="$seen $key"
    # setsid -f: fully detached, so it keeps running after this terminal or SSH session closes
    # shellcheck disable=SC2086
    setsid -f sudo -u "$USER_NAME" env HOME="$USER_HOME" $envs \
        /usr/local/bin/threat-monitor-screensaver session </dev/null >/dev/null 2>&1
    started=$((started + 1))
done
if [ "$started" -eq 0 ]; then
    echo "   no desktop open right now; it will start at the next desktop login"
else
    echo "   started (VNC desktops are skipped unless INCLUDE_VNC=yes in the settings)"
fi

. /etc/threat-monitor-screensaver.conf
echo
echo "Done. The Threat Monitor appears after ${START_AFTER_MIN} idle minutes and the screen turns off"
echo "after ${SCREEN_OFF_AFTER_MIN} (0 = never). Change these in /etc/threat-monitor-screensaver.conf."
echo "Try it now from a terminal on the desktop:  threat-monitor-screensaver preview"
echo "Remove it with:  sudo $APP_DIR/uninstall.sh"
