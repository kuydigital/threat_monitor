#!/bin/bash
# Builds the macOS screensaver "Threat Monitor.saver" (one file that runs on
# both Apple silicon and Intel Macs, macOS 12 or later).
# Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
#
# Needs Xcode or the Command Line Tools (xcode-select --install).
#   mac/build.sh                  ->  mac/build/Threat Monitor.saver
#   VERSION=1.2.0 mac/build.sh    ->  sets the version shown in System Settings
# To install your build, double-click mac/build/Threat Monitor.saver.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-1.1.0}"
OUT=build
SAVER="$OUT/Threat Monitor.saver"
SDK="$(xcrun --sdk macosx --show-sdk-path)"

rm -rf "$SAVER" "$OUT/obj"
mkdir -p "$SAVER/Contents/MacOS" "$SAVER/Contents/Resources" "$OUT/obj"

echo "Swift: $(xcrun swiftc --version 2>&1 | head -n 1)"
for arch in arm64 x86_64; do
  echo "Compiling for $arch..."
  xcrun swiftc -swift-version 5 -O -whole-module-optimization \
    -target "$arch-apple-macos12.0" -sdk "$SDK" \
    -module-name ThreatMonitor -emit-library \
    -Xlinker -install_name -Xlinker "@rpath/ThreatMonitor" \
    -o "$OUT/obj/ThreatMonitor-$arch" \
    -framework ScreenSaver -framework AppKit \
    Sources/Core/*.swift Sources/Saver/*.swift
done
lipo -create -output "$SAVER/Contents/MacOS/ThreatMonitor" "$OUT/obj/ThreatMonitor-arm64" "$OUT/obj/ThreatMonitor-x86_64"
sed "s/@VERSION@/$VERSION/g" Info.plist > "$SAVER/Contents/Info.plist"
cp Resources/thumbnail.png Resources/thumbnail@2x.png "$SAVER/Contents/Resources/"
cp ../LICENSE "$SAVER/Contents/Resources/LICENSE.txt"

# Ad-hoc signature: required to run on Apple silicon. (Not notarized - see
# INSTALL-Mac.txt for the one-time "Open Anyway" step.)
codesign --force --sign - --timestamp=none "$SAVER"
codesign --verify --strict --verbose=1 "$SAVER"
lipo -info "$SAVER/Contents/MacOS/ThreatMonitor"
echo "Built $SAVER (version $VERSION)"
