#!/bin/bash
# Tests for the macOS screensaver (run after mac/build.sh).
#   mac/test.sh GOLDEN_FOLDER OUTPUT_FOLDER
# GOLDEN_FOLDER comes from:  python3 mac/Tests/make_golden.py GOLDEN_FOLDER
# 1. core-tests: the Swift port gives the same results as threat_monitor.py
#    on the same downloaded sources (scores, keyword matches, headlines).
# 2. saver-check: loads "Threat Monitor.saver" the way macOS does, lets it
#    fetch live data, and saves pictures of every screen in OUTPUT_FOLDER.
set -euo pipefail
cd "$(dirname "$0")"
GOLDEN="$1"
OUTPUT="$2"
mkdir -p build "$OUTPUT"

echo "== Building the tests"
xcrun swiftc -swift-version 5 -O -o build/core-tests Sources/Core/*.swift Tests/CoreTests/main.swift
xcrun clang -fobjc-arc -O -Wall -o build/saver-check Tests/saver_check.m -framework AppKit -framework ScreenSaver

status=0
echo "== Core tests"
build/core-tests "$GOLDEN" || status=1
echo "== Screensaver check"
build/saver-check "build/Threat Monitor.saver" "$OUTPUT" || status=1
exit $status
