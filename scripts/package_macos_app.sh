#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT_DIR/dist/WireGuardC.app"
CONTENTS="$APP_DIR/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

cd "$ROOT_DIR"
go build -trimpath -ldflags "-s -w" -o wireguardc ./cmd/wireguardc
swift build -c release --package-path gui

rm -rf "$APP_DIR"
mkdir -p "$MACOS" "$RESOURCES"
cp "$ROOT_DIR/gui/.build/release/WireGuardCGUI" "$MACOS/WireGuardC"
cp "$ROOT_DIR/wireguardc" "$RESOURCES/wireguardc"
cp "$ROOT_DIR/scripts/wireguardc-root.sh" "$RESOURCES/wireguardc-root.sh"
cp "$ROOT_DIR/config/wireguardc.conf.example" "$RESOURCES/default.conf"
chmod +x "$MACOS/WireGuardC" "$RESOURCES/wireguardc" "$RESOURCES/wireguardc-root.sh"

cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>ko</string>
  <key>CFBundleExecutable</key>
  <string>WireGuardC</string>
  <key>CFBundleIdentifier</key>
  <string>local.wireguardc.gui</string>
  <key>CFBundleName</key>
  <string>WireGuardC</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

echo "$APP_DIR"
