#!/usr/bin/env bash
set -euo pipefail

XRAY_VERSION="26.6.27"
WINTUN_VERSION="0.14.1"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

case "${1:-}" in
  x64)
    XRAY_ARCHIVE="Xray-windows-64.zip"
    XRAY_SHA256="97f16a0701dbf931c9c4375399f8188e31615fdd5c863be5c612f946acd4dd01"
    WINTUN_ARCH="amd64"
    ;;
  arm64)
    XRAY_ARCHIVE="Xray-windows-arm64-v8a.zip"
    XRAY_SHA256="e9dbd1b54ebcd272691fc67535297315eda642905cf5a5076b495d857c480ecb"
    WINTUN_ARCH="arm64"
    ;;
  *)
    echo "usage: $0 <x64|arm64>" >&2
    exit 2
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/src-tauri/windows/runtime/$1"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${XRAY_ARCHIVE}" \
  --output "$TMP/xray.zip"
echo "${XRAY_SHA256}  $TMP/xray.zip" | sha256sum --check --status

curl --fail --location --proto '=https' --tlsv1.2 \
  "https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip" \
  --output "$TMP/wintun.zip"
echo "${WINTUN_SHA256}  $TMP/wintun.zip" | sha256sum --check --status

rm -rf "$DEST"
mkdir -p "$DEST"
unzip -q "$TMP/xray.zip" xray.exe geoip.dat geosite.dat -d "$DEST"
unzip -q "$TMP/wintun.zip" \
  "wintun/bin/${WINTUN_ARCH}/wintun.dll" -d "$TMP/wintun"
cp "$TMP/wintun/wintun/bin/${WINTUN_ARCH}/wintun.dll" "$DEST/wintun.dll"

for asset in xray.exe wintun.dll geoip.dat geosite.dat; do
  test -s "$DEST/$asset"
done

echo "Prepared pinned Windows runtime in $DEST"
