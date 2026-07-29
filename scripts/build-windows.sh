#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  x64)
    TARGET="x86_64-pc-windows-msvc"
    CONFIG="src-tauri/tauri.x64.conf.json"
    ;;
  arm64)
    TARGET="aarch64-pc-windows-msvc"
    CONFIG="src-tauri/tauri.arm64.conf.json"
    ;;
  *)
    echo "usage: $0 <x64|arm64>" >&2
    exit 2
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! VARMLEN_REAL_CLANG="$(command -v clang)"; then
  echo "clang is required and was not found in PATH" >&2
  exit 1
fi
export VARMLEN_REAL_CLANG
export PATH="$ROOT/scripts/clang-msvc-compat:$PATH"

"$ROOT/scripts/prepare-windows-runtime.sh" "$1"
cargo xwin build -p varmlen-service --target "$TARGET" --release --locked
npx tauri build \
  --runner "$ROOT/scripts/cargo-xwin-runner" \
  --target "$TARGET" \
  --config "$CONFIG" \
  --ci
