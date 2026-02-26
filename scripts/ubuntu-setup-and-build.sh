#!/usr/bin/env bash
set -euo pipefail

SKIP_TESTS="${SKIP_TESTS:-0}"
RELEASE="${RELEASE:-0}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[AI Armor] missing required command: $1" >&2
    exit 1
  fi
}

echo "[AI Armor] validating Ubuntu/Linux build prerequisites..."
require_cmd cargo

echo "[AI Armor] fetching dependencies..."
cargo fetch

if [[ "$SKIP_TESTS" != "1" ]]; then
  echo "[AI Armor] running core tests..."
  cargo test -p core-detect -p core-tokenize -p core-vault
fi

pushd apps/desktop-tauri/src-tauri >/dev/null
if [[ "$RELEASE" == "1" ]]; then
  echo "[AI Armor] building release binary..."
  cargo build --release
  echo "[AI Armor] binary: apps/desktop-tauri/src-tauri/target/release/desktop-tauri"
else
  echo "[AI Armor] running desktop app (Linux dev mode)..."
  cargo run
fi
popd >/dev/null
