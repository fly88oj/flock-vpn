#!/usr/bin/env bash
# build-wasm.sh —— M8b wasm build tier (pinned in docs/design.md §7-M8.1/§M8.6):
#
#   cargo build -p flock-protocol --release \
#     --target wasm32-unknown-unknown --no-default-features --features wasm,anchor
#
# (No zstd ⇒ zero C dependencies; the getrandom_backend="custom" rustflags in
# .cargo/config.toml apply to that target only.) The product is copied into
# webui/assets/vendor/flock_pake.wasm (**the artifact is committed to the
# repo** —— CI without a wasm toolchain can still produce a complete binary),
# plus an idempotence check: a rebuilt .wasm's sha256 must match the committed
# artifact byte-for-byte (guards against source/artifact drift and
# nondeterministic builds).
#
# Prerequisite: rustup target add wasm32-unknown-unknown.
# Idempotence: any number of re-runs ⇒ the artifact's sha256 is unchanged (same
# sources/toolchain; a change is a nondeterministic-build signal).
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown
FEATURES=wasm,anchor
SRC_CRATE=target/$TARGET/release/flock_protocol.wasm
DEST=app/flock-server/src/webui/assets/vendor/flock_pake.wasm

echo "== build-wasm: cargo build -p flock-protocol --release --target $TARGET --no-default-features --features $FEATURES"
cargo build -p flock-protocol --release --target $TARGET --no-default-features --features $FEATURES

[ -f "$SRC_CRATE" ] || { echo "build-wasm: artifact missing $SRC_CRATE"; exit 1; }
mkdir -p "$(dirname "$DEST")"

new_hash=$(sha256sum "$SRC_CRATE" | cut -d' ' -f1)
if [ -f "$DEST" ]; then
  old_hash=$(sha256sum "$DEST" | cut -d' ' -f1)
  if [ "$new_hash" = "$old_hash" ]; then
    echo "build-wasm: artifact identical to the committed one (sha256=$new_hash) —— no drift"
  else
    echo "build-wasm: copying new artifact to $DEST (sha256 $old_hash → $new_hash)"
    cp "$SRC_CRATE" "$DEST"
  fi
else
  echo "build-wasm: first-time artifact copy to $DEST (sha256=$new_hash)"
  cp "$SRC_CRATE" "$DEST"
fi

# Idempotence re-check: clean rebuild once, sha256 must be unchanged (toolchain
# determinism).
echo "== build-wasm: idempotence re-check (rebuild and compare sha256)"
# flock-protocol is already a git dependency (separate repo v0.1.0, sources in
# the cargo git checkout) —— force-rebuilding just that crate (dependency-layer
# cache kept) uses cargo clean -p instead of touching in-repo paths.
cargo clean -p flock-protocol --release --target $TARGET   # force-rebuild this one crate (dependency-layer cache kept)
cargo build -p flock-protocol --release --target $TARGET --no-default-features --features $FEATURES
again_hash=$(sha256sum "$SRC_CRATE" | cut -d' ' -f1)
if [ "$again_hash" != "$new_hash" ]; then
  echo "build-wasm: nondeterministic build (first run $new_hash ≠ re-run $again_hash) —— artifact not updated, please investigate" >&2
  exit 1
fi
echo "build-wasm: idempotent OK (re-run sha256=$again_hash)"
ls -l "$DEST"
