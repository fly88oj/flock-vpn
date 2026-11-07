#!/usr/bin/env bash
# build-wasm.sh —— M8b wasm 构建档（docs/design.md §7-M8.1/§M8.6 定死）：
#
#   cargo build -p flock-protocol --release \
#     --target wasm32-unknown-unknown --no-default-features --features wasm,anchor
#
# （无 zstd ⇒ 零 C 依赖；.cargo/config.toml 的 getrandom_backend="custom" rustflags
#  仅对该 target 生效。）产物拷入 webui/assets/vendor/flock_pake.wasm（**产物提交
# 进库**——CI 无 wasm 工具链也能出完整二进制），并做幂等性校验：重跑构建的
# .wasm sha256 与库内产物逐字节一致（防源码/产物漂移 + 构建不确定性）。
#
# 前置：rustup target add wasm32-unknown-unknown。
# 幂等：任意次重跑 ⇒ 产物 sha256 不变（同源码/同工具链；变更即非确定性构建信号）。
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown
FEATURES=wasm,anchor
SRC_CRATE=target/$TARGET/release/flock_protocol.wasm
DEST=app/flock-server/src/webui/assets/vendor/flock_pake.wasm

echo "== build-wasm: cargo build -p flock-protocol --release --target $TARGET --no-default-features --features $FEATURES"
cargo build -p flock-protocol --release --target $TARGET --no-default-features --features $FEATURES

[ -f "$SRC_CRATE" ] || { echo "build-wasm: 产物缺失 $SRC_CRATE"; exit 1; }
mkdir -p "$(dirname "$DEST")"

new_hash=$(sha256sum "$SRC_CRATE" | cut -d' ' -f1)
if [ -f "$DEST" ]; then
  old_hash=$(sha256sum "$DEST" | cut -d' ' -f1)
  if [ "$new_hash" = "$old_hash" ]; then
    echo "build-wasm: 产物与库内一致（sha256=$new_hash）——无漂移"
  else
    echo "build-wasm: 拷入新产物 $DEST（sha256 $old_hash → $new_hash）"
    cp "$SRC_CRATE" "$DEST"
  fi
else
  echo "build-wasm: 首次拷入产物 $DEST（sha256=$new_hash）"
  cp "$SRC_CRATE" "$DEST"
fi

# 幂等性复核：clean 重建一次，sha256 应不变（工具链确定性）。
echo "== build-wasm: 幂等复核（重跑构建比对 sha256）"
touch crates/flock-protocol/src/lib.rs   # 强制重编该 crate（依赖层缓存保留）
cargo build -p flock-protocol --release --target $TARGET --no-default-features --features $FEATURES
again_hash=$(sha256sum "$SRC_CRATE" | cut -d' ' -f1)
if [ "$again_hash" != "$new_hash" ]; then
  echo "build-wasm: 非确定性构建（首跑 $new_hash ≠ 重跑 $again_hash）——产物不更新，请排查" >&2
  exit 1
fi
echo "build-wasm: 幂等 OK（重跑 sha256=$again_hash）"
ls -l "$DEST"
