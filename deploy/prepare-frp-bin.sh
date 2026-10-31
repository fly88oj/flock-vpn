#!/usr/bin/env bash
# prepare-frp-bin.sh —— 把 .tmp 里的原版 frp v0.71.1 定版二进制拷进 deploy/build/
# （m2.yml 构建前置：frps 进 frps 镜像、frpc 进 server(Frp 模式) 镜像；build context 保持小）。
#
# 用法：bash deploy/prepare-frp-bin.sh
# 来源缺失时给出下载指引（frp-compat §1：GitHub Releases v0.71.1 / 2026-10-14）。
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/.tmp/frp_0.71.1_linux_amd64"
dst="$root/deploy/build"

mkdir -p "$dst"
for bin in frps frpc; do
  if [[ ! -f "$src/$bin" ]]; then
    cat >&2 <<EOF
缺少 $src/$bin
下载并解压到该目录（Linux amd64，v0.71.1）：
  curl -LO https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_linux_amd64.tar.gz
  tar -xzf frp_0.71.1_linux_amd64.tar.gz -C .tmp
EOF
    exit 1
  fi
  cp "$src/$bin" "$dst/$bin"
  chmod +x "$dst/$bin"
  echo "ok: deploy/build/$bin ($(stat -c%s "$dst/$bin" 2>/dev/null || stat -f%z "$dst/$bin") bytes)"
done
echo "下一步：docker compose -f deploy/m2.yml up -d --build"
