#!/usr/bin/env bash
# win-docker-cleanup.sh —— 多机实测收尾（Windows Git Bash 执行）：
# 删 flock-* 容器（场景一 wc1/wc2；场景二 srv1/2w1/2w2）与其命名卷（down -v 语义）+
# 本机 .tmp/flock-mn 运行状态。只匹配 flock- 前缀容器，他容器零触碰。退出码恒 0。

export MSYS_NO_PATHCONV=1
set -u

_src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"

echo "== flock-* 容器 =="
mapfile -t ct < <(docker ps -aq --filter 'name=flock-' 2>/dev/null)
if [ "${#ct[@]}" -gt 0 ] && [ -n "${ct[0]}" ]; then
    docker rm -f "${ct[@]}" >/dev/null
    echo "已删：$(docker ps -a --filter 'name=flock-' --format '{{.Names}}' | tr '\n' ' ')（已空）"
else
    echo "（无）"
fi

echo "== flock-mn-* 命名卷 =="
mapfile -t vols < <(docker volume ls -q --filter 'name=flock-mn-' 2>/dev/null)
if [ "${#vols[@]}" -gt 0 ] && [ -n "${vols[0]}" ]; then
    docker volume rm "${vols[@]}" >/dev/null
    echo "已删：${vols[*]}"
else
    echo "（无）"
fi

echo "== 运行状态（.tmp/flock-mn）=="
rm -rf "$HERE/../../.tmp/flock-mn" 2>/dev/null && echo "已删" || echo "（无）"

echo "清理完成。剩余：$(docker ps -a --filter 'name=flock-' --format '{{.Names}}' | tr '\n' ' ')"
