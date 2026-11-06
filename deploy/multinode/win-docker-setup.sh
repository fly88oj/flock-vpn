#!/usr/bin/env bash
# win-docker-setup.sh —— 真·多机组网实测：Windows 侧 Docker 供应脚本（Git Bash 执行）。
#
#   bash deploy/multinode/win-docker-setup.sh 1     # 场景一：客户端 flock-wc1/wc2（→ jowency:9443）
#   bash deploy/multinode/win-docker-setup.sh 2     # 场景二：server-1 容器 flock-srv1（Direct+Raft，
#                                                   #   发布 9443/9500）+ 客户端 flock-2w1/2w2（→ server-1）
#
# 镜像复用 flock/client:e2e / flock/server:e2e-a（工具面：iproute2/ping/procps/jq）；
# **二进制以 HEAD 构建产物覆盖挂载**（deploy/multinode/out/，构建见 Dockerfile.buildbin），
# 保证容器行为 = 本仓库当前源码。状态用命名卷（redb 文件锁不进 9p 挂载）。
# 幂等：容器存在即跳过创建（配置由 multinode_assert.sh 引导写入）。

export MSYS_NO_PATHCONV=1
set -euo pipefail

SCENARIO="${1:-}"
[ "$SCENARIO" = 1 ] || [ "$SCENARIO" = 2 ] || { echo "usage: win-docker-setup.sh <1|2>" >&2; exit 64; }

_src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"
OUT="$HERE/out"
# 注：BuildKit local 输出文件无 POSIX x 位（Windows ACL），此处只验存在；Docker Desktop
# 的 Windows→Linux bind mount 在容器内呈现 0777，可执行位无虞。
[ -f "$OUT/flock-client" ] || { echo "缺 $OUT/flock-client（先构建：docker buildx build -f deploy/multinode/Dockerfile.buildbin --output type=local,dest=deploy/multinode/out .）" >&2; exit 1; }

WIN_LAN_IP="$(ipconfig | awk '/IPv4/{print $NF}' | grep '^192\.168\.' | head -1)"
JOW_LAN_IP="${JOW_LAN_IP:-192.168.31.221}"
echo "Windows LAN IP = $WIN_LAN_IP ; jowency = $JOW_LAN_IP"

CLIENT_ARGS=(--cap-add NET_ADMIN --device /dev/net/tun
    --sysctl net.ipv4.conf.all.rp_filter=1 --sysctl net.ipv4.conf.default.rp_filter=1
    -v "$OUT/flock-client:/usr/local/bin/flock-client:ro")

ensure_client() { # ensure_client <name> <hostname>
    docker inspect "$1" >/dev/null 2>&1 && { echo "$1 已存在（幂等跳过）"; return; }
    docker run -d --name "$1" --hostname "$2" "${CLIENT_ARGS[@]}" \
        -v "flock-mn-$1:/var/lib/flock" \
        flock/client:e2e --config /etc/flock/client.toml service
    echo "$1 已创建（awaiting bootstrap；配置由 multinode_assert.sh 引导写入）"
}

if [ "$SCENARIO" = 1 ]; then
    ensure_client flock-wc1 flock-wc1
    ensure_client flock-wc2 flock-wc2
    echo "场景一 Windows 侧就绪：flock-wc1/wc2（Docker bridge → $JOW_LAN_IP:9443）"
else
    # —— server-1：Direct + multi-primary 二进制覆盖 + 9443/9500 发布 ——
    if ! docker inspect flock-srv1 >/dev/null 2>&1; then
        [ -f "$OUT/flock-server-mp" ] || { echo "缺 $OUT/flock-server-mp" >&2; exit 1; }
        sed -e "s|@WIN_LAN_IP@|$WIN_LAN_IP|g" -e "s|@JOW_LAN_IP@|$JOW_LAN_IP|g" \
            "$HERE/server-2w-direct-mp.toml" > "$HERE/out/server-2w.toml"
        docker run -d --name flock-srv1 --hostname flock-srv1 \
            --cap-add NET_ADMIN --device /dev/net/tun \
            --sysctl net.ipv4.conf.all.rp_filter=1 --sysctl net.ipv4.conf.default.rp_filter=1 \
            -p 0.0.0.0:9443:9443 -p 0.0.0.0:9500:9500 \
            -v "$OUT/flock-server-mp:/usr/local/bin/flock-server:ro" \
            -v "$HERE/out/server-2w.toml:/etc/flock/server.toml:ro" \
            -v flock-mn-srv1:/var/lib/flock \
            flock/server:e2e-a --config /etc/flock/server.toml
        echo "flock-srv1 已创建（Direct 0.0.0.0:9443 + Raft 0.0.0.0:9500 已发布）"
    else
        echo "flock-srv1 已存在（幂等跳过）"
    fi
    ensure_client flock-2w1 flock-2w1
    ensure_client flock-2w2 flock-2w2
    echo "场景二 Windows 侧就绪：flock-srv1 + flock-2w1/2w2（→ $WIN_LAN_IP:9443）"
fi
