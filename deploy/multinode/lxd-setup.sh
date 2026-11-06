#!/usr/bin/env bash
# lxd-setup.sh —— 真·多机组网实测：jowency（Ubuntu + LXD）侧供应脚本。
#
# 在 jowency 宿主上运行（Windows 侧经 ssh 投递执行；见 README「复刻步骤」）：
#   bash lxd-setup.sh 1     # 场景一：flock-s1（Direct server）+ flock-c3/c4（客户端）
#   bash lxd-setup.sh 2     # 场景二：flock-s2（Frp+Raft server）+ flock-c5/c6（客户端）
#                           #        + frps 宿主进程 + init-cluster 集群材料
#
# 前置：~/flock-mn/bin/{flock-server-direct,flock-server-mp,flock-client,frps,frpc}
#       ~/flock-mn/assets/（本目录模板，Windows 侧 tar 流式投递）。
# 幂等：容器存在即跳过 launch；配置/二进制/工具每次确保；frps 检测端口在听即跳过；
#       init-cluster 检测 root.seed 存在即跳过。
#
# 边界：只动 flock-* 前缀容器；既有容器零触碰。测毕 lxd-cleanup.sh 全删。

set -euo pipefail

SCENARIO="${1:-}"
[ "$SCENARIO" = 1 ] || [ "$SCENARIO" = 2 ] || { echo "usage: lxd-setup.sh <1|2>" >&2; exit 64; }

BIN=~/flock-mn/bin
ASSETS=~/flock-mn/assets
RUN=~/flock-mn/run

# JOW_LAN_IP 可环境变量钉死（多网卡机器：路由 src 可能不是 ssh 侧 IP；proxy/frps
# 均听 0.0.0.0，任一宿主 IP 皆可达——缺省取「到 Windows 的路由 src」，复刻时可
# JOW_LAN_IP=192.168.31.x bash lxd-setup.sh … 显式指定）。
JOW_LAN_IP="${JOW_LAN_IP:-$(ip -4 route get 192.168.31.244 | head -1 | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')}"
LXD_GW_IP="$(ip -4 addr show lxdbr0 | awk '/inet /{print $2}' | cut -d/ -f1)"
[ -n "$JOW_LAN_IP" ] && [ -n "$LXD_GW_IP" ] || { echo "LAN/lxdbr0 IP 探测失败" >&2; exit 1; }
echo "jowency LAN IP = $JOW_LAN_IP ; lxdbr0 = $LXD_GW_IP"

mkdir -p "$RUN"

render() { # render <template> <outfile> [KEY=value ...] —— @KEY@ 占位替换
    local t="$ASSETS/$1" o="$2"; shift 2
    local expr=() kv
    for kv in "$@"; do expr+=("-e" "s|@${kv%%=*}@|${kv#*=}|g"); done
    sed "${expr[@]}" "$t" > "$o"
}

# —— 通用：launch + 推二进制（tar 流，scp/lxc pull 会静默截断）+ 工具 + rp_filter ——
ensure_container() { # ensure_container <name> <bins...>
    local c="$1"; shift
    lxc list "$c" -c n --format csv 2>/dev/null | grep -qx "$c" || lxc launch ubuntu:26.04 "$c"
    lxc exec "$c" -- sh -c 'command -v ping >/dev/null 2>&1 || { apt-get update -qq >/dev/null && apt-get install -y -qq iputils-ping iproute2 procps netcat-openbsd >/dev/null; }'
    lxc exec "$c" -- sh -c 'sysctl -qw net.ipv4.conf.all.rp_filter=1 2>/dev/null || true; mkdir -p /var/lib/flock /etc/flock'
    local b
    for b in "$@"; do
        tar -C "$BIN" -cf - "$b" | lxc exec "$c" -- tar -C /usr/local/bin -xf -
        lxc exec "$c" -- chmod +x "/usr/local/bin/$b"
    done
}

put_file() { # put_file <container> <local-file> <remote-path>
    lxc exec "$1" -- tee "$3" >/dev/null < "$2"
}

render_client_cfg() { # render_client_cfg <outfile> <endpoint> <user>
    render client.toml.example "$1" "ENDPOINT=$2" "USER=$3"
}

# ============================================================================
if [ "$SCENARIO" = 1 ]; then
# 场景一【单 Server · Direct】：flock-s1 + LXD 客户端 c3/c4
# ============================================================================

ensure_container flock-s1 flock-server-direct
# 推送名 flock-server-direct → 容器内规范名 flock-server（配置/CLI 与 deploy 镜像一致）
lxc exec flock-s1 -- mv -f /usr/local/bin/flock-server-direct /usr/local/bin/flock-server
render server-s1-direct.toml "$RUN/server-s1.toml" "JOW_LAN_IP=$JOW_LAN_IP"
put_file flock-s1 "$RUN/server-s1.toml" /etc/flock/server.toml
# 接入端点发布：LXD proxy device → jowency 0.0.0.0:9443（容器内 127.0.0.1:9443）
lxc config device get flock-s1 p9443 listen >/dev/null 2>&1 \
    || lxc config device add flock-s1 p9443 proxy listen=tcp:0.0.0.0:9443 connect=tcp:127.0.0.1:9443

for pair in "flock-c3 mnc3" "flock-c4 mnc4"; do
    set -- $pair
    ensure_container "$1" flock-client
    render_client_cfg "$RUN/$1-client.toml" "$JOW_LAN_IP:9443" "$2"
    put_file "$1" "$RUN/$1-client.toml" /var/lib/flock/client.toml
done

echo "场景一 LXD 侧就绪：flock-s1（Direct :9443 已发布 $JOW_LAN_IP:9443）+ flock-c3/c4"

# ============================================================================
else
# 场景二【双 Server · 跨机 Raft + 双传输】：flock-s2（Frp+Raft）+ 客户端 c5/c6
#   + frps（宿主）+ init-cluster 材料（2 voter）
# ============================================================================

# —— frps（宿主进程；端口在听即跳过）——
if ! ss -ltn 2>/dev/null | grep -q ':7000 '; then
    nohup "$BIN/frps" -c "$ASSETS/frps-mn.toml" > "$RUN/frps.log" 2>&1 &
    echo "frps 已启动（pid $!，日志 $RUN/frps.log）"
else
    echo "frps 已在听 :7000（幂等跳过）"
fi

# —— init-cluster（2 voter；幂等）——端点序 = Windows server-1 直连口、flock-s2 frps 用户口
if [ ! -f "$RUN/mat/root.seed" ]; then
    mkdir -p "$RUN/mat"
    # init-cluster 本地生成（不拨号）；config 需通过完整校验（advertise_endpoint 必填）。
    printf 'state_dir = "%s/stub"\nbind = "127.0.0.1:19999"\nadmin_bind = "127.0.0.1:19998"\nadvertise_endpoint = "127.0.0.1:19999"\ndir_version = 1\n' "$RUN" > "$RUN/stub.toml"
    "$BIN/flock-server-mp" --config "$RUN/stub.toml" \
        init-cluster --voters 2 --out "$RUN/mat" \
        --endpoints "192.168.31.244:9443,$JOW_LAN_IP:24000"
    echo "init-cluster 完成（root.seed + node-0/1.bundle 于 $RUN/mat）"
else
    echo "init-cluster 已存在（幂等跳过）"
fi

ensure_container flock-s2 flock-server-mp frpc
# 推送名 flock-server-mp → 容器内规范名 flock-server（同 flock-s1 的 Direct 档处理）
lxc exec flock-s2 -- mv -f /usr/local/bin/flock-server-mp /usr/local/bin/flock-server
render server-2s-frp-mp.toml "$RUN/server-s2.toml" "JOW_LAN_IP=$JOW_LAN_IP" "LXD_GW_IP=$LXD_GW_IP" "WIN_LAN_IP=192.168.31.244"
put_file flock-s2 "$RUN/server-s2.toml" /etc/flock/server.toml
put_file flock-s2 "$RUN/mat/node-1.bundle" /var/lib/flock/node-1.bundle
# Raft 织物发布：LXD proxy device → jowency 0.0.0.0:9500（Windows 侧 server-1 跨机拨入）
lxc config device get flock-s2 p9500 listen >/dev/null 2>&1 \
    || lxc config device add flock-s2 p9500 proxy listen=tcp:0.0.0.0:9500 connect=tcp:127.0.0.1:9500

for pair in "flock-c5 mn2c5" "flock-c6 mn2c6"; do
    set -- $pair
    ensure_container "$1" flock-client
    render_client_cfg "$RUN/$1-client.toml" "$JOW_LAN_IP:24000" "$2"
    put_file "$1" "$RUN/$1-client.toml" /var/lib/flock/client.toml
done

echo "场景二 LXD 侧就绪：flock-s2（Frp→frps:24000 + Raft :9500 已发布）+ flock-c5/c6"
echo "node-0.bundle 待 Windows 侧拉取：ssh $USER@${JOW_LAN_IP} cat $RUN/mat/node-0.bundle"
fi
