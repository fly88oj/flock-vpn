#!/usr/bin/env bash
# m3_assert.sh —— M3 断言（docs/design.md §7-M3 完成标准：A2/A3/A4/A9 单服版）。
#
# 前置：
#   docker compose -f deploy/m3.yml up -d --build
#   bash deploy/m3_assert.sh
#
# 断言集（单服版——跨服面属 M5 §6.3）：
#   A2 隧道连通   client ping -c 3 100.64.0.1（服务器 tun VIP）0 丢包
#   A3 MTU        client `ip link show tun0` 含 mtu 1280；`ping -s 1252 -M do` 通
#                 （1252+28=1280，§2.1）
#   A4 吞吐基线   iperf3 over 隧道 ≥ 100 Mbps（记录数值供回归对比，R7）
#   A9 静默死链   `docker network disconnect` 模拟断网 ⇒ 双侧 ≤30s 检测进入重连
#                 （会话层 3×keepalive=30s，§1.3.3c）；恢复网络 ⇒ 重连 + ping 恢复
#
# 汇总：末尾逐项 PASS/FAIL；任一 FAIL ⇒ 退出码非零。
#
# Git Bash（MSYS）路径改写坑：/dev/net/tun、/etc/flock/... 等以 / 开头的参数会被
# 改写成 Windows 路径（设计附录 B-2 首次踩坑记录）——本脚本内部 export
# MSYS_NO_PATHCONV=1，调用方无需任何前置设置。
#
# WSL bash 兜底（Windows 下 `bash` 解析到 C:\Windows\System32\bash.exe 的 WSL 垫片时）：
# 垫片经默认发行版起 /bin/bash——若默认发行版是 docker-desktop（无 /bin/bash）则本脚本
# 根本起不来（execvpe(/bin/bash) failed）；若是完整发行版（如 Ubuntu）则起得来但无
# MSYS 语义（pwd -W 缺席、docker.exe 收到 /mnt/... 不识别）。两形态统一转投 Windows 侧
# Git Bash 执行——脚本主体（MSYS_NO_PATHCONV + pwd -W 双侧路径形态）即在该形态验证。
if grep -qi microsoft /proc/version 2>/dev/null && [ -d /mnt/c ]; then
    _gb="/mnt/c/Program Files/Git/bin/bash.exe"
    if [ -x "$_gb" ]; then
        _self="${BASH_SOURCE[0]:-$0}"
        case "$_self" in /*) ;; *) _self="$(pwd)/$_self" ;; esac
        exec "$_gb" "$(wslpath -m "$_self")" "$@"
    fi
fi

export MSYS_NO_PATHCONV=1

set -u

_src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# Git Bash（MSYS）：MSYS_NO_PATHCONV=1 关闭了参数路径改写 ⇒ docker（Windows 可执行）
# 收到 /e/... 形态不识别——换 Windows 形态（E:/...，正斜杠；原生 Linux 的 pwd -W
# 不存在则回落 POSIX 路径，docker on Linux 本就接受）。
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"
COMPOSE_FILE="$HERE/m3.yml"
NETWORK="flock-m3net"
SERVER_VIP="100.64.0.1"
MTU_EXPECT=1280
A4_MIN_MBPS=100
A9_DEADLINE=30   # 秒；会话层 3×keepalive(10s) 静默 ⇒ DeadLink（A9 语义）

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

PASS=0
FAIL=0
declare -a SUMMARY

record() { # record PASS|FAIL <id> <detail>
    if [ "$1" = "PASS" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
    SUMMARY+=("$(printf '%-4s %s | %s' "$1" "$2" "$3")")
    printf '[%s] %s | %s\n' "$1" "$2" "$3"
}

exec_client() { compose exec -T client "$@"; }
exec_server() { compose exec -T server "$@"; }

log() { printf '\n== %s ==\n' "$*"; }

# ============================================================================
# 编排（幂等：state 卷跨次运行保留 ⇒ ready 标记即跳过）
# ============================================================================

bootstrap() {
    log "bootstrap: 等待 server 就绪（admin 端点）"
    local deadline=$((SECONDS + 120))
    until exec_server bash -c 'exec 3<>/dev/tcp/127.0.0.1/9444 && echo ok' 2>/dev/null | grep -q ok; do
        if [ $SECONDS -ge $deadline ]; then
            echo "server admin 端点 120s 未就绪"; return 1
        fi
        sleep 2
    done
    # 数据面装配确认（服务端 tun + 路由）。
    exec_server sh -c 'ip link show tun0' >/dev/null 2>&1 \
        || { echo "server tun0 未创建（dataplane down）"; compose logs --tail 40 server; return 1; }

    if exec_client sh -c 'test -f /var/lib/flock/ready' 2>/dev/null; then
        log "bootstrap: 已就绪（幂等跳过）"
        return 0
    fi

    log "bootstrap: gen-keys（客户端）"
    local keys
    keys="$(exec_client flock-client --config /etc/flock/client.toml gen-keys)" || return 1
    local dev_x dev_ed
    dev_x="$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')"
    dev_ed="$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')"
    [ -n "$dev_x" ] && [ -n "$dev_ed" ] || { echo "gen-keys 输出异常：$keys"; return 1; }

    log "bootstrap: 服务端 device-add（预注册设备 + 分 VIP）"
    local out
    out="$(exec_server flock-server --config /etc/flock/server.toml \
        device-add --user m3client --device-x "$dev_x" --device-ed "$dev_ed" 2>&1)" \
        || { echo "device-add 失败：$out"; return 1; }
    local vip
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    case "$vip" in
        100.64.*) ;;
        *) echo "device-add 未返回 100.64/10 池内 VIP：$out"; return 1 ;;
    esac

    log "bootstrap: 服务端 invite（v3 邀请）"
    local invite_b64
    invite_b64="$(exec_server flock-server --config /etc/flock/server.toml \
        invite --ttl-secs 86400)" || return 1
    printf '%s' "$invite_b64" | exec_client sh -c 'cat > /var/lib/flock/invite.b64' || return 1

    log "bootstrap: 客户端 ingest invite（钉扎根公钥 + 存目录）"
    exec_client flock-client --config /etc/flock/client.toml \
        invite /var/lib/flock/invite.b64 || return 1

    log "bootstrap: 写入 vip=$vip"
    printf '%s' "$vip" | exec_client sh -c 'cat > /var/lib/flock/vip' || return 1

    log "bootstrap: ready + restart client（主进程接管）"
    exec_client sh -c 'touch /var/lib/flock/ready' || return 1
    compose restart client >/dev/null 2>&1 || return 1

    # 等客户端握手成功（tun0 出现 = 客户端主进程已跑到数据面装配）。
    local t=$((SECONDS + 60))
    until exec_client sh -c 'ip link show tun0' >/dev/null 2>&1; do
        if [ $SECONDS -ge $t ]; then
            echo "client tun0 60s 内未创建"; compose logs --tail 40 client; return 1
        fi
        sleep 2
    done
    # 等 ping 面可用（握手 + 路由完成；上限 60s）。
    local ok=""
    t=$((SECONDS + 60))
    while [ $SECONDS -lt $t ]; do
        if exec_client ping -c 1 -W 2 "$SERVER_VIP" >/dev/null 2>&1; then ok=1; break; fi
        sleep 2
    done
    [ -n "$ok" ] || { echo "client 60s 内 ping 不通 $SERVER_VIP"; compose logs --tail 40 client; return 1; }
    return 0
}

# ============================================================================
# A2：隧道连通（client ↔ 服务器 peer，0 丢包）
# ============================================================================

a2() {
    log "A2 隧道连通：ping -c 3 $SERVER_VIP（0 丢包）"
    local out
    out="$(exec_client ping -c 3 -W 3 "$SERVER_VIP" 2>&1)"; local rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'
    if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q '0% packet loss'; then
        record PASS A2 "ping $SERVER_VIP 3/3, 0% packet loss"
    else
        record FAIL A2 "ping 失败（rc=$rc）"
    fi
}

# ============================================================================
# A3：MTU 1280 + DF 大包
# ============================================================================

a3() {
    log "A3 MTU：tun0 mtu $MTU_EXPECT + ping -s 1252 -M do"
    local link
    link="$(exec_client ip link show tun0 2>&1)"
    printf '%s\n' "$link" | sed 's/^/    /'
    local mtu_ok=no
    printf '%s\n' "$link" | grep -q "mtu $MTU_EXPECT" && mtu_ok=yes

    local out
    out="$(exec_client ping -c 2 -W 3 -s 1252 -M do "$SERVER_VIP" 2>&1)"; local rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'

    if [ "$mtu_ok" = yes ] && [ $rc -eq 0 ]; then
        record PASS A3 "tun0 mtu=$MTU_EXPECT；-s 1252 -M do 通（1252+28=1280）"
    else
        record FAIL A3 "mtu_ok=$mtu_ok df_ping_rc=$rc"
    fi
}

# ============================================================================
# A4：吞吐基线（iperf3 over 隧道，记录数值）
# ============================================================================

a4() {
    log "A4 吞吐：iperf3 over 隧道（阈值 ${A4_MIN_MBPS} Mbps，记录数值）"
    # iperf3 服务端（-D 自守护；绑定服务器 tun VIP——只经隧道可达）。
    # pgrep -x：按进程名精确匹配（-f 会命中本 sh -c 包装自身 ⇒ 永假阳性跳过启动）。
    exec_server sh -c "pgrep -x iperf3 >/dev/null 2>&1 || iperf3 -s -D -B $SERVER_VIP" || true
    sleep 1
    local out
    out="$(exec_client iperf3 -c "$SERVER_VIP" -t 5 --format m 2>&1)"; local rc=$?
    printf '%s\n' "$out" | grep -E 'sender|receiver' | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL A4 "iperf3 客户端失败（rc=$rc）"
        return
    fi
    # sender 汇总行的速率列 = 「Mbits/sec」字段的前一列（--format m 固定 Mbits 单位）。
    local mbps
    mbps="$(printf '%s\n' "$out" | awk '/sender/ {for (i = 1; i <= NF; i++) if ($(i+1) == "Mbits/sec") {print $i; exit}}')"
    case "$mbps" in
        ''|*[!0-9.]*)
            record FAIL A4 "未能解析 sender 速率：$out"
            ;;
        *)
            if awk -v m="$mbps" -v t="$A4_MIN_MBPS" 'BEGIN{exit !(m>=t)}'; then
                record PASS A4 "iperf3 sender = ${mbps} Mbits/sec（≥ ${A4_MIN_MBPS}）"
            else
                record FAIL A4 "iperf3 sender = ${mbps} Mbits/sec（< ${A4_MIN_MBPS}）"
            fi
            ;;
    esac
}

# ============================================================================
# A9：静默死链双侧 ≤30s 检测进入重连 + 网络恢复后重连成功
# ============================================================================

a9() {
    log "A9 静默死链：network disconnect ⇒ 双侧 ≤${A9_DEADLINE}s 检测（dead-link）并重连"
    local cid
    cid="$(compose ps -q client)"
    [ -n "$cid" ] || { record FAIL A9 "client 容器 id 为空"; return; }

    local base_c base_s
    base_c="$(compose logs client 2>/dev/null | grep -c 'reason=dead-link' || true)"
    base_s="$(compose logs server 2>/dev/null | grep -c 'reason=dead-link' || true)"

    docker network disconnect "$NETWORK" "$cid" || { record FAIL A9 "network disconnect 失败"; return; }
    local t0=$SECONDS

    local saw_c=0 saw_s=0 elapsed=0
    while [ $SECONDS -lt $((t0 + A9_DEADLINE + 2)) ]; do
        [ "$saw_c" -eq 0 ] && [ "$(compose logs client 2>/dev/null | grep -c 'reason=dead-link' || true)" -gt "$base_c" ] && saw_c=1
        [ "$saw_s" -eq 0 ] && [ "$(compose logs server 2>/dev/null | grep -c 'reason=dead-link' || true)" -gt "$base_s" ] && saw_s=1
        elapsed=$((SECONDS - t0))
        if [ "$saw_c" -eq 1 ] && [ "$saw_s" -eq 1 ]; then break; fi
        sleep 1
    done

    if [ "$saw_c" -ne 1 ] || [ "$saw_s" -ne 1 ]; then
        docker network connect "$NETWORK" "$cid" 2>/dev/null || true
        record FAIL A9 "双侧未都在 ${A9_DEADLINE}s 内检出（client=$saw_c server=$saw_s，elapsed=${elapsed}s）"
        return
    fi

    # 恢复网络 ⇒ 客户端退避后重连（attempt 间隔 5s 起 + 抖动；预算 90s）。
    docker network connect "$NETWORK" "$cid" || { record FAIL A9 "network connect 失败"; return; }
    local reconnected=""
    local t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        if exec_client ping -c 1 -W 2 "$SERVER_VIP" >/dev/null 2>&1; then reconnected=1; break; fi
        sleep 2
    done
    if [ -n "$reconnected" ]; then
        record PASS A9 "双侧 ${elapsed}s 检出 dead-link 进入重连；网络恢复后 ping 恢复（≤${A9_DEADLINE}s 预算）"
    else
        record FAIL A9 "检出 ${elapsed}s 达标，但 90s 内未完成重连（ping 未恢复）"
    fi
}

# ============================================================================
# 入口
# ============================================================================

if ! docker info >/dev/null 2>&1; then
    echo "docker 不可用（Docker Desktop 是否在跑？）" >&2
    exit 2
fi
# 拓扑在位（容器可能仍在启动——重试 60s）。
topology_up=""
for _ in $(seq 1 30); do
    if compose ps -q server >/dev/null 2>&1 && [ -n "$(compose ps -q server)" ] \
        && compose ps -q client >/dev/null 2>&1 && [ -n "$(compose ps -q client)" ]; then
        topology_up=1
        break
    fi
    sleep 2
done
if [ -z "$topology_up" ]; then
    echo "m3 拓扑未运行：先 docker compose -f $COMPOSE_FILE up -d --build" >&2
    exit 2
fi

if ! bootstrap; then
    echo "bootstrap 失败" >&2
    exit 2
fi

a2
a3
a4
a9

log "汇总"
printf '%s\n' "${SUMMARY[@]}"
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
