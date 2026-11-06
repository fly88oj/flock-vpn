#!/usr/bin/env bash
# m7_assert.sh —— M7 客户端名册断言（docs/design.md §7-M7.7 完成标准：容器实测）。
#
# 前置：
#   docker compose -f deploy/m7.yml up -d --build
#   bash deploy/m7_assert.sh
#
# 断言集：
#   P1 名册装配   client-1 `flock-client peers`：含 server 与 client-2 条目
#                （hostname client-2 / 账户 m7c2 / 在线 / 延迟非 —）；自身行 (self)
#   P2 流量观测   iperf3 client-1→client-2 跑流后（EWMA 收敛窗 ~10s）再次 peers：
#                client-1 tx 与 client-2 rx 非 0（「设备视角」计数点）
#   P3 机读档     `peers --json` 可解析（jq）且字段语义（vip/online/latency）
#
# 凭据引导 = admin 开户路径（对齐 m3 既有脚本）：gen-keys → device-add → invite →
# ingest → vip → `flock-client login`（设口令 + 登录验证 + hostname 入册）→ ready。
#
# Windows 宿主不跑本实测（tun 需提权 + WSL2 后端）——真机清单：
# docs/manual/service-install.md（M7 条目）。
#
# 汇总：末尾逐项 PASS/FAIL；任一 FAIL ⇒ 退出码非零。
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
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"
COMPOSE_FILE="$HERE/m7.yml"
NETWORK="flock-m7net"
SERVER_VIP="100.64.0.1"
CLIENT_USER_1="m7c1"
CLIENT_USER_2="m7c2"
PASS_1="m7-pass-1"
PASS_2="m7-pass-2"
CFG_1="/var/lib/flock/client.toml"
EWMA_SETTLE=12   # iperf 停流后等 EWMA 收敛展示（α=0.2/1s 折——10s 量级窗）

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

PASS=0
FAIL=0
declare -a SUMMARY

record() {
    if [ "$1" = "PASS" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
    SUMMARY+=("$(printf '%-4s %s | %s' "$1" "$2" "$3")")
    printf '[%s] %s | %s\n' "$1" "$2" "$3"
}

ec1() { compose exec -T client-1 "$@"; }
ec2() { compose exec -T client-2 "$@"; }
esrv() { compose exec -T server "$@"; }

log() { printf '\n== %s ==\n' "$*"; }

# ============================================================================
# bootstrap（幂等：ready 标记跳过；admin 开户路径对齐 m3_assert.sh）
# ============================================================================

bootstrap_client() { # bootstrap_client <n:1|2> <user> <pass>
    local n="$1" user="$2" pass="$3"
    ec() { compose exec -T "client-$n" "$@"; }
    if ec sh -c "test -f /var/lib/flock/ready" 2>/dev/null; then
        log "bootstrap client-$n: 已就绪（幂等跳过）"
        # VIP 从卷内 vip 文件回填（后续断言用）。
        local v
        v="$(ec sh -c 'cat /var/lib/flock/vip' 2>/dev/null | tr -d '\r\n')"
        case "$v" in 100.64.*) eval "VIP_C$n=\$v" ;; *) echo "client-$n vip 文件异常：$v"; return 1;; esac
        return 0
    fi

    # 卷内配置（[auth] username——daemon 登录态与 login 子命令共用）。
    ec sh -c "printf 'state_dir = \"/var/lib/flock\"\ntun_name = \"tun0\"\nmtu = 1280\n\n[auth]\nusername = \"$user\"\n' > $CFG_1" || return 1

    log "bootstrap client-$n: gen-keys"
    local keys
    keys="$(ec flock-client --config "$CFG_1" gen-keys)" || return 1
    local dev_x dev_ed
    dev_x="$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')"
    dev_ed="$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')"
    [ -n "$dev_x" ] && [ -n "$dev_ed" ] || { echo "client-$n gen-keys 输出异常：$keys"; return 1; }

    log "bootstrap client-$n: 服务端 device-add（--user $user）"
    local out vip
    out="$(esrv flock-server --config /etc/flock/server.toml \
        device-add --user "$user" --device-x "$dev_x" --device-ed "$dev_ed" 2>&1)" \
        || { echo "client-$n device-add 失败：$out"; return 1; }
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    case "$vip" in 100.64.*) ;; *) echo "client-$n VIP 异常：$out"; return 1;; esac
    eval "VIP_C$n=\$vip"

    log "bootstrap client-$n: invite → ingest → vip=$vip"
    local invite_b64
    invite_b64="$(esrv flock-server --config /etc/flock/server.toml invite --ttl-secs 86400)" || return 1
    printf '%s' "$invite_b64" | ec sh -c 'cat > /var/lib/flock/invite.b64' || return 1
    ec flock-client --config "$CFG_1" invite /var/lib/flock/invite.b64 || return 1
    printf '%s' "$vip" | ec sh -c 'cat > /var/lib/flock/vip' || return 1

    log "bootstrap client-$n: login（设口令 + 登录验证 + hostname 入册）"
    printf '%s\n' "$pass" | ec flock-client --config "$CFG_1" login 2>&1 | tee /tmp/m7_login_$n.log | sed 's/^/    /'
    grep -q '^login ok:' /tmp/m7_login_$n.log || { echo "client-$n login 失败（见上）"; return 1; }

    log "bootstrap client-$n: ready + restart（service daemon 接管）"
    ec sh -c 'touch /var/lib/flock/ready' || return 1
    compose restart "client-$n" >/dev/null 2>&1 || return 1

    local t=$((SECONDS + 90))
    until ec sh -c 'ip link show tun0' >/dev/null 2>&1; do
        if [ $SECONDS -ge $t ]; then
            echo "client-$n tun0 90s 未创建"; compose logs --tail 30 "client-$n"; return 1
        fi
        sleep 2
    done
    local ok=""
    t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        if ec ping -c 1 -W 2 "$SERVER_VIP" >/dev/null 2>&1; then ok=1; break; fi
        sleep 2
    done
    [ -n "$ok" ] || { echo "client-$n 90s 内 ping 不通 $SERVER_VIP"; compose logs --tail 30 "client-$n"; return 1; }
    return 0
}

bootstrap() {
    log "bootstrap: 等待 server 就绪（admin 端点）"
    local deadline=$((SECONDS + 120))
    until esrv bash -c 'exec 3<>/dev/tcp/127.0.0.1/9444 && echo ok' 2>/dev/null | grep -q ok; do
        if [ $SECONDS -ge $deadline ]; then
            echo "server admin 端点 120s 未就绪"; return 1
        fi
        sleep 2
    done
    esrv sh -c 'ip link show tun0' >/dev/null 2>&1 \
        || { echo "server tun0 未创建（dataplane down）"; compose logs --tail 40 server; return 1; }

    bootstrap_client 1 "$CLIENT_USER_1" "$PASS_1" || return 1
    bootstrap_client 2 "$CLIENT_USER_2" "$PASS_2" || return 1

    # 等两台 daemon 登录保持就绪（login ok 日志）。
    local t=$((SECONDS + 60)) ok1=0 ok2=0
    while [ $SECONDS -lt $t ]; do
        [ "$ok1" -eq 0 ] && [ "$(compose logs client-1 2>/dev/null | grep -c 'login ok' || true)" -gt 0 ] && ok1=1
        [ "$ok2" -eq 0 ] && [ "$(compose logs client-2 2>/dev/null | grep -c 'login ok' || true)" -gt 0 ] && ok2=1
        [ "$ok1" -eq 1 ] && [ "$ok2" -eq 1 ] && break
        sleep 2
    done
    [ "$ok1" -eq 1 ] && [ "$ok2" -eq 1 ] || { echo "daemon 登录未就绪（c1=$ok1 c2=$ok2）"; compose logs --tail 20 client-1 client-2; return 1; }
    echo "VIP: client-1=${VIP_C1:-?} client-2=${VIP_C2:-?}"
    return 0
}

# ============================================================================
# P1：名册装配（server + client-2 + self 三类条目）
# ============================================================================

peers_table() { # peers_table <n:1|2> → stdout（表格）
    compose exec -T "client-$1" flock-client --config "$CFG_1" peers 2>/dev/null
}

p1() {
    log "P1 名册：client-1 peers（server + client-2 + self 条目）"
    local out
    out="$(peers_table 1)"; local rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL P1 "peers 命令失败（rc=$rc）"
        return
    fi
    local ok=1 why=""
    # 服务器条目：VIP .1 + 在线 + 延迟列数字（在线 ⇒ 必有探测值）。
    printf '%s\n' "$out" | grep -E "^100\.64\.0\.1\b" | grep -q '在线' || { ok=0; why="$why server 行非在线;"; }
    local srv_row
    srv_row="$(printf '%s\n' "$out" | grep -E '^100\.64\.0\.1\b')"
    if printf '%s' "$srv_row" | awk -F'|' '{gsub(/ /,"",$6); exit ($6=="—" || $6=="") ? 1 : 0}'; then :; else ok=0; why="$why server 延迟列为—;"; fi
    # client-2 条目：hostname client-2 + 账户 m7c2 + 在线 + 延迟非 —。
    printf '%s\n' "$out" | grep -q 'client-2' || { ok=0; why="$why 无 client-2 行;"; }
    printf '%s\n' "$out" | grep 'client-2' | grep -q "$CLIENT_USER_2" || { ok=0; why="$why client-2 账户列异常;"; }
    printf '%s\n' "$out" | grep 'client-2' | grep -q '在线' || { ok=0; why="$why client-2 非在线;"; }
    if printf '%s\n' "$out" | grep 'client-2' | awk -F'|' '{gsub(/ /,"",$6); exit ($6=="—" || $6=="") ? 1 : 0}'; then :; else ok=0; why="$why client-2 延迟列为—;"; fi
    # 自身行：(self) 标注。
    printf '%s\n' "$out" | grep -q '(self)' || { ok=0; why="$why 无 (self) 行;"; }

    if [ "$ok" -eq 1 ]; then
        record PASS P1 "server/client-2/self 条目齐（在线 + 延迟数字 + 账户/主机名正确）"
    else
        record FAIL P1 "缺项：$why"
    fi
}

# ============================================================================
# P2：iperf3 跑流 → EWMA 收敛 → tx/rx 非 0
# ============================================================================

p2() {
    log "P2 流量观测：iperf3 client-1→client-2（VIP ${VIP_C2:-?}）→ ${EWMA_SETTLE}s 收敛 → peers 断言"
    if [ -z "${VIP_C2:-}" ]; then
        record FAIL P2 "client-2 VIP 未知（bootstrap 未跑）"
        return
    fi
    # iperf3 服务端挂 client-2 的 VIP（-B 绑定 ⇒ 只经隧道可达；pgrep -x 防重复起）。
    ec2 sh -c "pgrep -x iperf3 >/dev/null 2>&1 || iperf3 -s -D -B ${VIP_C2}" || true
    sleep 1
    local out
    out="$(ec1 iperf3 -c "$VIP_C2" -t 5 --format m 2>&1)"; local rc=$?
    printf '%s\n' "$out" | grep -E 'sender|receiver' | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL P2 "iperf3 失败（rc=$rc）"
        return
    fi
    echo "    等 ${EWMA_SETTLE}s（EWMA 收敛窗）…"
    sleep "$EWMA_SETTLE"
    local tbl
    tbl="$(peers_table 1)"
    printf '%s\n' "$tbl" | sed 's/^/    /'
    local ok=1 why=""
    # client-1 行：设备视角 tx（iperf 发端）非 0（↑流量列）。
    local c1_row c2_row
    c1_row="$(printf '%s\n' "$tbl" | grep '(self)')"
    c2_row="$(printf '%s\n' "$tbl" | grep 'client-2')"
    [ -n "$c1_row" ] || { ok=0; why="$why 无 self 行;"; }
    [ -n "$c2_row" ] || { ok=0; why="$why 无 client-2 行;"; }
    if [ -n "$c1_row" ]; then
        printf '%s' "$c1_row" | awk -F'|' '{gsub(/ /,"",$8); exit ($8+0<=0) ? 1 : 0}' || { ok=0; why="$why client-1 tx=0;"; }
    fi
    if [ -n "$c2_row" ]; then
        printf '%s' "$c2_row" | awk -F'|' '{gsub(/ /,"",$7); exit ($7+0<=0) ? 1 : 0}' || { ok=0; why="$why client-2 rx=0;"; }
    fi
    if [ "$ok" -eq 1 ]; then
        record PASS P2 "跑流后 client-1 tx 非 0 且 client-2 rx 非 0（设备视角计数）"
    else
        record FAIL P2 "流量断言失败：$why"
    fi
}

# ============================================================================
# P3：--json 机读档（jq 解析 + 字段语义）
# ============================================================================

p3() {
    log "P3 机读档：peers --json | jq（容器内）"
    local js
    js="$(compose exec -T client-1 flock-client --config "$CFG_1" peers --json 2>/dev/null)"; local rc=$?
    printf '%s\n' "$js" | head -12 | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL P3 "peers --json 失败（rc=$rc）"
        return
    fi
    # jq 在容器内跑（宿主无 jq 依赖——镜像已装）；过滤值经 --arg 传（内层零双引号，
    # 免 docker exec 跨 Windows 参数边界时被吃引号）。
    local ty n srv_online c2_lat
    ty="$(compose exec -T client-1 sh -c "flock-client --config $CFG_1 peers --json | jq -r 'type'" 2>/dev/null | tr -d '\r')" \
        || { record FAIL P3 "jq 解析失败"; return; }
    [ "$ty" = "array" ] || { record FAIL P3 "顶层非 array（$ty）"; return; }
    n="$(compose exec -T client-1 sh -c "flock-client --config $CFG_1 peers --json | jq 'length'" 2>/dev/null | tr -d '\r')"
    [ "${n:-0}" -ge 3 ] || { record FAIL P3 "条目数 ${n:-?} < 3"; return; }
    srv_online="$(compose exec -T client-1 sh -c "flock-client --config $CFG_1 peers --json | jq -r --arg v 100.64.0.1 '.[] | select(.vip==\$v) | .online'" 2>/dev/null | tr -d '\r')"
    [ "$srv_online" = "true" ] || { record FAIL P3 "server 条目 online != true（$srv_online）"; return; }
    c2_lat="$(compose exec -T client-1 sh -c "flock-client --config $CFG_1 peers --json | jq -r --arg h client-2 '.[] | select(.hostname==\$h) | .latency_ms'" 2>/dev/null | tr -d '\r')"
    case "$c2_lat" in
        ''|null) record FAIL P3 "client-2 latency_ms 为空/null（$c2_lat）" ;;
        *) record PASS P3 "json 数组（$n 条）+ server online + client-2 latency=${c2_lat}ms" ;;
    esac
}

# ============================================================================
# 入口
# ============================================================================

if ! docker info >/dev/null 2>&1; then
    echo "docker 不可用（Docker Desktop 是否在跑？）" >&2
    exit 2
fi
topology_up=""
for _ in $(seq 1 30); do
    if [ -n "$(compose ps -q server)" ] && [ -n "$(compose ps -q client-1)" ] && [ -n "$(compose ps -q client-2)" ]; then
        topology_up=1
        break
    fi
    sleep 2
done
if [ -z "$topology_up" ]; then
    echo "m7 拓扑未运行：先 docker compose -f $COMPOSE_FILE up -d --build" >&2
    exit 2
fi

if ! bootstrap; then
    echo "bootstrap 失败" >&2
    exit 2
fi

p1
p2
p3

log "汇总"
printf '%s\n' "${SUMMARY[@]}"
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
