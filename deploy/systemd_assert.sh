#!/usr/bin/env bash
# systemd_assert.sh —— M6 systemd 开机自启真机语义实测（docs/design.md §7-M6.3/M6.1；
# deploy/systemd-test.yml：client 容器 PID 1 = systemd，docker restart = 关机→开机）。
#
# 前置：
#   MSYS_NO_PATHCONV=1 docker compose -f deploy/systemd-test.yml up -d --build
#   bash deploy/systemd_assert.sh
#
# 断言集（全部容器内实测；S6 为加分项，脚本按硬门禁计入）：
#   S1 安装        `flock-client install --config /etc/flock/client.toml`（root、缺省
#                  scope）→ 单元落 /etc/systemd/system/flock-client.service（install.rs
#                  新常量）、is-enabled=enabled、daemon-reload 已执行（LoadState=loaded
#                  + FragmentPath）、enable --now 已拉起（is-active=active）、单元关键
#                  指令（ExecStart/Restart=on-failure/WantedBy）
#   S2 开机自启    docker restart 容器（模拟开机）→ systemd 拉起（is-active=active）
#   S3 VPN 连通    服务拉起后 tun0 出现 + ping 通 server VIP 100.64.0.1
#   S4 IPC         `flock-client status` → state=connected、vip 与 device-add 分配一致
#   S5 无头        daemon 进程环境无 DISPLAY/WAYLAND_DISPLAY/DBus 面；进程面无 tray；
#                  `flock-client tray` 无头优雅退出（码 0 + 「未检测到 GUI 会话」）
#   S6 退出语义    IPC Shutdown（postcard CtrlReq::Shutdown 帧手投——与 tray 停服同构）
#                  → CtrlResp::Ok、服务 exit 0 停止（Result=success）且 >RestartSec 不
#                  复活（Restart=on-failure）；docker restart 又自启
#
# 帧格式（§7-M6.2）：[u32 LE len][postcard]；CtrlReq 变体序 Status=0/Shutdown=1/Peers=2，
# token [u8;32]（serde 定长数组逐元素 ⇒ 32B 裸字节）。变体布局以 Status 探针实证（A=
# 裸 32B；B=varint 长度前缀 0x20+32B 备选），探针结果随取证打印。
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
COMPOSE_FILE="$HERE/systemd-test.yml"
SERVER_VIP="100.64.0.1"
CLIENT_USER="m6svc"
CFG="/etc/flock/client.toml"
UNIT_PATH="/etc/systemd/system/flock-client.service"
STATE_DIR="/var/lib/flock"
TOKEN_FILE="/var/lib/flock/client/control-token"
SOCKET="/run/flock/client.sock"

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }
ec() { compose exec -T client "$@"; }
esrv() { compose exec -T server "$@"; }

PASS=0
FAIL=0
declare -a SUMMARY

record() {
    if [ "$1" = "PASS" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
    SUMMARY+=("$(printf '%-4s %s | %s' "$1" "$2" "$3")")
    printf '[%s] %s | %s\n' "$1" "$2" "$3"
}

log() { printf '\n== %s ==\n' "$*"; }

evidence() { # 失败取证：journal + status
    ec journalctl -u flock-client --no-pager -n 30 2>/dev/null | sed 's/^/    jr /'
    ec systemctl status flock-client --no-pager -l 2>/dev/null | sed 's/^/    st /'
}

# ============================================================================
# bootstrap（admin 开户路径，对齐 m3/m7：gen-keys → device-add → invite → ingest → vip；
# ready 标记幂等；本拓扑无 [auth]/login——M6 服务语义面不需要登录保持）
# ============================================================================

bootstrap() {
    log "bootstrap: 等待 server 就绪（admin 端点 + 数据面 tun0）"
    local deadline=$((SECONDS + 120))
    until esrv bash -c 'exec 3<>/dev/tcp/127.0.0.1/9444 && echo ok' 2>/dev/null | grep -q ok; do
        if [ $SECONDS -ge $deadline ]; then
            echo "server admin 端点 120s 未就绪"; return 1
        fi
        sleep 2
    done
    esrv sh -c 'test -d /sys/class/net/tun0' >/dev/null 2>&1 \
        || { echo "server tun0 未创建（dataplane down）"; compose logs --tail 30 server; return 1; }

    if ec sh -c "test -f $STATE_DIR/ready" 2>/dev/null; then
        log "bootstrap client: 已就绪（幂等跳过）"
        local v
        v="$(ec sh -c "cat $STATE_DIR/vip" 2>/dev/null | tr -d '\r\n')"
        case "$v" in 100.64.*) VIP_C="$v" ;; *) echo "client vip 文件异常：$v"; return 1;; esac
        return 0
    fi

    log "bootstrap client: gen-keys"
    local keys dev_x dev_ed
    keys="$(ec flock-client --config "$CFG" gen-keys)" || return 1
    dev_x="$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')"
    dev_ed="$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')"
    [ -n "$dev_x" ] && [ -n "$dev_ed" ] || { echo "gen-keys 输出异常：$keys"; return 1; }

    log "bootstrap client: 服务端 device-add（--user $CLIENT_USER）"
    local out vip
    out="$(esrv flock-server --config /etc/flock/server.toml \
        device-add --user "$CLIENT_USER" --device-x "$dev_x" --device-ed "$dev_ed" 2>&1)" \
        || { echo "device-add 失败：$out"; return 1; }
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    case "$vip" in 100.64.*) ;; *) echo "VIP 异常：$out"; return 1;; esac
    VIP_C="$vip"

    log "bootstrap client: invite → ingest → vip=$vip"
    local invite_b64
    invite_b64="$(esrv flock-server --config /etc/flock/server.toml invite --ttl-secs 86400)" || return 1
    printf '%s' "$invite_b64" | ec sh -c "cat > $STATE_DIR/invite.b64" || return 1
    ec flock-client --config "$CFG" invite "$STATE_DIR/invite.b64" || return 1
    printf '%s' "$vip" | ec sh -c "cat > $STATE_DIR/vip" || return 1
    ec sh -c "touch $STATE_DIR/ready" || return 1
    return 0
}

# ============================================================================
# S1：安装（install → 单元路径/is-enabled/daemon-reload/enable --now/关键指令）
# ============================================================================

s1() {
    log "S1 安装：flock-client install --config $CFG（root，缺省 scope = 服务+托盘自启）"
    local out rc
    out="$(ec flock-client --config "$CFG" install 2>&1)"; rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL S1 "install 退出码 $rc"
        return
    fi
    local ok=1 why="" v
    ec test -f "$UNIT_PATH" 2>/dev/null || { ok=0; why="$why 单元未落 $UNIT_PATH;"; }
    v="$(ec systemctl is-enabled flock-client 2>/dev/null | tr -d '\r')"
    [ "$v" = "enabled" ] || { ok=0; why="$why is-enabled=$v;"; }
    # daemon-reload 已执行的证据：systemd 已装载该单元（LoadState=loaded 且 FragmentPath
    # 指向新路径——未 reload 时为 not-found）。
    v="$(ec systemctl show flock-client -p LoadState --value 2>/dev/null | tr -d '\r')"
    [ "$v" = "loaded" ] || { ok=0; why="$why LoadState=$v（daemon-reload 未生效？）;"; }
    v="$(ec systemctl show flock-client -p FragmentPath --value 2>/dev/null | tr -d '\r')"
    [ "$v" = "$UNIT_PATH" ] || { ok=0; why="$why FragmentPath=$v;"; }
    # enable --now 的执行面：服务已在跑。
    v="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
    [ "$v" = "active" ] || { ok=0; why="$why is-active=$v（enable --now 未拉起？）;"; }
    # 单元内容关键指令（install.rs render_systemd_unit 面）。
    local unit
    unit="$(ec cat "$UNIT_PATH" 2>/dev/null)"
    printf '%s\n' "$unit" | grep -q "ExecStart=/usr/local/bin/flock-client service --config $CFG" \
        || { ok=0; why="$why ExecStart 异常;"; }
    printf '%s\n' "$unit" | grep -q '^Restart=on-failure' || { ok=0; why="$why Restart 指令异常;"; }
    printf '%s\n' "$unit" | grep -q '^WantedBy=multi-user.target' || { ok=0; why="$why WantedBy 异常;"; }
    if [ "$ok" -eq 1 ]; then
        record PASS S1 "单元落 $UNIT_PATH + enabled + loaded(daemon-reload) + active(enable --now) + 指令齐"
    else
        record FAIL S1 "缺项：$why"
        evidence
    fi
}

# ============================================================================
# S2：开机自启（docker restart 容器 = 模拟开机 → systemd 拉起）
# ============================================================================

s2() {
    log "S2 开机自启：docker compose restart client（STOPSIGNAL SIGRTMIN+3 → systemd 关机；再开机）"
    compose restart client >/dev/null 2>&1 || { record FAIL S2 "docker restart 失败"; return; }
    local act="" t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        act="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
        [ "$act" = "active" ] && break
        sleep 2
    done
    if [ "$act" = "active" ]; then
        record PASS S2 "开机后 systemd 拉起 flock-client（is-active=active）"
    else
        record FAIL S2 "is-active=$act（90s）"
        evidence
    fi
}

# ============================================================================
# S3：VPN 连通（tun0 + ping server VIP）
# ============================================================================

s3() {
    log "S3 VPN 连通：tun0 出现 + ping $SERVER_VIP"
    local t=$((SECONDS + 90))
    until ec ip link show tun0 >/dev/null 2>&1; do
        if [ $SECONDS -ge $t ]; then
            record FAIL S3 "tun0 90s 未创建"
            evidence
            return
        fi
        sleep 2
    done
    ec ip -4 addr show tun0 2>/dev/null | grep -E 'inet |mtu' | sed 's/^/    /'
    local ok="" t2=$((SECONDS + 90))
    while [ $SECONDS -lt $t2 ]; do
        if ec ping -c 3 -W 2 "$SERVER_VIP" >/dev/null 2>&1; then ok=1; break; fi
        sleep 2
    done
    if [ -n "$ok" ]; then
        record PASS S3 "tun0 在位且 ping $SERVER_VIP 通（3/3）"
    else
        record FAIL S3 "90s 内 ping 不通 $SERVER_VIP"
        evidence
    fi
}

# ============================================================================
# S4：IPC status（state=connected + vip 正确）
# ============================================================================

s4() {
    log "S4 IPC：flock-client status → state=connected、vip=${VIP_C:-?}"
    local out state vip
    out="$(ec flock-client status 2>&1)"
    printf '%s\n' "$out" | sed 's/^/    /'
    state="$(printf '%s\n' "$out" | sed -n 's/^state=//p' | tr -d '\r')"
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    if [ "$state" = "connected" ] && [ "$vip" = "${VIP_C:-}" ]; then
        record PASS S4 "status: state=connected vip=$vip（与 device-add 分配一致）"
    else
        record FAIL S4 "state=${state:-?} vip=${vip:-?}（期望 connected / ${VIP_C:-?}）"
    fi
}

# ============================================================================
# S5：无头（无 DISPLAY/DBus；无 tray 进程；tray 子命令优雅退出）
# ============================================================================

s5() {
    log "S5 无头：daemon 环境无 GUI/DBus 面 + 无 tray 进程 + tray 子命令优雅退出"
    local ok=1 why="" pid env
    pid="$(ec systemctl show flock-client -p MainPID --value 2>/dev/null | tr -d '\r')"
    case "$pid" in ''|0) ok=0; why="$why MainPID=$pid（服务未跑？）;";; esac
    if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        env="$(ec sh -c "tr '\0' '\n' < /proc/$pid/environ" 2>/dev/null)"
        for v in DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR; do
            if printf '%s\n' "$env" | grep -q "^$v="; then
                ok=0; why="$why daemon 环境含 $v;"
            fi
        done
        printf '%s\n' "$env" | wc -l | sed 's/^/    （daemon 环境变量数） /'
    fi
    # 进程面：唯一 flock-client 进程 = service（无 tray）。
    local procs n
    procs="$(ec pgrep -af flock-client 2>/dev/null | tr -d '\r')"
    printf '%s\n' "$procs" | sed 's/^/    ps /'
    n="$(printf '%s\n' "$procs" | grep -c . )"
    [ "${n:-0}" -eq 1 ] || { ok=0; why="$why flock-client 进程数=${n:-0};"; }
    printf '%s\n' "$procs" | grep -q "service --config $CFG" || { ok=0; why="$why 进程非 service 形态;"; }
    printf '%s\n' "$procs" | grep -q 'tray' && { ok=0; why="$why 存在 tray 进程;"; }
    # journal 无 panic/报错面。
    if ec journalctl -u flock-client --no-pager 2>/dev/null | grep -qi 'panic'; then
        ok=0; why="$why journal 含 panic;"
    fi
    # tray 子命令：无头优雅退出（码 0 + 探测文案）。
    local tout trc
    tout="$(ec timeout 10 flock-client tray 2>&1)"; trc=$?
    printf '%s\n' "$tout" | sed 's/^/    tray /'
    [ "$trc" -eq 0 ] || { ok=0; why="$why tray 退出码=$trc（期望 0）;"; }
    printf '%s\n' "$tout" | grep -q '未检测到 GUI 会话' || { ok=0; why="$why tray 无头文案缺失;"; }
    # tray 退出后进程面仍无 tray。
    ec pgrep -af flock-client 2>/dev/null | grep -q 'tray' && { ok=0; why="$why tray 进程残留;"; }
    if [ "$ok" -eq 1 ]; then
        record PASS S5 "无 DISPLAY/DBus、唯一 service 进程、tray 无头优雅退出（码 0）"
    else
        record FAIL S5 "缺项：$why"
    fi
}

# ============================================================================
# S6：退出语义（IPC Shutdown → exit 0 不复活；docker restart 又自启）
# ============================================================================

s6() {
    log "S6 退出语义：IPC Shutdown 帧（postcard CtrlReq::Shutdown——与 tray 停服同构）"
    # 探针 + Shutdown 帧都在容器内构造（token 不出容器；bash printf \x 转义 + od 校验）。
    local probe
    probe="$(compose exec -T client bash -s <<'EOS' 2>&1
set -u
hex="$(cat /var/lib/flock/client/control-token 2>/dev/null)" || { echo "probe_err=no_token_file"; exit 0; }
tok=""
i=0
while [ "$i" -lt 64 ]; do tok="$tok\\x${hex:$i:2}"; i=$((i+2)); done
# ① Status 探针（幂等无副作用）确定 token [u8;32] 的 postcard 布局：
#    A = 32B 裸字节（serde 定长数组逐元素）；B = varint 长度前缀 + 32B。
stA="$(printf "\\x21\\x00\\x00\\x00\\x00$tok" | timeout 5 socat -t 3 - UNIX-CONNECT:/run/flock/client.sock 2>/dev/null | od -An -tx1 | tr -d ' \n')"
if [ -n "$stA" ]; then
    echo "layout=A status_resp_head=${stA:0:20}"
    layout=A
else
    stB="$(printf "\\x22\\x00\\x00\\x00\\x00\\x20$tok" | timeout 5 socat -t 3 - UNIX-CONNECT:/run/flock/client.sock 2>/dev/null | od -An -tx1 | tr -d ' \n')"
    if [ -n "$stB" ]; then
        echo "layout=B status_resp_head=${stB:0:20}"
        layout=B
    else
        echo "probe_err=no_status_response"
        exit 0
    fi
fi
# ② Shutdown（CtrlReq 变体 1）→ 期望 CtrlResp::Ok = 帧 01 00 00 00 01。
if [ "$layout" = A ]; then
    out="$(printf "\\x21\\x00\\x00\\x00\\x01$tok" | timeout 5 socat -t 3 - UNIX-CONNECT:/run/flock/client.sock 2>/dev/null | od -An -tx1 | tr -d ' \n')"
else
    out="$(printf "\\x22\\x00\\x00\\x00\\x01\\x20$tok" | timeout 5 socat -t 3 - UNIX-CONNECT:/run/flock/client.sock 2>/dev/null | od -An -tx1 | tr -d ' \n')"
fi
echo "shutdown_resp=$out"
EOS
)"
    printf '%s\n' "$probe" | sed 's/^/    /'
    local resp
    resp="$(printf '%s\n' "$probe" | sed -n 's/^shutdown_resp=//p' | tr -d '\r')"
    if printf '%s\n' "$probe" | grep -q 'probe_err'; then
        record FAIL S6 "探针失败：$probe"
        evidence
        return
    fi
    if [ "$resp" != "0100000001" ]; then
        # 0100000004 = CtrlResp::Denied（token 失配）；空 = 无响应。
        record FAIL S6 "Shutdown 响应帧=${resp:-<空>}（期望 0100000001 = CtrlResp::Ok）"
        evidence
        return
    fi
    # Shutdown 受理 → 服务停止（Result=success ⇒ exit 0）。
    local act="" t=$((SECONDS + 30))
    while [ $SECONDS -lt $t ]; do
        act="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
        [ "$act" = "inactive" ] || [ "$act" = "failed" ] && break
        sleep 1
    done
    local result st
    result="$(ec systemctl show flock-client -p Result --value 2>/dev/null | tr -d '\r')"
    st="$(ec systemctl show flock-client -p ExecMainStatus --value 2>/dev/null | tr -d '\r')"
    if [ "$act" != "inactive" ] || [ "$result" != "success" ] || [ "$st" != "0" ]; then
        record FAIL S6 "停服态异常：is-active=$act Result=$result ExecMainStatus=$st（期望 inactive/success/0）"
        evidence
        return
    fi
    # >RestartSec（5s）不复活（Restart=on-failure 只对失败退出动作）。
    echo "    等 8s（> RestartSec=5）验证不复活…"
    sleep 8
    act="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
    local enabled
    enabled="$(ec systemctl is-enabled flock-client 2>/dev/null | tr -d '\r')"
    if [ "$act" != "inactive" ]; then
        record FAIL S6 "优雅停服后被复活（is-active=$act）——Restart 语义异常"
        evidence
        return
    fi
    # 再次开机（docker restart）→ 又自启。
    compose restart client >/dev/null 2>&1 || { record FAIL S6 "docker restart 失败"; return; }
    act=""
    t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        act="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
        [ "$act" = "active" ] && break
        sleep 2
    done
    if [ "$act" = "active" ] && [ "$enabled" = "enabled" ]; then
        record PASS S6 "Shutdown→Ok、exit 0（Result=success）不复活；docker restart 又自启（enabled 保持）"
    else
        record FAIL S6 "重启后 is-active=$act is-enabled=$enabled"
        evidence
    fi
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
    if [ -n "$(compose ps -q server)" ] && [ -n "$(compose ps -q client)" ]; then
        topology_up=1
        break
    fi
    sleep 2
done
if [ -z "$topology_up" ]; then
    echo "systemd-test 拓扑未运行：先 MSYS_NO_PATHCONV=1 docker compose -f $COMPOSE_FILE up -d --build" >&2
    exit 2
fi

# systemd 起来前置探测（boot 就绪面：is-system-running 容忍 degraded——剥单机面后
# 个别掩埋单元可能标记 degraded，本实测只消费 flock-client 单元面）。
log "前置：容器内 systemd 就绪探测"
sdstate=""
_t=$((SECONDS + 60))
while [ $SECONDS -lt $_t ]; do
    sdstate="$(ec systemctl is-system-running 2>/dev/null | tr -d '\r')"
    case "$sdstate" in running|degraded) break ;; esac
    sleep 2
done
printf 'systemctl is-system-running = %s\n' "${sdstate:-<未响应>}"
case "$sdstate" in
    running|degraded) ;;
    *) echo "容器内 systemd 未就绪（is-system-running=${sdstate:-?}）" >&2
       compose logs --tail 30 client >&2
       exit 2 ;;
esac

if ! bootstrap; then
    echo "bootstrap 失败" >&2
    exit 2
fi
echo "VIP: client=${VIP_C:-?}"

s1
s2
s3
s4
s5
s6

log "汇总"
printf '%s\n' "${SUMMARY[@]}"
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
