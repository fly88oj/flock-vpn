#!/usr/bin/env bash
# systemd_assert.sh —— M6 systemd boot-autostart real-machine semantics, measured in
# containers (docs/design.md §7-M6.3/M6.1; deploy/systemd-test.yml: the client
# container runs systemd as PID 1, docker restart = shutdown→boot).
#
# Prerequisites:
#   MSYS_NO_PATHCONV=1 docker compose -f deploy/systemd-test.yml up -d --build
#   bash deploy/systemd_assert.sh
#
# Assertion set (all measured inside containers; S6 is a bonus item, counted as a
# hard gate by this script):
#   S1 install      `flock-client install --config /etc/flock/client.toml` (root,
#                   default scope) → unit lands at /etc/systemd/system/flock-client.service
#                   (the new constant in install.rs), is-enabled=enabled, daemon-reload
#                   executed (LoadState=loaded + FragmentPath), enable --now started it
#                   (is-active=active), unit key directives (ExecStart/Restart=on-failure/
#                   WantedBy)
#   S2 boot autostart  docker restart the container (simulated boot) → systemd starts it
#                   (is-active=active)
#   S3 VPN up       after the service starts, tun0 appears + ping to server VIP
#                   100.64.0.1 works
#   S4 IPC          `flock-client status` → state=connected, vip matches the
#                   device-add assignment
#   S5 headless     the daemon process environment has no DISPLAY/WAYLAND_DISPLAY/DBus
#                   surface; no tray process; `flock-client tray` exits gracefully
#                   headless (code 0 + "no GUI session detected")
#   S6 exit semantics  IPC Shutdown (postcard CtrlReq::Shutdown frame submitted by hand
#                   —— isomorphic to the tray stopping the service) → CtrlResp::Ok,
#                   the service exits 0 and stops (Result=success) and does not revive
#                   after >RestartSec (Restart=on-failure); docker restart autostarts
#                   it again
#
# Frame format (§7-M6.2): [u32 LE len][postcard]; CtrlReq variant ordinals Status=0/
# Shutdown=1/Peers=2, token [u8;32] (serde fixed-length array element-wise ⇒ 32B of raw
# bytes). The variant layout is proven by the Status probe (A = raw 32B; B = varint
# length prefix 0x20 + 32B as the alternative); probe results are printed with the
# evidence.
#
# Summary: per-item PASS/FAIL at the end; any FAIL ⇒ non-zero exit code.
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

evidence() { # failure evidence: journal + status
    ec journalctl -u flock-client --no-pager -n 30 2>/dev/null | sed 's/^/    jr /'
    ec systemctl status flock-client --no-pager -l 2>/dev/null | sed 's/^/    st /'
}

# ============================================================================
# bootstrap (admin onboarding path, aligned with m3/m7: gen-keys → device-add →
# invite → ingest → vip; ready marker for idempotence; no [auth]/login in this
# topology —— the M6 service-semantics surface needs no login keepalive)
# ============================================================================

bootstrap() {
    log "bootstrap: waiting for the server to be ready (admin endpoint + data plane tun0)"
    local deadline=$((SECONDS + 120))
    until esrv bash -c 'exec 3<>/dev/tcp/127.0.0.1/9444 && echo ok' 2>/dev/null | grep -q ok; do
        if [ $SECONDS -ge $deadline ]; then
            echo "server admin endpoint not ready within 120s"; return 1
        fi
        sleep 2
    done
    esrv sh -c 'test -d /sys/class/net/tun0' >/dev/null 2>&1 \
        || { echo "server tun0 not created (dataplane down)"; compose logs --tail 30 server; return 1; }

    if ec sh -c "test -f $STATE_DIR/ready" 2>/dev/null; then
        log "bootstrap client: already ready (idempotent skip)"
        local v
        v="$(ec sh -c "cat $STATE_DIR/vip" 2>/dev/null | tr -d '\r\n')"
        case "$v" in 100.64.*) VIP_C="$v" ;; *) echo "client vip file abnormal: $v"; return 1;; esac
        return 0
    fi

    log "bootstrap client: gen-keys"
    local keys dev_x dev_ed
    keys="$(ec flock-client --config "$CFG" gen-keys)" || return 1
    dev_x="$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')"
    dev_ed="$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')"
    [ -n "$dev_x" ] && [ -n "$dev_ed" ] || { echo "gen-keys output abnormal: $keys"; return 1; }

    log "bootstrap client: server-side device-add (--user $CLIENT_USER)"
    local out vip
    out="$(esrv flock-server --config /etc/flock/server.toml \
        device-add --user "$CLIENT_USER" --device-x "$dev_x" --device-ed "$dev_ed" 2>&1)" \
        || { echo "device-add failed: $out"; return 1; }
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    case "$vip" in 100.64.*) ;; *) echo "VIP abnormal: $out"; return 1;; esac
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
# S1: install (install → unit path / is-enabled / daemon-reload / enable --now /
#     key directives)
# ============================================================================

s1() {
    log "S1 install: flock-client install --config $CFG (root, default scope = service + tray autostart)"
    local out rc
    out="$(ec flock-client --config "$CFG" install 2>&1)"; rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL S1 "install exit code $rc"
        return
    fi
    local ok=1 why="" v
    ec test -f "$UNIT_PATH" 2>/dev/null || { ok=0; why="$why unit not at $UNIT_PATH;"; }
    v="$(ec systemctl is-enabled flock-client 2>/dev/null | tr -d '\r')"
    [ "$v" = "enabled" ] || { ok=0; why="$why is-enabled=$v;"; }
    # Evidence that daemon-reload ran: systemd has loaded the unit (LoadState=loaded
    # and FragmentPath pointing at the new path —— not-found when no reload happened).
    v="$(ec systemctl show flock-client -p LoadState --value 2>/dev/null | tr -d '\r')"
    [ "$v" = "loaded" ] || { ok=0; why="$why LoadState=$v (daemon-reload not effective?);"; }
    v="$(ec systemctl show flock-client -p FragmentPath --value 2>/dev/null | tr -d '\r')"
    [ "$v" = "$UNIT_PATH" ] || { ok=0; why="$why FragmentPath=$v;"; }
    # The execution face of enable --now: the service is running.
    v="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
    [ "$v" = "active" ] || { ok=0; why="$why is-active=$v (enable --now did not start it?);"; }
    # Unit content key directives (the install.rs render_systemd_unit surface).
    local unit
    unit="$(ec cat "$UNIT_PATH" 2>/dev/null)"
    printf '%s\n' "$unit" | grep -q "ExecStart=/usr/local/bin/flock-client service --config $CFG" \
        || { ok=0; why="$why ExecStart abnormal;"; }
    printf '%s\n' "$unit" | grep -q '^Restart=on-failure' || { ok=0; why="$why Restart directive abnormal;"; }
    printf '%s\n' "$unit" | grep -q '^WantedBy=multi-user.target' || { ok=0; why="$why WantedBy abnormal;"; }
    if [ "$ok" -eq 1 ]; then
        record PASS S1 "unit at $UNIT_PATH + enabled + loaded(daemon-reload) + active(enable --now) + directives complete"
    else
        record FAIL S1 "missing items: $why"
        evidence
    fi
}

# ============================================================================
# S2: boot autostart (docker restart the container = simulated boot → systemd
#     starts the service)
# ============================================================================

s2() {
    log "S2 boot autostart: docker compose restart client (STOPSIGNAL SIGRTMIN+3 → systemd shutdown; then boot again)"
    compose restart client >/dev/null 2>&1 || { record FAIL S2 "docker restart failed"; return; }
    local act="" t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        act="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
        [ "$act" = "active" ] && break
        sleep 2
    done
    if [ "$act" = "active" ]; then
        record PASS S2 "after boot, systemd started flock-client (is-active=active)"
    else
        record FAIL S2 "is-active=$act (90s)"
        evidence
    fi
}

# ============================================================================
# S3: VPN connectivity (tun0 + ping server VIP)
# ============================================================================

s3() {
    log "S3 VPN connectivity: tun0 appears + ping $SERVER_VIP"
    local t=$((SECONDS + 90))
    until ec ip link show tun0 >/dev/null 2>&1; do
        if [ $SECONDS -ge $t ]; then
            record FAIL S3 "tun0 not created within 90s"
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
        record PASS S3 "tun0 in place and ping $SERVER_VIP works (3/3)"
    else
        record FAIL S3 "ping to $SERVER_VIP not working within 90s"
        evidence
    fi
}

# ============================================================================
# S4: IPC status (state=connected + vip correct)
# ============================================================================

s4() {
    log "S4 IPC: flock-client status → state=connected, vip=${VIP_C:-?}"
    local out state vip
    out="$(ec flock-client status 2>&1)"
    printf '%s\n' "$out" | sed 's/^/    /'
    state="$(printf '%s\n' "$out" | sed -n 's/^state=//p' | tr -d '\r')"
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    if [ "$state" = "connected" ] && [ "$vip" = "${VIP_C:-}" ]; then
        record PASS S4 "status: state=connected vip=$vip (matches the device-add assignment)"
    else
        record FAIL S4 "state=${state:-?} vip=${vip:-?} (expected connected / ${VIP_C:-?})"
    fi
}

# ============================================================================
# S5: headless (no DISPLAY/DBus; no tray process; tray subcommand exits gracefully)
# ============================================================================

s5() {
    log "S5 headless: daemon environment has no GUI/DBus surface + no tray process + tray subcommand exits gracefully"
    local ok=1 why="" pid env
    pid="$(ec systemctl show flock-client -p MainPID --value 2>/dev/null | tr -d '\r')"
    case "$pid" in ''|0) ok=0; why="$why MainPID=$pid (service not running?);";; esac
    if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        env="$(ec sh -c "tr '\0' '\n' < /proc/$pid/environ" 2>/dev/null)"
        for v in DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR; do
            if printf '%s\n' "$env" | grep -q "^$v="; then
                ok=0; why="$why daemon environment contains $v;"
            fi
        done
        printf '%s\n' "$env" | wc -l | sed 's/^/    (daemon env var count) /'
    fi
    # Process surface: the only flock-client process = service (no tray).
    local procs n
    procs="$(ec pgrep -af flock-client 2>/dev/null | tr -d '\r')"
    printf '%s\n' "$procs" | sed 's/^/    ps /'
    n="$(printf '%s\n' "$procs" | grep -c . )"
    [ "${n:-0}" -eq 1 ] || { ok=0; why="$why flock-client process count=${n:-0};"; }
    printf '%s\n' "$procs" | grep -q "service --config $CFG" || { ok=0; why="$why process not in service form;"; }
    printf '%s\n' "$procs" | grep -q 'tray' && { ok=0; why="$why a tray process exists;"; }
    # No panic/error surface in the journal.
    if ec journalctl -u flock-client --no-pager 2>/dev/null | grep -qi 'panic'; then
        ok=0; why="$why journal contains panic;"
    fi
    # tray subcommand: graceful headless exit (code 0 + the probe message).
    local tout trc
    tout="$(ec timeout 10 flock-client tray 2>&1)"; trc=$?
    printf '%s\n' "$tout" | sed 's/^/    tray /'
    [ "$trc" -eq 0 ] || { ok=0; why="$why tray exit code=$trc (expected 0);"; }
    printf '%s\n' "$tout" | grep -q 'no GUI session detected' || { ok=0; why="$why tray headless message missing;"; }
    # Still no tray process after the tray subcommand exits.
    ec pgrep -af flock-client 2>/dev/null | grep -q 'tray' && { ok=0; why="$why tray process left behind;"; }
    if [ "$ok" -eq 1 ]; then
        record PASS S5 "no DISPLAY/DBus, single service process, tray exits gracefully headless (code 0)"
    else
        record FAIL S5 "missing items: $why"
    fi
}

# ============================================================================
# S6: exit semantics (IPC Shutdown → exit 0 no revival; docker restart
#     autostarts again)
# ============================================================================

s6() {
    log "S6 exit semantics: IPC Shutdown frame (postcard CtrlReq::Shutdown —— isomorphic to the tray stopping the service)"
    # The probe + the Shutdown frame are both built inside the container (the
    # token never leaves it; bash printf \x escapes + od verification).
    local probe
    probe="$(compose exec -T client bash -s <<'EOS' 2>&1
set -u
hex="$(cat /var/lib/flock/client/control-token 2>/dev/null)" || { echo "probe_err=no_token_file"; exit 0; }
tok=""
i=0
while [ "$i" -lt 64 ]; do tok="$tok\\x${hex:$i:2}"; i=$((i+2)); done
# ① The Status probe (idempotent, side-effect-free) determines the postcard
#    layout of the token [u8;32]:
#    A = 32B raw bytes (serde fixed-length array element-wise); B = varint
#    length prefix + 32B.
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
# ② Shutdown (CtrlReq variant 1) → expect CtrlResp::Ok = frame 01 00 00 00 01.
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
        record FAIL S6 "probe failed: $probe"
        evidence
        return
    fi
    if [ "$resp" != "0100000001" ]; then
        # 0100000004 = CtrlResp::Denied (token mismatch); empty = no response.
        record FAIL S6 "Shutdown response frame=${resp:-<empty>} (expected 0100000001 = CtrlResp::Ok)"
        evidence
        return
    fi
    # Shutdown accepted → the service stops (Result=success ⇒ exit 0).
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
        record FAIL S6 "stopped-state abnormal: is-active=$act Result=$result ExecMainStatus=$st (expected inactive/success/0)"
        evidence
        return
    fi
    # >RestartSec (5s) without revival (Restart=on-failure only acts on failed exits).
    echo "    waiting 8s (> RestartSec=5) to verify no revival..."
    sleep 8
    act="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
    local enabled
    enabled="$(ec systemctl is-enabled flock-client 2>/dev/null | tr -d '\r')"
    if [ "$act" != "inactive" ]; then
        record FAIL S6 "revived after graceful stop (is-active=$act) —— Restart semantics abnormal"
        evidence
        return
    fi
    # Boot again (docker restart) → autostarts again.
    compose restart client >/dev/null 2>&1 || { record FAIL S6 "docker restart failed"; return; }
    act=""
    t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        act="$(ec systemctl is-active flock-client 2>/dev/null | tr -d '\r')"
        [ "$act" = "active" ] && break
        sleep 2
    done
    if [ "$act" = "active" ] && [ "$enabled" = "enabled" ]; then
        record PASS S6 "Shutdown→Ok, exit 0 (Result=success) no revival; docker restart autostarts again (enabled kept)"
    else
        record FAIL S6 "after restart is-active=$act is-enabled=$enabled"
        evidence
    fi
}

# ============================================================================
# Entry point
# ============================================================================

if ! docker info >/dev/null 2>&1; then
    echo "docker unavailable (is Docker Desktop running?)" >&2
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
    echo "systemd-test topology not running: first MSYS_NO_PATHCONV=1 docker compose -f $COMPOSE_FILE up -d --build" >&2
    exit 2
fi

# Pre-probe that systemd is up (the boot-ready surface: is-system-running
# tolerates degraded —— after stripping the single-machine surface a few masked
# units may report degraded; this test only consumes the flock-client unit
# surface).
log "pre-check: systemd readiness probe inside the container"
sdstate=""
_t=$((SECONDS + 60))
while [ $SECONDS -lt $_t ]; do
    sdstate="$(ec systemctl is-system-running 2>/dev/null | tr -d '\r')"
    case "$sdstate" in running|degraded) break ;; esac
    sleep 2
done
printf 'systemctl is-system-running = %s\n' "${sdstate:-<no response>}"
case "$sdstate" in
    running|degraded) ;;
    *) echo "systemd inside the container not ready (is-system-running=${sdstate:-?})" >&2
       compose logs --tail 30 client >&2
       exit 2 ;;
esac

if ! bootstrap; then
    echo "bootstrap failed" >&2
    exit 2
fi
echo "VIP: client=${VIP_C:-?}"

s1
s2
s3
s4
s5
s6

log "Summary"
printf '%s\n' "${SUMMARY[@]}"
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
