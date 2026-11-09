#!/usr/bin/env bash
# m7_assert.sh —— M7 client roster assertions (docs/design.md §7-M7.7 completion
# criteria: measured in containers).
#
# Prerequisites:
#   docker compose -f deploy/m7.yml up -d --build
#   bash deploy/m7_assert.sh
#
# Assertion set:
#   P1 roster assembly   client-1 `flock-client peers`: contains the server and
#                        client-2 entries (hostname client-2 / account m7c2 /
#                        online / latency not —) plus its own (self) row
#   P2 traffic observability  after iperf3 client-1→client-2 runs a flow (EWMA
#                        convergence window ~10s), peers again: client-1 tx and
#                        client-2 rx non-zero (the "device view" counters)
#   P3 machine-readable  `peers --json` parseable (jq) with correct field
#                        semantics (vip/online/latency)
#
# Credential bootstrap = the admin onboarding path (aligned with the existing
# m3 script): gen-keys → device-add → invite → ingest → vip → `flock-client
# login` (set password + login verification + hostname registered) → ready.
#
# re-login window retries: the daemon's login keepalive re-logs-in per the
# refresh_after period (server ticket_ttl=6s ⇒ 4s); during the brief LoggingIn
# window peers returns PeersUnavailable (the guidance message says "retry
# shortly") —— peers-type queries get bounded retries via flock_retry/sh_retry
# (PEERS_RETRIES times) to ride out that transient; the assertion thresholds
# (entry count / online / latency / traffic non-zero) are not relaxed by the
# retries.
#
# This run is not executed on a Windows host (tun needs privileges + the WSL2
# backend) —— the real-machine checklist:
# docs/manual/service-install.md (the M7 entry).
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
COMPOSE_FILE="$HERE/m7.yml"
NETWORK="flock-m7net"
SERVER_VIP="100.64.0.1"
CLIENT_USER_1="m7c1"
CLIENT_USER_2="m7c2"
PASS_1="m7-pass-1"
PASS_2="m7-pass-2"
CFG_1="/var/lib/flock/client.toml"
EWMA_SETTLE=12   # wait for EWMA convergence display after the iperf flow stops (α=0.2/1s fold —— a 10s-scale window)
# Retries for the re-login window of the daemon's login keepalive (M7 re-run
# field-proven: server ticket_ttl=6s ⇒ re-login every refresh_after=4s; during
# the brief phase=LoggingIn window peers returns PeersUnavailable ("login in
# progress (retry shortly)") —— the CLI guidance message says exactly that;
# the assertion script applies bounded retries to **that semantic transient**
# (~5% hit rate per query; residual probability after 6×2s backoff is
# negligible). Numeric/semantic thresholds unchanged —— the original
# assertions still apply to the final successful output (entry count / fields
# / traffic-column thresholds are not relaxed at all).
PEERS_RETRIES=6
PEERS_RETRY_SLEEP=2

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
# bootstrap (idempotent: ready marker skips; admin onboarding path aligned
# with m3_assert.sh)
# ============================================================================

bootstrap_client() { # bootstrap_client <n:1|2> <user> <pass>
    local n="$1" user="$2" pass="$3"
    ec() { compose exec -T "client-$n" "$@"; }
    if ec sh -c "test -f /var/lib/flock/ready" 2>/dev/null; then
        log "bootstrap client-$n: already ready (idempotent skip)"
        # VIP backfilled from the in-volume vip file (used by later assertions).
        local v
        v="$(ec sh -c 'cat /var/lib/flock/vip' 2>/dev/null | tr -d '\r\n')"
        case "$v" in 100.64.*) eval "VIP_C$n=\$v" ;; *) echo "client-$n vip file abnormal: $v"; return 1;; esac
        return 0
    fi

    # In-volume config ([auth] username —— shared by the daemon's login state
    # and the login subcommand).
    ec sh -c "printf 'state_dir = \"/var/lib/flock\"\ntun_name = \"tun0\"\nmtu = 1280\n\n[auth]\nusername = \"$user\"\n' > $CFG_1" || return 1

    log "bootstrap client-$n: gen-keys"
    local keys
    keys="$(ec flock-client --config "$CFG_1" gen-keys)" || return 1
    local dev_x dev_ed
    dev_x="$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')"
    dev_ed="$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')"
    [ -n "$dev_x" ] && [ -n "$dev_ed" ] || { echo "client-$n gen-keys output abnormal: $keys"; return 1; }

    log "bootstrap client-$n: server-side device-add (--user $user)"
    local out vip
    out="$(esrv flock-server --config /etc/flock/server.toml \
        device-add --user "$user" --device-x "$dev_x" --device-ed "$dev_ed" 2>&1)" \
        || { echo "client-$n device-add failed: $out"; return 1; }
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    case "$vip" in 100.64.*) ;; *) echo "client-$n VIP abnormal: $out"; return 1;; esac
    eval "VIP_C$n=\$vip"

    log "bootstrap client-$n: invite → ingest → vip=$vip"
    local invite_b64
    invite_b64="$(esrv flock-server --config /etc/flock/server.toml invite --ttl-secs 86400)" || return 1
    printf '%s' "$invite_b64" | ec sh -c 'cat > /var/lib/flock/invite.b64' || return 1
    ec flock-client --config "$CFG_1" invite /var/lib/flock/invite.b64 || return 1
    printf '%s' "$vip" | ec sh -c 'cat > /var/lib/flock/vip' || return 1

    log "bootstrap client-$n: login (set password + login verification + hostname registered)"
    printf '%s\n' "$pass" | ec flock-client --config "$CFG_1" login 2>&1 | tee /tmp/m7_login_$n.log | sed 's/^/    /'
    grep -q '^login ok:' /tmp/m7_login_$n.log || { echo "client-$n login failed (see above)"; return 1; }

    log "bootstrap client-$n: ready + restart (service daemon takes over)"
    ec sh -c 'touch /var/lib/flock/ready' || return 1
    compose restart "client-$n" >/dev/null 2>&1 || return 1

    local t=$((SECONDS + 90))
    until ec sh -c 'ip link show tun0' >/dev/null 2>&1; do
        if [ $SECONDS -ge $t ]; then
            echo "client-$n tun0 not created within 90s"; compose logs --tail 30 "client-$n"; return 1
        fi
        sleep 2
    done
    local ok=""
    t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        if ec ping -c 1 -W 2 "$SERVER_VIP" >/dev/null 2>&1; then ok=1; break; fi
        sleep 2
    done
    [ -n "$ok" ] || { echo "client-$n ping to $SERVER_VIP not working within 90s"; compose logs --tail 30 "client-$n"; return 1; }
    return 0
}

bootstrap() {
    log "bootstrap: waiting for the server to be ready (admin endpoint)"
    local deadline=$((SECONDS + 120))
    until esrv bash -c 'exec 3<>/dev/tcp/127.0.0.1/9444 && echo ok' 2>/dev/null | grep -q ok; do
        if [ $SECONDS -ge $deadline ]; then
            echo "server admin endpoint not ready within 120s"; return 1
        fi
        sleep 2
    done
    esrv sh -c 'ip link show tun0' >/dev/null 2>&1 \
        || { echo "server tun0 not created (dataplane down)"; compose logs --tail 40 server; return 1; }

    bootstrap_client 1 "$CLIENT_USER_1" "$PASS_1" || return 1
    bootstrap_client 2 "$CLIENT_USER_2" "$PASS_2" || return 1

    # Wait for both daemons' login keepalive to be ready (login ok logs).
    local t=$((SECONDS + 60)) ok1=0 ok2=0
    while [ $SECONDS -lt $t ]; do
        [ "$ok1" -eq 0 ] && [ "$(compose logs client-1 2>/dev/null | grep -c 'login ok' || true)" -gt 0 ] && ok1=1
        [ "$ok2" -eq 0 ] && [ "$(compose logs client-2 2>/dev/null | grep -c 'login ok' || true)" -gt 0 ] && ok2=1
        [ "$ok1" -eq 1 ] && [ "$ok2" -eq 1 ] && break
        sleep 2
    done
    [ "$ok1" -eq 1 ] && [ "$ok2" -eq 1 ] || { echo "daemon login not ready (c1=$ok1 c2=$ok2)"; compose logs --tail 20 client-1 client-2; return 1; }
    echo "VIP: client-1=${VIP_C1:-?} client-2=${VIP_C2:-?}"
    return 0
}

# ============================================================================
# peers query retry wrapper (the daemon re-login window transient; semantic
# thresholds not lowered —— see the file header)
# ============================================================================

flock_retry() { # flock_retry <n:1|2> <flock-client subcommand/args...> → stdout (rc from the final attempt)
    local n="$1"; shift
    local out="" rc=1
    for _ in $(seq 1 "$PEERS_RETRIES"); do
        out="$(compose exec -T "client-$n" flock-client --config "$CFG_1" "$@" 2>/dev/null)"; rc=$?
        if [ "$rc" -eq 0 ] && [ -n "$out" ]; then break; fi
        sleep "$PEERS_RETRY_SLEEP"
    done
    printf '%s\n' "$out"
    return "$rc"
}

sh_retry() { # sh_retry <sh -c payload> (inside the client-1 container) → stdout; empty output = re-login window
    # (peers CLI error ⇒ jq gets no input, no value) ⇒ still empty after
    # bounded retries ⇒ non-zero.
    local payload="$1" out=""
    for _ in $(seq 1 "$PEERS_RETRIES"); do
        out="$(compose exec -T client-1 sh -c "$payload" 2>/dev/null | tr -d '\r')"
        if [ -n "$out" ]; then printf '%s' "$out"; return 0; fi
        sleep "$PEERS_RETRY_SLEEP"
    done
    printf '%s' "$out"
    return 1
}

# ============================================================================
# P1: roster assembly (three kinds of entries: server + client-2 + self)
# ============================================================================

peers_table() { # peers_table <n:1|2> → stdout (table; re-login window retries via flock_retry)
    flock_retry "$1" peers
}

p1() {
    log "P1 roster: client-1 peers (server + client-2 + self entries)"
    local out
    out="$(peers_table 1)"; local rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL P1 "peers command failed (rc=$rc)"
        return
    fi
    local ok=1 why=""
    # Server entry: VIP .1 + online + a number in the latency column (online ⇒
    # a probe value must exist).
    printf '%s\n' "$out" | grep -E "^100\.64\.0\.1\b" | grep -q 'online' || { ok=0; why="$why server row not online;"; }
    local srv_row
    srv_row="$(printf '%s\n' "$out" | grep -E '^100\.64\.0\.1\b')"
    if printf '%s' "$srv_row" | awk -F'|' '{gsub(/ /,"",$6); exit ($6=="—" || $6=="") ? 1 : 0}'; then :; else ok=0; why="$why server latency column is —;"; fi
    # client-2 entry: hostname client-2 + account m7c2 + online + latency not —.
    printf '%s\n' "$out" | grep -q 'client-2' || { ok=0; why="$why no client-2 row;"; }
    printf '%s\n' "$out" | grep 'client-2' | grep -q "$CLIENT_USER_2" || { ok=0; why="$why client-2 account column abnormal;"; }
    printf '%s\n' "$out" | grep 'client-2' | grep -q 'online' || { ok=0; why="$why client-2 not online;"; }
    if printf '%s\n' "$out" | grep 'client-2' | awk -F'|' '{gsub(/ /,"",$6); exit ($6=="—" || $6=="") ? 1 : 0}'; then :; else ok=0; why="$why client-2 latency column is —;"; fi
    # Own row: marked (self).
    printf '%s\n' "$out" | grep -q '(self)' || { ok=0; why="$why no (self) row;"; }

    if [ "$ok" -eq 1 ]; then
        record PASS P1 "server/client-2/self entries complete (online + numeric latency + correct account/hostname)"
    else
        record FAIL P1 "missing items: $why"
    fi
}

# ============================================================================
# P2: iperf3 flow → EWMA convergence → tx/rx non-zero
# ============================================================================

p2() {
    log "P2 traffic observability: iperf3 client-1→client-2 (VIP ${VIP_C2:-?}) → ${EWMA_SETTLE}s convergence → peers assertion"
    if [ -z "${VIP_C2:-}" ]; then
        record FAIL P2 "client-2 VIP unknown (bootstrap not run)"
        return
    fi
    # iperf3 server bound to client-2's VIP (-B ⇒ reachable only via the
    # tunnel; pgrep -x prevents duplicate launches).
    ec2 sh -c "pgrep -x iperf3 >/dev/null 2>&1 || iperf3 -s -D -B ${VIP_C2}" || true
    sleep 1
    local out
    out="$(ec1 iperf3 -c "$VIP_C2" -t 5 --format m 2>&1)"; local rc=$?
    printf '%s\n' "$out" | grep -E 'sender|receiver' | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL P2 "iperf3 failed (rc=$rc)"
        return
    fi
    echo "    waiting ${EWMA_SETTLE}s (EWMA convergence window)..."
    sleep "$EWMA_SETTLE"
    local tbl
    tbl="$(peers_table 1)"
    printf '%s\n' "$tbl" | sed 's/^/    /'
    local ok=1 why=""
    # client-1 row: device-view tx (iperf sender side) non-zero (↑ traffic column).
    local c1_row c2_row
    c1_row="$(printf '%s\n' "$tbl" | grep '(self)')"
    c2_row="$(printf '%s\n' "$tbl" | grep 'client-2')"
    [ -n "$c1_row" ] || { ok=0; why="$why no self row;"; }
    [ -n "$c2_row" ] || { ok=0; why="$why no client-2 row;"; }
    if [ -n "$c1_row" ]; then
        printf '%s' "$c1_row" | awk -F'|' '{gsub(/ /,"",$8); exit ($8+0<=0) ? 1 : 0}' || { ok=0; why="$why client-1 tx=0;"; }
    fi
    if [ -n "$c2_row" ]; then
        printf '%s' "$c2_row" | awk -F'|' '{gsub(/ /,"",$7); exit ($7+0<=0) ? 1 : 0}' || { ok=0; why="$why client-2 rx=0;"; }
    fi
    if [ "$ok" -eq 1 ]; then
        record PASS P2 "after the flow, client-1 tx non-zero and client-2 rx non-zero (device-view counters)"
    else
        record FAIL P2 "traffic assertion failed: $why"
    fi
}

# ============================================================================
# P3: --json machine-readable form (jq parsing + field semantics)
# ============================================================================

p3() {
    log "P3 machine-readable: peers --json | jq (inside the container)"
    local js
    js="$(flock_retry 1 peers --json)"; local rc=$?
    printf '%s\n' "$js" | head -12 | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL P3 "peers --json failed (rc=$rc; includes failure after re-login-window retries)"
        return
    fi
    # jq runs inside the container (no jq dependency on the host —— the image
    # has it installed); filter values are passed via --arg (zero double quotes
    # inside, avoiding quote-eating when docker exec crosses the Windows
    # argument boundary). Queries go through sh_retry: bounded retries for the
    # re-login window transient (see the file header), field assertions not
    # lowered.
    local ty n srv_online c2_lat
    ty="$(sh_retry "flock-client --config $CFG_1 peers --json | jq -r 'type'")" \
        || { record FAIL P3 "jq parsing failed (still empty after re-login-window retries)"; return; }
    [ "$ty" = "array" ] || { record FAIL P3 "top level not an array ($ty)"; return; }
    n="$(sh_retry "flock-client --config $CFG_1 peers --json | jq 'length'")" \
        || { record FAIL P3 "entry count query empty (including retries)"; return; }
    [ "${n:-0}" -ge 3 ] || { record FAIL P3 "entry count ${n:-?} < 3"; return; }
    srv_online="$(sh_retry "flock-client --config $CFG_1 peers --json | jq -r --arg v 100.64.0.1 '.[] | select(.vip==\$v) | .online'")"
    [ "$srv_online" = "true" ] || { record FAIL P3 "server entry online != true ($srv_online)"; return; }
    c2_lat="$(sh_retry "flock-client --config $CFG_1 peers --json | jq -r --arg h client-2 '.[] | select(.hostname==\$h) | .latency_ms'")"
    case "$c2_lat" in
        ''|null) record FAIL P3 "client-2 latency_ms empty/null ($c2_lat)" ;;
        *) record PASS P3 "json array ($n entries) + server online + client-2 latency=${c2_lat}ms" ;;
    esac
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
    if [ -n "$(compose ps -q server)" ] && [ -n "$(compose ps -q client-1)" ] && [ -n "$(compose ps -q client-2)" ]; then
        topology_up=1
        break
    fi
    sleep 2
done
if [ -z "$topology_up" ]; then
    echo "m7 topology not running: first docker compose -f $COMPOSE_FILE up -d --build" >&2
    exit 2
fi

if ! bootstrap; then
    echo "bootstrap failed" >&2
    exit 2
fi

p1
p2
p3

log "Summary"
printf '%s\n' "${SUMMARY[@]}"
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
