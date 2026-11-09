#!/usr/bin/env bash
# m3_assert.sh —— M3 assertions (docs/design.md §7-M3 completion criteria: the
# single-server versions of A2/A3/A4/A9).
#
# Prerequisites:
#   docker compose -f deploy/m3.yml up -d --build
#   bash deploy/m3_assert.sh
#
# Assertion set (single-server versions —— the cross-server face belongs to M5 §6.3):
#   A2 tunnel connectivity  client ping -c 3 100.64.0.1 (the server tun VIP) with
#                          0 loss
#   A3 MTU                 client `ip link show tun0` contains mtu 1280;
#                          `ping -s 1252 -M do` passes (1252+28=1280, §2.1)
#   A4 throughput baseline iperf3 over the tunnel ≥ 100 Mbps (value recorded for
#                          regression comparison, R7)
#   A9 silent dead link    `docker network disconnect` simulates a network cut ⇒
#                          both sides detect within ≤30s and enter reconnect
#                          (session layer 3×keepalive=30s, §1.3.3c); restoring the
#                          network ⇒ reconnect + ping recovery
#
# Summary: per-item PASS/FAIL at the end; any FAIL ⇒ non-zero exit code.
#
# Git Bash (MSYS) path-rewriting pitfall: arguments starting with / such as
# /dev/net/tun and /etc/flock/... get rewritten into Windows paths (design
# appendix B-2, first encounter) —— this script exports MSYS_NO_PATHCONV=1
# internally; callers need no prior setup.
#
# WSL bash fallback (when `bash` on Windows resolves to the WSL shim at
# C:\Windows\System32\bash.exe): the shim starts /bin/bash via the default
# distro —— if the default distro is docker-desktop (no /bin/bash) this script
# never starts (execvpe(/bin/bash) failed); if it is a full distro (e.g.
# Ubuntu) it starts but lacks MSYS semantics (no pwd -W; docker.exe does not
# recognize /mnt/... paths). Both shapes are re-execed via Windows-side Git
# Bash —— the script body (MSYS_NO_PATHCONV + the pwd -W dual path forms) is
# validated in exactly that shape.
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
# Git Bash (MSYS): MSYS_NO_PATHCONV=1 disabled argument path rewriting ⇒ docker
# (a Windows executable) does not recognize the /e/... form —— switch to the
# Windows form (E:/..., forward slashes; if native Linux's pwd -W does not
# exist fall back to the POSIX path, which docker on Linux accepts anyway).
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"
COMPOSE_FILE="$HERE/m3.yml"
NETWORK="flock-m3net"
SERVER_VIP="100.64.0.1"
MTU_EXPECT=1280
A4_MIN_MBPS=100
A9_DEADLINE=30   # seconds; session layer 3×keepalive(10s) of silence ⇒ DeadLink (A9 semantics)

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
# Orchestration (idempotent: state volumes persist across runs ⇒ the ready
# marker means skip)
# ============================================================================

bootstrap() {
    log "bootstrap: waiting for the server to be ready (admin endpoint)"
    local deadline=$((SECONDS + 120))
    until exec_server bash -c 'exec 3<>/dev/tcp/127.0.0.1/9444 && echo ok' 2>/dev/null | grep -q ok; do
        if [ $SECONDS -ge $deadline ]; then
            echo "server admin endpoint not ready within 120s"; return 1
        fi
        sleep 2
    done
    # Data-plane assembly confirmation (server tun + routes).
    exec_server sh -c 'ip link show tun0' >/dev/null 2>&1 \
        || { echo "server tun0 not created (dataplane down)"; compose logs --tail 40 server; return 1; }

    if exec_client sh -c 'test -f /var/lib/flock/ready' 2>/dev/null; then
        log "bootstrap: already ready (idempotent skip)"
        return 0
    fi

    log "bootstrap: gen-keys (client)"
    local keys
    keys="$(exec_client flock-client --config /etc/flock/client.toml gen-keys)" || return 1
    local dev_x dev_ed
    dev_x="$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')"
    dev_ed="$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')"
    [ -n "$dev_x" ] && [ -n "$dev_ed" ] || { echo "gen-keys output abnormal: $keys"; return 1; }

    log "bootstrap: server-side device-add (pre-register the device + assign a VIP)"
    local out
    out="$(exec_server flock-server --config /etc/flock/server.toml \
        device-add --user m3client --device-x "$dev_x" --device-ed "$dev_ed" 2>&1)" \
        || { echo "device-add failed: $out"; return 1; }
    local vip
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    case "$vip" in
        100.64.*) ;;
        *) echo "device-add returned no VIP inside the 100.64/10 pool: $out"; return 1 ;;
    esac

    log "bootstrap: server-side invite (v3 invite)"
    local invite_b64
    invite_b64="$(exec_server flock-server --config /etc/flock/server.toml \
        invite --ttl-secs 86400)" || return 1
    printf '%s' "$invite_b64" | exec_client sh -c 'cat > /var/lib/flock/invite.b64' || return 1

    log "bootstrap: client ingests the invite (pins the cluster root key + stores the directory)"
    exec_client flock-client --config /etc/flock/client.toml \
        invite /var/lib/flock/invite.b64 || return 1

    log "bootstrap: writing vip=$vip"
    printf '%s' "$vip" | exec_client sh -c 'cat > /var/lib/flock/vip' || return 1

    log "bootstrap: ready + restart client (main process takes over)"
    exec_client sh -c 'touch /var/lib/flock/ready' || return 1
    compose restart client >/dev/null 2>&1 || return 1

    # Wait for the client handshake to succeed (tun0 appearing = the client's
    # main process has reached data-plane assembly).
    local t=$((SECONDS + 60))
    until exec_client sh -c 'ip link show tun0' >/dev/null 2>&1; do
        if [ $SECONDS -ge $t ]; then
            echo "client tun0 not created within 60s"; compose logs --tail 40 client; return 1
        fi
        sleep 2
    done
    # Wait for the ping face to be usable (handshake + routing done; 60s cap).
    local ok=""
    t=$((SECONDS + 60))
    while [ $SECONDS -lt $t ]; do
        if exec_client ping -c 1 -W 2 "$SERVER_VIP" >/dev/null 2>&1; then ok=1; break; fi
        sleep 2
    done
    [ -n "$ok" ] || { echo "client ping to $SERVER_VIP not working within 60s"; compose logs --tail 40 client; return 1; }
    return 0
}

# ============================================================================
# A2: tunnel connectivity (client ↔ server peer, 0 loss)
# ============================================================================

a2() {
    log "A2 tunnel connectivity: ping -c 3 $SERVER_VIP (0 loss)"
    local out
    out="$(exec_client ping -c 3 -W 3 "$SERVER_VIP" 2>&1)"; local rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'
    if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q '0% packet loss'; then
        record PASS A2 "ping $SERVER_VIP 3/3, 0% packet loss"
    else
        record FAIL A2 "ping failed (rc=$rc)"
    fi
}

# ============================================================================
# A3: MTU 1280 + DF large packets
# ============================================================================

a3() {
    log "A3 MTU: tun0 mtu $MTU_EXPECT + ping -s 1252 -M do"
    local link
    link="$(exec_client ip link show tun0 2>&1)"
    printf '%s\n' "$link" | sed 's/^/    /'
    local mtu_ok=no
    printf '%s\n' "$link" | grep -q "mtu $MTU_EXPECT" && mtu_ok=yes

    local out
    out="$(exec_client ping -c 2 -W 3 -s 1252 -M do "$SERVER_VIP" 2>&1)"; local rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'

    if [ "$mtu_ok" = yes ] && [ $rc -eq 0 ]; then
        record PASS A3 "tun0 mtu=$MTU_EXPECT; -s 1252 -M do passes (1252+28=1280)"
    else
        record FAIL A3 "mtu_ok=$mtu_ok df_ping_rc=$rc"
    fi
}

# ============================================================================
# A4: throughput baseline (iperf3 over the tunnel, value recorded)
# ============================================================================

a4() {
    log "A4 throughput: iperf3 over the tunnel (threshold ${A4_MIN_MBPS} Mbps, value recorded)"
    # iperf3 server (-D daemonizes itself; bound to the server tun VIP ——
    # reachable only via the tunnel).
    # pgrep -x: exact process-name match (-f would hit this very sh -c wrapper
    # itself ⇒ a permanent false-positive skip of the launch).
    exec_server sh -c "pgrep -x iperf3 >/dev/null 2>&1 || iperf3 -s -D -B $SERVER_VIP" || true
    sleep 1
    local out
    out="$(exec_client iperf3 -c "$SERVER_VIP" -t 5 --format m 2>&1)"; local rc=$?
    printf '%s\n' "$out" | grep -E 'sender|receiver' | sed 's/^/    /'
    if [ $rc -ne 0 ]; then
        record FAIL A4 "iperf3 client failed (rc=$rc)"
        return
    fi
    # The sender summary line's rate column = the column before the
    # "Mbits/sec" field (--format m fixes the Mbits unit).
    local mbps
    mbps="$(printf '%s\n' "$out" | awk '/sender/ {for (i = 1; i <= NF; i++) if ($(i+1) == "Mbits/sec") {print $i; exit}}')"
    case "$mbps" in
        ''|*[!0-9.]*)
            record FAIL A4 "could not parse the sender rate: $out"
            ;;
        *)
            if awk -v m="$mbps" -v t="$A4_MIN_MBPS" 'BEGIN{exit !(m>=t)}'; then
                record PASS A4 "iperf3 sender = ${mbps} Mbits/sec (≥ ${A4_MIN_MBPS})"
            else
                record FAIL A4 "iperf3 sender = ${mbps} Mbits/sec (< ${A4_MIN_MBPS})"
            fi
            ;;
    esac
}

# ============================================================================
# A9: silent dead link detected on both sides ≤30s, entering reconnect +
#     reconnect succeeds after network recovery
# ============================================================================

a9() {
    log "A9 silent dead link: network disconnect ⇒ both sides detect within ≤${A9_DEADLINE}s (dead-link) and reconnect"
    local cid
    cid="$(compose ps -q client)"
    [ -n "$cid" ] || { record FAIL A9 "client container id empty"; return; }

    local base_c base_s
    base_c="$(compose logs client 2>/dev/null | grep -c 'reason=dead-link' || true)"
    base_s="$(compose logs server 2>/dev/null | grep -c 'reason=dead-link' || true)"

    docker network disconnect "$NETWORK" "$cid" || { record FAIL A9 "network disconnect failed"; return; }
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
        record FAIL A9 "both sides did not detect within ${A9_DEADLINE}s (client=$saw_c server=$saw_s, elapsed=${elapsed}s)"
        return
    fi

    # Network restored ⇒ the client reconnects after backoff (attempt interval
    # from 5s + jitter; 90s budget).
    docker network connect "$NETWORK" "$cid" || { record FAIL A9 "network connect failed"; return; }
    local reconnected=""
    local t=$((SECONDS + 90))
    while [ $SECONDS -lt $t ]; do
        if exec_client ping -c 1 -W 2 "$SERVER_VIP" >/dev/null 2>&1; then reconnected=1; break; fi
        sleep 2
    done
    if [ -n "$reconnected" ]; then
        record PASS A9 "both sides detected dead-link in ${elapsed}s and entered reconnect; after network recovery ping recovered (≤${A9_DEADLINE}s budget)"
    else
        record FAIL A9 "detection ${elapsed}s met the bar, but reconnect not completed within 90s (ping not recovered)"
    fi
}

# ============================================================================
# Entry point
# ============================================================================

if ! docker info >/dev/null 2>&1; then
    echo "docker unavailable (is Docker Desktop running?)" >&2
    exit 2
fi
# Topology in place (containers may still be starting —— retry 60s).
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
    echo "m3 topology not running: first docker compose -f $COMPOSE_FILE up -d --build" >&2
    exit 2
fi

if ! bootstrap; then
    echo "bootstrap failed" >&2
    exit 2
fi

a2
a3
a4
a9

log "Summary"
printf '%s\n' "${SUMMARY[@]}"
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
