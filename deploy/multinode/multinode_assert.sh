#!/usr/bin/env bash
# multinode_assert.sh —— real multi-machine networking test assertions (result
# matrix written to docs/manual/multinode-test.md).
#
#   bash deploy/multinode/multinode_assert.sh 1   # Scenario 1: single server · Direct full mesh
#   bash deploy/multinode/multinode_assert.sh 2   # Scenario 2: two servers · cross-machine Raft + dual transport
#
# Prerequisites (README "replication steps"):
#   1) deploy/multinode/out/ built (Dockerfile.buildbin) and streamed to jowency ~/flock-mn/bin/
#   2) bash deploy/multinode/lxd-setup.sh <1|2> (on jowency, via ssh)
#   3) bash deploy/multinode/win-docker-setup.sh <1|2> (Windows side)
#   Scenario 2 additionally needs the LXD→Windows temporary firewall allowances
#   from the README "firewall prerequisites" + the Windows inbound probe passing.
#
# Assertions: Scenario 1 S1–S3 / Scenario 2 R1–R5.
# Exit code: 0 = all PASS; 1 = ≥1 FAIL; 2 = bootstrap failure; 64 = usage error.
#
# Git Bash (MSYS) path-rewriting pitfall (design appendix B-2): the script
# exports MSYS_NO_PATHCONV=1 internally.
# WSL bash shim fallback (same as m3_assert.sh): re-exec via Windows-side Git
# Bash.
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

SCENARIO="${1:-}"
[ "$SCENARIO" = 1 ] || [ "$SCENARIO" = 2 ] || { echo "usage: multinode_assert.sh <1|2>" >&2; exit 64; }

_src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"
REPO="$(cd "$HERE/../.." && pwd)"
STATE_DIR="$REPO/.tmp/flock-mn"
mkdir -p "$STATE_DIR"
STATE="$STATE_DIR/state-$SCENARIO.env"

JOW="${JOW_SSH:-jowency@192.168.31.221}"
JOW_LAN_IP="${JOW_LAN_IP:-192.168.31.221}"
WIN_LAN_IP="$(ipconfig | awk '/IPv4/{print $NF}' | grep '^192\.168\.' | head -1)"
PASSWD_PREFIX="flock-mn"
PING_PKTS=3

# Local JSON parsing (jq absent): python3 first, python fallback; both missing
# ⇒ JSON-dependent assertions honestly FAIL.
PY_BIN=""
for _py in python3 python; do
    if command -v "$_py" >/dev/null 2>&1 && "$_py" -c 'import json' >/dev/null 2>&1; then
        PY_BIN="$_py"; break
    fi
done
pj() { # pj <json-text> <py-expr over arr>
    [ -n "$PY_BIN" ] || { echo ERR; return; }
    printf '%s' "$1" | "$PY_BIN" -c "import json,sys; arr=json.load(sys.stdin); print($2)" 2>/dev/null || echo ERR
}
now_ms() { date +%s%3N; }

PASS=0; FAIL=0
declare -a SUMMARY
record() { # record PASS|FAIL <id> <detail>
    if [ "$1" = PASS ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
    SUMMARY+=("$1|$2|$3")
    printf '[%s] %-4s | %s\n' "$1" "$2" "$3"
}
log() { printf '\n== %s ==\n' "$*"; }
die_boot() { echo "bootstrap failed: $*" >&2; exit 2; }

# —— node execution faces: docker nodes (docker exec) / lxd nodes (ssh → lxc exec) ——
declare -A NODE_KIND NODE_CT NODE_USER NODE_CFG
on() { # on <node> <cmdstring> [stdin: 0|1]
    local n="$1" cmd="$2" use_stdin="${3:-0}" q
    q="$(printf '%q' "$cmd")"
    if [ "${NODE_KIND[$n]:-}" = docker ]; then
        if [ "$use_stdin" = 1 ]; then docker exec -i "${NODE_CT[$n]}" sh -c "$cmd"; else docker exec "${NODE_CT[$n]}" sh -c "$cmd"; fi
    else
        ssh -o BatchMode=yes "$JOW" "lxc exec ${NODE_CT[$n]} -- sh -c $q"
    fi
}
cfg_of() { printf '%s' "${NODE_CFG[$1]}"; }

# Server admin CLI (inside the server's own netns at 127.0.0.1:9444)
s1_admin() { ssh -o BatchMode=yes "$JOW" "lxc exec flock-s1 -- flock-server --config /etc/flock/server.toml $*"; }
s2_admin() { ssh -o BatchMode=yes "$JOW" "lxc exec flock-s2 -- flock-server --config /etc/flock/server.toml $*"; }
w2_admin() { docker exec flock-srv1 flock-server --config /etc/flock/server.toml "$@"; }
stats_w2() { w2_admin stats 2>/dev/null; }
stats_s2() { s2_admin stats 2>/dev/null; }

wait_tun() { # wait_tun <node> [timeout]
    local n="$1" t=$((SECONDS + ${2:-90}))
    until on "$n" 'ip link show tun0' >/dev/null 2>&1; do
        [ $SECONDS -ge $t ] && return 1; sleep 2
    done
}
wait_ping() { # wait_ping <node> <vip> [timeout]
    local n="$1" v="$2" t=$((SECONDS + ${3:-90}))
    until on "$n" "ping -c1 -W2 $v" >/dev/null 2>&1; do
        [ $SECONDS -ge $t ] && return 1; sleep 2
    done
}
PING_AWK='/packets transmitted/{for(i=1;i<NF;i++) if($i ~ /%$/){gsub(/[(%]/,"",$(i-1)); loss=$(i-1)}} /rtt min/{split($4,a,"/"); avg=a[2]} END{printf "%s %s", loss+0, avg+0}'
ping3() { # ping3 <node> <vip> → "loss% avg_ms"
    on "$1" "ping -c $PING_PKTS -W 2 $2" 2>/dev/null | awk "$PING_AWK"
}
ping3_s1() { # Scenario-1 server (flock-s1) → clients
    ssh -o BatchMode=yes "$JOW" "lxc exec flock-s1 -- ping -c $PING_PKTS -W 2 $1" 2>/dev/null | awk "$PING_AWK"
}

# Client bootstrap (the cross-machine version of the m3/m7 admin onboarding
# path; idempotent: ready marker)
boot_client() { # boot_client <node> <adminfn> <invite-subcmd...>
    local n="$1" adminfn="$2"; shift 2
    local user="${NODE_USER[$n]}" cfg; cfg="$(cfg_of "$n")"
    if on "$n" 'test -f /var/lib/flock/ready' 2>/dev/null; then
        local v; v="$(on "$n" 'cat /var/lib/flock/vip' | tr -d '\r\n')"
        case "$v" in 100.64.*) eval "VIP_$n=\$v"; echo "  $n already ready (idempotent skip, vip=$v)"; return 0;; esac
    fi
    local keys dx de out vip devid inv
    keys="$(on "$n" "flock-client --config $cfg gen-keys")" || die_boot "$n gen-keys"
    dx="$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')"
    de="$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')"
    [ -n "$dx" ] && [ -n "$de" ] || die_boot "$n gen-keys output abnormal"
    out="$("$adminfn" device-add --user "$user" --device-x "$dx" --device-ed "$de" 2>&1)" || true
    if ! printf '%s\n' "$out" | grep -q '^vip='; then
        # Idempotent retry: the device is already registered (register_device
        # is not idempotent —— a previous run broke at the login/service-start
        # stage) ⇒ continue with the vip file already on the client
        # (invite/login are idempotent).
        printf '%s\n' "$out" | grep -qiE 'exist|already' || die_boot "$n device-add: $out"
        v_old="$(on "$n" 'cat /var/lib/flock/vip 2>/dev/null' | tr -d '\r\n')"
        case "$v_old" in 100.64.*) out="vip=$v_old";; *) die_boot "$n device-add duplicate with no vip on file: $out";; esac
    fi
    vip="$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')"
    devid="$(printf '%s\n' "$out" | sed -n 's/^device_id=//p' | tr -d '\r')"
    case "$vip" in 100.64.*) ;; *) die_boot "$n VIP abnormal: $out";; esac
    inv="$("$adminfn" "$@" 2>&1)" || die_boot "$n invite issuance: $inv"
    inv="$(printf '%s\n' "$inv" | tail -1)"
    on "$n" "printf '%s' '$inv' > /var/lib/flock/invite.b64"
    on "$n" "flock-client --config $cfg invite /var/lib/flock/invite.b64" >/dev/null || die_boot "$n invite ingest"
    on "$n" "printf '%s\n' '$vip' > /var/lib/flock/vip"
    printf '%s\n' "${PASSWD_PREFIX}-$n" | on "$n" "flock-client --config $cfg login" 1 2>&1 | grep -q '^login ok:' || die_boot "$n login"
    on "$n" 'touch /var/lib/flock/ready'
    eval "VIP_$n=\$vip"; eval "DEV_$n=\$devid"
    echo "  $n bootstrap complete vip=$vip device=${devid:0:16}…"
    if [ "${NODE_KIND[$n]}" = docker ]; then
        docker restart "${NODE_CT[$n]}" >/dev/null || die_boot "$n restart"
    else
        on "$n" 'pkill -x flock-client 2>/dev/null; sleep 0.3; setsid nohup flock-client --config '"$cfg"' service </dev/null >>/var/log/flock-client.log 2>&1 &' || true
    fi
}
save_state() { # VIP_*/DEV_* are shell variables (not exported) — invisible to env, extract via set
    { set | grep -E '^(VIP|DEV)_[A-Za-z0-9]+=' | sort; } > "$STATE"
}
vips_line() { # vips_line <names...> → "VIP_x=v …"
    local n out=""
    for n in "$@"; do eval "out=\"\$out VIP_\$n=\${VIP_$n}\""; done
    printf '%s' "$out"
}
load_state() { [ -f "$STATE" ] && . "$STATE"; }

peers_of() { on "$1" "flock-client --config $(cfg_of "$1") peers" 2>&1; }
peers_json() { on "$1" "flock-client --config $(cfg_of "$1") peers --json" 2>/dev/null; }
# Roster semantics (peers.rs): VIP/hostname/account/type/online/latency;
# offline rows show — in the latency column (not probed).
check_peers() { # check_peers <node> <tag> <expected-rows> [expected-offline]
    local n="$1" tag="$2" want_rows="${3:-5}" want_off="${4:-0}" j rows off nolat has_srv ok=1
    j="$(peers_json "$n")"
    rows="$(pj "$j" 'len(arr)')"
    off="$(pj "$j" 'len([r for r in arr if not r["online"]])')"
    nolat="$(pj "$j" 'len([r for r in arr if not r["is_self"] and r["latency_ms"] is None])')"
    has_srv="$(pj "$j" 'len([r for r in arr if r["kind"] in ("Server","server")])')"
    [ "$rows" = "$want_rows" ] || ok=0
    [ "$off" = "$want_off" ] || ok=0
    [ "$nolat" = 0 ] || ok=0
    [ "$has_srv" -ge 1 ] 2>/dev/null || ok=0
    if [ "$ok" = 1 ]; then
        record PASS "$tag" "$n roster has $rows rows (incl. a server row); offline $off (expected $want_off); all non-self latencies non-empty"
    else
        record FAIL "$tag" "$n roster abnormal: rows=$rows(expected $want_rows) offline=$off(expected $want_off) no-latency=$nolat server-rows=$has_srv"
    fi
}

# ============================================================================
if [ "$SCENARIO" = 1 ]; then
# ============================================================================
NODE_KIND[wc1]=docker; NODE_CT[wc1]=flock-wc1; NODE_USER[wc1]=mncw1; NODE_CFG[wc1]=/etc/flock/client.toml
NODE_KIND[wc2]=docker; NODE_CT[wc2]=flock-wc2; NODE_USER[wc2]=mncw2; NODE_CFG[wc2]=/etc/flock/client.toml
NODE_KIND[c3]=lxd;     NODE_CT[c3]=flock-c3;   NODE_USER[c3]=mnc3;  NODE_CFG[c3]=/var/lib/flock/client.toml
NODE_KIND[c4]=lxd;     NODE_CT[c4]=flock-c4;   NODE_USER[c4]=mnc4;  NODE_CFG[c4]=/var/lib/flock/client.toml
VIP_S1="100.64.0.1"

load_state
log "Scenario 1 bootstrap (single server · Direct: LXD flock-s1 + Win-Docker wc1/wc2 + LXD c3/c4)"
for n in wc1 wc2; do
    on "$n" "printf '%s\n' 'state_dir = \"/var/lib/flock\"' '' 'tun_name = \"tun0\"' 'mtu = 1280' '' 'endpoints = [\"$JOW_LAN_IP:9443\"]' '' '[auth]' 'username = \"${NODE_USER[$n]}\"' > /etc/flock/client.toml"
    boot_client "$n" s1_admin invite --ttl-secs 86400
done
for n in c3 c4; do
    boot_client "$n" s1_admin invite --ttl-secs 86400
done
for n in wc1 wc2 c3 c4; do
    wait_tun "$n" || die_boot "$n tun0 not created"
    wait_ping "$n" "$VIP_S1" || die_boot "$n ping to server not working"
done
save_state
log "bootstrap complete: $(vips_line wc1 wc2 c3 c4)"

# —— S1: full-mesh ping matrix ——
log "S1 full-mesh ping matrix ($PING_PKTS packets per cell)"
printf '| src | dst | VIP | loss | avg rtt(ms) | path | result |\n|---|---|---|---|---|---|---|\n'
s1_fail=0
path_of() {
    case "$1 $2" in
      "wc1 wc2"|"wc2 wc1"|"c3 c4"|"c4 c3") echo "same host";;
      *) if [ "${NODE_KIND[$1]}" = docker ]; then echo "cross-machine Win-Docker→LXD"; else echo "cross-machine LXD→Win-Docker"; fi;;
    esac
}
for src in wc1 wc2 c3 c4; do
    for dst in wc1 wc2 c3 c4 server; do
        [ "$src" = "$dst" ] && continue
        local_vip="$VIP_S1"; [ "$dst" != server ] && eval "local_vip=\$VIP_$dst"
        [ -n "$local_vip" ] || { printf '| %s | %s | ? | - | - | - | FAIL(no-vip) |\n' "$src" "$dst"; s1_fail=1; continue; }
        read -r loss avg <<< "$(ping3 "$src" "$local_vip")"
        ok=PASS; [ "$loss" = 0 ] || { ok=FAIL; s1_fail=1; }
        printf '| %s | %s | %s | %s%% | %s | %s | %s |\n' "$src" "$dst" "$local_vip" "$loss" "$avg" "$(path_of "$src" "$dst")" "$ok"
    done
done
for dst in wc1 wc2 c3 c4; do
    eval "local_vip=\$VIP_$dst"
    read -r loss avg <<< "$(ping3_s1 "$local_vip")"
    ok=PASS; [ "$loss" = 0 ] || { ok=FAIL; s1_fail=1; }
    printf '| server(s1) | %s | %s | %s%% | %s | LXD local | %s |\n' "$dst" "$local_vip" "$loss" "$avg" "$ok"
done
[ "$s1_fail" = 0 ] && record PASS S1 "full mesh: 4 clients × (server + 3 peers) + server→4 clients, all 0 loss" \
                 || record FAIL S1 "matrix has loss/failure cells (see table above)"

# —— S2: peers roster ——
log "S2 peers roster (wc1 view + c3 view, 5 nodes expected: hostname/account/online/latency not —)"
echo "--- wc1: flock-client peers ---"; peers_of wc1 | sed 's/^/    /'
echo "--- c3: flock-client peers ---"; peers_of c3 | sed 's/^/    /'
check_peers wc1 S2-w 5 0
check_peers c3  S2-l 5 0

# —— S3: VIP assignment table ——
log "S3 VIP assignment table"
for n in S1 wc1 wc2 c3 c4; do eval "printf '    VIP_%s=%s\n' $n \"\${VIP_$n}\""; done
uniq_vips="$(for n in wc1 wc2 c3 c4; do eval "printf '%s\n' \"\${VIP_$n}\""; done | sort -u | wc -l | tr -d ' ')"
[ "$uniq_vips" = 4 ] && record PASS S3 "4 client VIPs mutually distinct + server $VIP_S1 (device pool above)" \
                 || record FAIL S3 "VIPs duplicated or missing (unique count=$uniq_vips/4)"

# ============================================================================
else
# ============================================================================
NODE_KIND[2w1]=docker; NODE_CT[2w1]=flock-2w1; NODE_USER[2w1]=mn2w1; NODE_CFG[2w1]=/etc/flock/client.toml
NODE_KIND[2w2]=docker; NODE_CT[2w2]=flock-2w2; NODE_USER[2w2]=mn2w2; NODE_CFG[2w2]=/etc/flock/client.toml
NODE_KIND[c5]=lxd;    NODE_CT[c5]=flock-c5;    NODE_USER[c5]=mn2c5;  NODE_CFG[c5]=/var/lib/flock/client.toml
NODE_KIND[c6]=lxd;    NODE_CT[c6]=flock-c6;    NODE_USER[c6]=mn2c6;  NODE_CFG[c6]=/var/lib/flock/client.toml
VIP_W2SRV="100.64.0.1"; VIP_S2SRV="100.64.0.2"

load_state
log "Scenario 2 bootstrap (cross-machine 2-voter Raft: Win-Docker flock-srv1(Direct 9443/9500) + LXD flock-s2(Frp→frps:24000, Raft 9500))"

# root.seed → flock-s2 (the cluster-invite ops face runs inside the s2 container)
ssh -o BatchMode=yes "$JOW" 'lxc exec flock-s2 -- sh -c "test -f /var/lib/flock/root.seed"' >/dev/null 2>&1 \
    || ssh -o BatchMode=yes "$JOW" 'cat ~/flock-mn/run/mat/root.seed' \
        | ssh -o BatchMode=yes "$JOW" 'lxc exec flock-s2 -- sh -c "cat > /var/lib/flock/root.seed"'

if ! ssh -o BatchMode=yes "$JOW" 'lxc exec flock-s2 -- sh -c "pgrep -x flock-server >/dev/null"' >/dev/null 2>&1; then
    log "flock-s2 enroll + start service"
    ssh -o BatchMode=yes "$JOW" 'lxc exec flock-s2 -- flock-server --config /etc/flock/server.toml enroll --bundle /var/lib/flock/node-1.bundle' | tail -1 || die_boot "s2 enroll"
    ssh -o BatchMode=yes "$JOW" 'lxc exec flock-s2 -- sh -c "setsid nohup flock-server --config /etc/flock/server.toml </dev/null >>/var/log/flock-server.log 2>&1 &"' || true
fi
if ! docker exec flock-srv1 sh -c 'test -f /var/lib/flock/bundle.bin' >/dev/null 2>&1; then
    log "node-0.bundle →srv1 (tar stream) + enroll"
    ssh -o BatchMode=yes "$JOW" 'tar -C ~/flock-mn/run/mat -cf - node-0.bundle root.seed' | docker exec -i flock-srv1 sh -c 'tar -C /var/lib/flock -xf -' || die_boot "bundle stream to srv1"
    docker exec flock-srv1 flock-server --config /etc/flock/server.toml enroll --bundle /var/lib/flock/node-0.bundle | tail -1 || die_boot "srv1 enroll"
    docker restart flock-srv1 >/dev/null || die_boot "srv1 restart"
fi
log "cluster-bootstrap (via srv1 admin; a 2-voter write needs both interconnected, up to 240s)"
t=$((SECONDS+240))
until docker exec flock-srv1 flock-server --config /etc/flock/server.toml cluster-bootstrap --root-seed /var/lib/flock/root.seed 2>&1 | tee "$STATE_DIR/boot2.log" | grep -q 'cluster-bootstrap ok\|idempotent: already bootstrapped'; do
    [ $SECONDS -ge $t ] && { cat "$STATE_DIR/boot2.log"; docker logs --tail 20 flock-srv1; ssh -o BatchMode=yes "$JOW" 'lxc exec flock-s2 -- tail -20 /var/log/flock-server.log' 2>/dev/null; die_boot "cluster-bootstrap timed out"; }
    sleep 5
done
t=$((SECONDS+120)); ok=""
while [ -z "$ok" ]; do
    ok=1
    stats_w2 | grep -q '^epoch=' || ok=""
    stats_s2 | grep -q '^epoch=' || ok=""
    [ -n "$ok" ] && break
    [ $SECONDS -ge $t ] && { stats_w2; stats_s2; die_boot "both endpoints' stats not ready"; }
    sleep 3
done
docker exec flock-srv1 ip link show tun0 >/dev/null 2>&1 || die_boot "srv1 tun0 not created"
ssh -o BatchMode=yes "$JOW" 'lxc exec flock-s2 -- ip link show tun0' >/dev/null 2>&1 || die_boot "s2 tun0 not created"

# Clients (device-add/cluster-invite both via the s2 admin —— proving any node
# serves equivalently)
for n in 2w1 2w2; do
    on "$n" "printf '%s\n' 'state_dir = \"/var/lib/flock\"' '' 'tun_name = \"tun0\"' 'mtu = 1280' '' 'endpoints = [\"$WIN_LAN_IP:9443\", \"$JOW_LAN_IP:24000\"]' '' '[auth]' 'username = \"${NODE_USER[$n]}\"' > /etc/flock/client.toml"
    boot_client "$n" s2_admin cluster-invite --root-seed /var/lib/flock/root.seed --bundle /var/lib/flock/node-1.bundle --ttl-secs 86400
done
for n in c5 c6; do
    boot_client "$n" s2_admin cluster-invite --root-seed /var/lib/flock/root.seed --bundle /var/lib/flock/node-1.bundle --ttl-secs 86400
done
for n in 2w1 2w2 c5 c6; do
    wait_tun "$n" || die_boot "$n tun0 not created"
done
wait_ping 2w1 "$VIP_W2SRV" || die_boot "2w1 ping to server-1 not working"
wait_ping c5 "$VIP_S2SRV" || die_boot "c5 ping to server-2 not working"
save_state
log "bootstrap complete: $(vips_line 2w1 2w2 c5 c6)"

# —— R1: Raft cross-machine consistency ——
log "R1 Raft cross-machine state consistency (both servers' stats)"
echo "--- srv1 (Windows Docker, Direct+Raft) stats ---"; stats_w2 | sed 's/^/    /'
echo "--- s2 (LXD, Frp→frps + Raft) stats ---";        stats_s2 | sed 's/^/    /'
e1="$(stats_w2 | sed -n 's/^epoch=//p')";  e2="$(stats_s2 | sed -n 's/^epoch=//p')"
l1="$(stats_w2 | sed -n 's/^leader=//p')"; l2="$(stats_s2 | sed -n 's/^leader=//p')"
r1=1
[ -n "$e1" ] && [ "$e1" = "$e2" ] || r1=0
{ [ -n "$l1" ] && [ "$l1" = "$l2" ] && [ "$l1" != "(none)" ] && [ "$l1" != "unknown" ]; } || r1=0
[ "$r1" = 1 ] && record PASS R1 "cross-machine 2-voter Raft: both servers epoch=$e1 consistent, leader=$l1 consistent; one registry (R4 revokes a srv1-side session via s2; R2/R5 double-check both rosters)" \
             || record FAIL R1 "inconsistent: srv1 epoch=$e1 leader=$l1 vs s2 epoch=$e2 leader=$l2"

# —— R2: cross-server forwarding ——
log "R2 cross-server forwarding matrix (srv1 side ↔ srv2 side, ForwardEnvelope over the real network)"
printf '| src | src side | dst | dst side | VIP | loss | avg rtt(ms) | result |\n|---|---|---|---|---|---|---|---|\n'
r2=0
cross_ping() { # cross_ping <src> <dst>
    eval "local_vip=\$VIP_$2"
    read -r loss avg <<< "$(ping3 "$1" "$local_vip")"
    local ok=PASS; [ "$loss" = 0 ] || { ok=FAIL; r2=1; }
    local a="$([ "${NODE_KIND[$1]}" = docker ] && echo srv1-direct || echo srv2-relay)"
    local b="$([ "${NODE_KIND[$2]}" = docker ] && echo srv1-direct || echo srv2-relay)"
    printf '| %s | %s | %s | %s | %s | %s%% | %s | %s |\n' "$1" "$a" "$2" "$b" "$local_vip" "$loss" "$avg" "$ok"
}
cross_ping 2w1 c5; cross_ping c5 2w1; cross_ping 2w1 c6; cross_ping c6 2w1
cross_ping 2w2 c5; cross_ping c5 2w2; cross_ping 2w2 c6; cross_ping c6 2w2
cross_ping 2w1 2w2; cross_ping c5 c6   # same-side controls
[ "$r2" = 0 ] && record PASS R2 "all 8 cross-server pairs 0 loss (+2 same-side control pairs)" \
             || record FAIL R2 "cross-server pings have loss (see table above)"

# —— R3: any endpoint is equivalent ——
log "R3 endpoint equivalence (c6: srv2/frps user port 24000 → srv1 direct port 9443, VIP must not change)"
vip_c6_before="$(on c6 'cat /var/lib/flock/vip' | tr -d '\r\n')"
rows_before="$(pj "$(peers_json c5)" 'len(arr)')"
on c6 "printf '%s\n' 'state_dir = \"/var/lib/flock\"' '' 'tun_name = \"tun0\"' 'mtu = 1280' '' 'endpoints = [\"$WIN_LAN_IP:9443\", \"$JOW_LAN_IP:24000\"]' '' '[auth]' 'username = \"mn2c6\"' > /var/lib/flock/client.toml"
on c6 'pkill -x flock-client 2>/dev/null; sleep 0.5; setsid nohup flock-client --config /var/lib/flock/client.toml service </dev/null >>/var/log/flock-client.log 2>&1 &' || true
r3=1
t=$((SECONDS+60)); until on c6 'ip link show tun0' >/dev/null 2>&1; do [ $SECONDS -ge $t ] && { r3=0; break; }; sleep 2; done
[ "$r3" = 1 ] && { wait_ping c6 "$VIP_W2SRV" 30 || r3=0; }
vip_c6_after="$(on c6 'cat /var/lib/flock/vip' | tr -d '\r\n')"
rows_after="$(pj "$(peers_json c6)" 'len(arr)')"
ep_now="$(on c6 'grep -o "flock-client: connected [^( ]*" /var/log/flock-client.log | tail -1' | sed 's/.*connected //')"
[ "$vip_c6_before" = "$vip_c6_after" ] || r3=0
[ -n "$rows_after" ] && [ "$rows_after" = "$rows_before" ] || r3=0
case "$ep_now" in "$WIN_LAN_IP":*) ;; *) r3=0;; esac
[ "$r3" = 1 ] && record PASS R3 "c6 changed endpoints (→$ep_now) with VIP unchanged ($vip_c6_after), roster row count consistent ($rows_after)" \
             || record FAIL R3 "VIP $vip_c6_before→$vip_c6_after rows $rows_before→$rows_after ep=$ep_now"

# —— R4: revocation propagates cross-machine ≤5s ——
log "R4 revocation cross-machine propagation (via s2 admin revoke the srv1-side 2w2; session kill + epoch + new-handshake rejection ≤5s)"
dev_2w2="$(on 2w2 'flock-client --config /etc/flock/client.toml gen-keys' 2>/dev/null | sed -n 's/^device-id=//p')"
[ -n "$dev_2w2" ] || dev_2w2="${DEV_2w2:-}"
if [ -z "$dev_2w2" ]; then
    record FAIL R4 "failed to get 2w2 device-id"
else
    online_before="$(stats_w2 | sed -n 's/^sessions_online=//p')"
    epoch_before="$(stats_s2 | sed -n 's/^epoch=//p')"
    conn_base="$(docker logs flock-2w2 2>/dev/null | grep -c 'flock-client: connected ')"
    t0="$(now_ms)"
    out="$(s2_admin revoke --device "$dev_2w2" 2>&1)" || record FAIL R4 "revoke submission failed: $out"
    killed=0; adv=0; dt=99999
    while :; do
        el=$(( $(now_ms) - t0 ))
        [ "$el" -gt 5000 ] && break
        [ "$killed" = 0 ] && [ "$(stats_w2 | sed -n 's/^sessions_online=//p')" -lt "$online_before" ] 2>/dev/null && killed=1
        [ "$adv" = 0 ] && [ "$(stats_s2 | sed -n 's/^epoch=//p')" -gt "$epoch_before" ] 2>/dev/null && adv=1
        dt=$el
        [ "$killed" = 1 ] && [ "$adv" = 1 ] && break
        sleep 0.3
    done
    no_reconn=1
    [ "$(docker logs flock-2w2 2>/dev/null | grep -c 'flock-client: connected ')" -gt "$conn_base" ] && no_reconn=0
    t=$((SECONDS+10))
    while [ $SECONDS -lt $t ]; do
        [ "$(docker logs flock-2w2 2>/dev/null | grep -c 'flock-client: connected ')" -gt "$conn_base" ] && { no_reconn=0; break; }
        sleep 1
    done
    if [ "$killed" = 1 ] && [ "$adv" = 1 ] && [ "$no_reconn" = 1 ]; then
        record PASS R4 "≤5s (measured ${dt}ms): srv1 session killed (sessions_online $online_before→$(stats_w2 | sed -n 's/^sessions_online=//p')) + epoch advanced (s2 view $epoch_before→$(stats_s2 | sed -n 's/^epoch=//p')) + no new connection in the 15s observation window (new handshakes rejected)"
    else
        record FAIL R4 "killed=$killed epoch_adv=$adv no_reconnect=$no_reconn dt=${dt}ms"
    fi
fi

# —— R5: both-side rosters ——
# Semantics calibration (server.rs:897 "roster = same snapshot as Active
# rows"): revoked rows do not appear in the roster (the registry keeps them for
# audit, IPs are not reused —— the epoch/session-kill faces of R4 re-checked);
# row count = 2 servers + 3 Active clients.
# The remote server row's latency column = —: client→non-access-server VIP
# pings get ICMP unreachable by design (§2.2 forwarding rule 4: a server is not
# a "device lease" forwarding target), probe timeout ⇒ None ⇒ rendered as —.
# Also: R4's global revocation_epoch advance invalidates all in-flight tickets
# (ticket epoch check; the daemon re-logs-in every 25s to keep alive) —— the
# roster may be TicketBad transient right after the revocation (m7 commit
# 76241a2 set the bounded-retry precedent).
log "R5 peers roster (2w1 = srv1 side / c5 = srv2 side; revoked rows leave the roster by design)"
t=$((SECONDS+40))
until [ "$(peers_json 2w1 | head -c1)" = "[" ] && [ "$(peers_json c5 | head -c1)" = "[" ]; do
    [ $SECONDS -ge $t ] && break
    sleep 2
done
echo "--- 2w1: flock-client peers ---"; peers_of 2w1 | sed 's/^/    /'
echo "--- c5: flock-client peers ---";  peers_of c5 | sed 's/^/    /'
check_peers_nl() { # check_peers_nl <node> <tag> <rows> <offline> <allowed-no-latency-rows>
    local n="$1" tag="$2" want_rows="$3" want_off="$4" want_nolat="$5" j rows off nolat has_srv ok=1
    j="$(peers_json "$n")"
    rows="$(pj "$j" 'len(arr)')"
    off="$(pj "$j" 'len([r for r in arr if not r["online"]])')"
    nolat="$(pj "$j" 'len([r for r in arr if not r["is_self"] and r["latency_ms"] is None])')"
    has_srv="$(pj "$j" 'len([r for r in arr if r["kind"] in ("Server","server")])')"
    [ "$rows" = "$want_rows" ] || ok=0
    [ "$off" = "$want_off" ] || ok=0
    [ "$nolat" = "$want_nolat" ] || ok=0
    [ "$has_srv" -ge 2 ] 2>/dev/null || ok=0
    if [ "$ok" = 1 ]; then
        record PASS "$tag" "$n roster has $rows rows (2 servers + 3 Active clients; revoked rows leave the roster by design); all non-self latencies non-empty except the remote server"
    else
        record FAIL "$tag" "$n roster abnormal: rows=$rows(expected $want_rows) offline=$off(expected $want_off) no-latency=$nolat(expected $want_nolat) server-rows=$has_srv"
    fi
}
check_peers_nl 2w1 R5-w 5 0 1
check_peers_nl c5  R5-l 5 0 1
save_state
fi

# ============================================================================
log "Summary"
printf '%s\n' "----------------------------------------"
for s in "${SUMMARY[@]}"; do IFS='|' read -r st id detail <<< "$s"; printf '[%s] %-4s | %s\n' "$st" "$id" "$detail"; done
printf '%s\n' "----------------------------------------"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ] && exit 0 || exit 1
