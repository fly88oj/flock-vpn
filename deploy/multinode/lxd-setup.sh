#!/usr/bin/env bash
# lxd-setup.sh —— real multi-machine networking test: the provisioning script for
# the jowency (Ubuntu + LXD) side.
#
# Runs on the jowency host (dispatched via ssh from the Windows side; see the
# README "replication steps"):
#   bash lxd-setup.sh 1     # Scenario 1: flock-s1 (Direct server) + flock-c3/c4 (clients)
#   bash lxd-setup.sh 2     # Scenario 2: flock-s2 (Frp+Raft server) + flock-c5/c6 (clients)
#                           #        + frps host process + init-cluster cluster material
#
# Prerequisites: ~/flock-mn/bin/{flock-server-direct,flock-server-mp,flock-client,frps,frpc}
#                ~/flock-mn/assets/ (this directory's templates, streamed over from
#                the Windows side as a tar).
# Idempotent: skip launch when a container exists; config/binaries/tools ensured
# every time; frps skips when it detects the port already listening; init-cluster
# skips when root.seed already exists.
#
# Boundary: touches only flock-* prefixed containers; existing containers are
# never touched. After testing, lxd-cleanup.sh deletes everything.

set -euo pipefail

SCENARIO="${1:-}"
[ "$SCENARIO" = 1 ] || [ "$SCENARIO" = 2 ] || { echo "usage: lxd-setup.sh <1|2>" >&2; exit 64; }

BIN=~/flock-mn/bin
ASSETS=~/flock-mn/assets
RUN=~/flock-mn/run

# JOW_LAN_IP can be pinned via an environment variable (multi-NIC machines: the
# route source may not be the ssh-side IP; proxy/frps both listen on 0.0.0.0,
# any host IP works —— the default takes "the route source toward Windows";
# when replicating you can be explicit with JOW_LAN_IP=192.168.31.x bash
# lxd-setup.sh ...).
JOW_LAN_IP="${JOW_LAN_IP:-$(ip -4 route get 192.168.31.244 | head -1 | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')}"
LXD_GW_IP="$(ip -4 addr show lxdbr0 | awk '/inet /{print $2}' | cut -d/ -f1)"
[ -n "$JOW_LAN_IP" ] && [ -n "$LXD_GW_IP" ] || { echo "LAN/lxdbr0 IP probe failed" >&2; exit 1; }
echo "jowency LAN IP = $JOW_LAN_IP ; lxdbr0 = $LXD_GW_IP"

mkdir -p "$RUN"

render() { # render <template> <outfile> [KEY=value ...] —— @KEY@ placeholder substitution
    local t="$ASSETS/$1" o="$2"; shift 2
    local expr=() kv
    for kv in "$@"; do expr+=("-e" "s|@${kv%%=*}@|${kv#*=}|g"); done
    sed "${expr[@]}" "$t" > "$o"
}

# —— common: launch + push binaries (tar stream; scp/lxc pull silently truncate
#    large files) + tools + rp_filter ——
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
# Scenario 1 [single server · Direct]: flock-s1 + LXD clients c3/c4
# ============================================================================

ensure_container flock-s1 flock-server-direct
# The pushed name flock-server-direct → the canonical in-container name
# flock-server (config/CLI aligned with the deploy images)
lxc exec flock-s1 -- mv -f /usr/local/bin/flock-server-direct /usr/local/bin/flock-server
render server-s1-direct.toml "$RUN/server-s1.toml" "JOW_LAN_IP=$JOW_LAN_IP"
put_file flock-s1 "$RUN/server-s1.toml" /etc/flock/server.toml
# Access endpoint publication: LXD proxy device → jowency 0.0.0.0:9443 (in-container
# 127.0.0.1:9443)
lxc config device get flock-s1 p9443 listen >/dev/null 2>&1 \
    || lxc config device add flock-s1 p9443 proxy listen=tcp:0.0.0.0:9443 connect=tcp:127.0.0.1:9443

for pair in "flock-c3 mnc3" "flock-c4 mnc4"; do
    set -- $pair
    ensure_container "$1" flock-client
    render_client_cfg "$RUN/$1-client.toml" "$JOW_LAN_IP:9443" "$2"
    put_file "$1" "$RUN/$1-client.toml" /var/lib/flock/client.toml
done

echo "Scenario 1 LXD side ready: flock-s1 (Direct :9443 published on $JOW_LAN_IP:9443) + flock-c3/c4"

# ============================================================================
else
# Scenario 2 [two servers · cross-machine Raft + dual transport]: flock-s2
# (Frp+Raft) + clients c5/c6 + frps (host) + init-cluster material (2 voters)
# ============================================================================

# —— frps (host process; skip when the port is already listening) ——
if ! ss -ltn 2>/dev/null | grep -q ':7000 '; then
    nohup "$BIN/frps" -c "$ASSETS/frps-mn.toml" > "$RUN/frps.log" 2>&1 &
    echo "frps started (pid $!, log $RUN/frps.log)"
else
    echo "frps already listening on :7000 (idempotent skip)"
fi

# —— init-cluster (2 voters; idempotent) —— endpoint order = the Windows
#    server-1 direct port, the flock-s2 frps user port
if [ ! -f "$RUN/mat/root.seed" ]; then
    mkdir -p "$RUN/mat"
    # init-cluster generates locally (no dialing); the config must pass full
    # validation (advertise_endpoint required).
    printf 'state_dir = "%s/stub"\nbind = "127.0.0.1:19999"\nadmin_bind = "127.0.0.1:19998"\nadvertise_endpoint = "127.0.0.1:19999"\ndir_version = 1\n' "$RUN" > "$RUN/stub.toml"
    "$BIN/flock-server-mp" --config "$RUN/stub.toml" \
        init-cluster --voters 2 --out "$RUN/mat" \
        --endpoints "192.168.31.244:9443,$JOW_LAN_IP:24000"
    echo "init-cluster done (root.seed + node-0/1.bundle under $RUN/mat)"
else
    echo "init-cluster already present (idempotent skip)"
fi

ensure_container flock-s2 flock-server-mp frpc
# The pushed name flock-server-mp → the canonical in-container name flock-server
# (same Direct-tier handling as flock-s1)
lxc exec flock-s2 -- mv -f /usr/local/bin/flock-server-mp /usr/local/bin/flock-server
render server-2s-frp-mp.toml "$RUN/server-s2.toml" "JOW_LAN_IP=$JOW_LAN_IP" "LXD_GW_IP=$LXD_GW_IP" "WIN_LAN_IP=192.168.31.244"
put_file flock-s2 "$RUN/server-s2.toml" /etc/flock/server.toml
put_file flock-s2 "$RUN/mat/node-1.bundle" /var/lib/flock/node-1.bundle
# Raft fabric publication: LXD proxy device → jowency 0.0.0.0:9500 (the Windows-side
# server-1 dials in cross-machine)
lxc config device get flock-s2 p9500 listen >/dev/null 2>&1 \
    || lxc config device add flock-s2 p9500 proxy listen=tcp:0.0.0.0:9500 connect=tcp:127.0.0.1:9500

for pair in "flock-c5 mn2c5" "flock-c6 mn2c6"; do
    set -- $pair
    ensure_container "$1" flock-client
    render_client_cfg "$RUN/$1-client.toml" "$JOW_LAN_IP:24000" "$2"
    put_file "$1" "$RUN/$1-client.toml" /var/lib/flock/client.toml
done

echo "Scenario 2 LXD side ready: flock-s2 (Frp→frps:24000 + Raft :9500 published) + flock-c5/c6"
echo "node-0.bundle awaiting the Windows-side pull: ssh $USER@${JOW_LAN_IP} cat $RUN/mat/node-0.bundle"
fi
