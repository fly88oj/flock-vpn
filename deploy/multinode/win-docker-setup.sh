#!/usr/bin/env bash
# win-docker-setup.sh —— real multi-machine networking test: the Windows-side
# Docker provisioning script (run in Git Bash).
#
#   bash deploy/multinode/win-docker-setup.sh 1     # Scenario 1: clients flock-wc1/wc2 (→ jowency:9443)
#   bash deploy/multinode/win-docker-setup.sh 2     # Scenario 2: the server-1 container flock-srv1
#                                                   #   (Direct+Raft, publishing 9443/9500) + clients
#                                                   #   flock-2w1/2w2 (→ server-1)
#
# Images reuse flock/client:e2e / flock/server:e2e-a (tool face:
# iproute2/ping/procps/jq); **binaries are override-mounted from the HEAD build
# artifacts** (deploy/multinode/out/, built via Dockerfile.buildbin), so
# container behavior = this repo's current sources. State uses named volumes
# (redb file locks do not go through 9p mounts).
# Idempotent: skip creation when a container exists (the config is written by
# the multinode_assert.sh bootstrap).

export MSYS_NO_PATHCONV=1
set -euo pipefail

SCENARIO="${1:-}"
[ "$SCENARIO" = 1 ] || [ "$SCENARIO" = 2 ] || { echo "usage: win-docker-setup.sh <1|2>" >&2; exit 64; }

_src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"
OUT="$HERE/out"
# Note: BuildKit local output files carry no POSIX x bit (Windows ACL), so only
# existence is checked here; Docker Desktop's Windows→Linux bind mounts present
# 0777 inside the container, the executable bit is not a concern.
[ -f "$OUT/flock-client" ] || { echo "missing $OUT/flock-client (build first: docker buildx build -f deploy/multinode/Dockerfile.buildbin --output type=local,dest=deploy/multinode/out .)" >&2; exit 1; }

WIN_LAN_IP="$(ipconfig | awk '/IPv4/{print $NF}' | grep '^192\.168\.' | head -1)"
JOW_LAN_IP="${JOW_LAN_IP:-192.168.31.221}"
echo "Windows LAN IP = $WIN_LAN_IP ; jowency = $JOW_LAN_IP"

CLIENT_ARGS=(--cap-add NET_ADMIN --device /dev/net/tun
    --sysctl net.ipv4.conf.all.rp_filter=1 --sysctl net.ipv4.conf.default.rp_filter=1
    -v "$OUT/flock-client:/usr/local/bin/flock-client:ro")

ensure_client() { # ensure_client <name> <hostname>
    docker inspect "$1" >/dev/null 2>&1 && { echo "$1 already exists (idempotent skip)"; return; }
    docker run -d --name "$1" --hostname "$2" "${CLIENT_ARGS[@]}" \
        -v "flock-mn-$1:/var/lib/flock" \
        flock/client:e2e --config /etc/flock/client.toml service
    echo "$1 created (awaiting bootstrap; the config is written by the multinode_assert.sh bootstrap)"
}

if [ "$SCENARIO" = 1 ]; then
    ensure_client flock-wc1 flock-wc1
    ensure_client flock-wc2 flock-wc2
    echo "Scenario 1 Windows side ready: flock-wc1/wc2 (Docker bridge → $JOW_LAN_IP:9443)"
else
    # —— server-1: Direct + multi-primary binary override + 9443/9500 published ——
    if ! docker inspect flock-srv1 >/dev/null 2>&1; then
        [ -f "$OUT/flock-server-mp" ] || { echo "missing $OUT/flock-server-mp" >&2; exit 1; }
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
        echo "flock-srv1 created (Direct 0.0.0.0:9443 + Raft 0.0.0.0:9500 published)"
    else
        echo "flock-srv1 already exists (idempotent skip)"
    fi
    ensure_client flock-2w1 flock-2w1
    ensure_client flock-2w2 flock-2w2
    echo "Scenario 2 Windows side ready: flock-srv1 + flock-2w1/2w2 (→ $WIN_LAN_IP:9443)"
fi
