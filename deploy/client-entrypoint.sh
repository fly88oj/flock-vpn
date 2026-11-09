#!/bin/sh
# M3 client entrypoint (docs/design.md §7-M3).
#
# Orchestration order (driven by deploy/m3_assert.sh):
#   1. client `gen-keys` (generate/reuse device keys and print the public keys);
#   2. server `device-add` (register the device + assign a VIP) and `invite`
#      (issue a v3 invite);
#   3. client `invite <file>` (pin the cluster root key + store the signed
#      directory) + write the vip file;
#   4. after `touch /var/lib/flock/ready`, `docker compose restart client`
#      ⇒ this entrypoint execs the client main process (logs go to
#      `docker compose logs client`, the A9 grep face).
set -e
STATE=/var/lib/flock

if [ -f "$STATE/ready" ]; then
    # $@ overrides the default (M7: the compose command injects --config with
    # the in-volume config + the service subcommand).
    if [ "$#" -eq 0 ]; then
        set -- --config /etc/flock/client.toml
    fi
    echo "flock-client: state ready; starting (flock-client $*)"
    exec flock-client "$@"
fi

echo "flock-client: awaiting bootstrap (run deploy/m3_assert.sh)..."
exec sleep infinity
