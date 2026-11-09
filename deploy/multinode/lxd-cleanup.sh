#!/usr/bin/env bash
# lxd-cleanup.sh —— multi-machine test teardown (jowency side, executed via ssh):
#   bash lxd-cleanup.sh            # full clean: flock-* containers (incl. proxy
#                                  # devices) + the frps process + ~/flock-mn
#                                  # (binaries/cluster material/temp files)
#   bash lxd-cleanup.sh --keep-files   # delete only the containers and frps
#                                  # (keep ~/flock-mn for reuse)
#
# Boundary: deletes only flock-* prefixed containers (proxy devices die with
# the container); existing containers (dmgvm/krymux-*/l2ctest/uesktop-ui-audit
# etc.) are never touched. Exit code: always 0 (a missing item is already
# clean).

set -u

KEEP_FILES=0
[ "${1:-}" = "--keep-files" ] && KEEP_FILES=1

echo "== flock-* containers =="
mapfile -t ct < <(lxc list flock- -c n --format csv 2>/dev/null)
if [ "${#ct[@]}" -gt 0 ] && [ -n "${ct[0]}" ]; then
    lxc delete --force "${ct[@]}"
    echo "deleted: ${ct[*]}"
else
    echo "(none)"
fi

echo "== frps host process (started by lxd-setup.sh scenario 2) =="
if pkill -f 'flock-mn/bin/frps' 2>/dev/null; then
    echo "frps stopped"
else
    echo "(not running)"
fi

if [ "$KEEP_FILES" = 0 ]; then
    echo "== ~/flock-mn (binaries/cluster material/logs/temp files) =="
    rm -rf ~/flock-mn
    echo "removed"
else
    echo "--keep-files: ~/flock-mn kept"
fi

echo "cleanup complete. Remaining flock-* containers: $(lxc list flock- -c n --format csv 2>/dev/null | tr '\n' ' ')"
