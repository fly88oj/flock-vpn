#!/usr/bin/env bash
# win-docker-cleanup.sh —— multi-machine test teardown (run in Windows Git Bash):
# deletes the flock-* containers (scenario 1: wc1/wc2; scenario 2:
# srv1/2w1/2w2) and their named volumes (down -v semantics) + the local
# .tmp/flock-mn run state. Matches only flock- prefixed containers; other
# containers are never touched. Exit code always 0.

export MSYS_NO_PATHCONV=1
set -u

_src="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
HERE="$(cd "$_src" && pwd -W 2>/dev/null || echo "$_src")"

echo "== flock-* containers =="
mapfile -t ct < <(docker ps -aq --filter 'name=flock-' 2>/dev/null)
if [ "${#ct[@]}" -gt 0 ] && [ -n "${ct[0]}" ]; then
    docker rm -f "${ct[@]}" >/dev/null
    echo "deleted: $(docker ps -a --filter 'name=flock-' --format '{{.Names}}' | tr '\n' ' ')(now empty)"
else
    echo "(none)"
fi

echo "== flock-mn-* named volumes =="
mapfile -t vols < <(docker volume ls -q --filter 'name=flock-mn-' 2>/dev/null)
if [ "${#vols[@]}" -gt 0 ] && [ -n "${vols[0]}" ]; then
    docker volume rm "${vols[@]}" >/dev/null
    echo "deleted: ${vols[*]}"
else
    echo "(none)"
fi

echo "== run state (.tmp/flock-mn) =="
rm -rf "$HERE/../../.tmp/flock-mn" 2>/dev/null && echo "deleted" || echo "(none)"

echo "cleanup complete. Remaining: $(docker ps -a --filter 'name=flock-' --format '{{.Names}}' | tr '\n' ' ')"
