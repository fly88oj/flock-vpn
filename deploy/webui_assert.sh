#!/usr/bin/env bash
# webui_assert.sh —— M8 Web UI container integration assertions (docs/design.md §7-M8.9).
#
#   docker compose -f deploy/webui.yml up -d --build
#   bash deploy/webui_assert.sh
#
# This batch (M8b) runs the full W1–W7 set: W4 (client VIP reachability + login
# chain) and W6 (dual-VIP data consistency) are new; W6 needs the dual tier
# running (otherwise PENDING output, not a FAIL).
set -u
# Working directory = repo root (the compose file path deploy/webui.yml resolves
# relative to the root).
cd "$(dirname "$0")/.."
# Git Bash (MSYS) host: no POSIX→Windows translation for container-internal
# absolute paths passed to docker exec (no-op for Linux/macOS hosts).
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXEMPT='*'

COMPOSE="docker compose -f deploy/webui.yml"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL $1"; }
pending() { echo "PENDING $1"; }

# —— readiness wait: server-a's webui loopback face responds (bootstrap 200) ——
wait_webui() {
  for _ in $(seq 1 60); do
    code=$($COMPOSE exec -T server-a curl -s -o /dev/null -w '%{http_code}' \
      http://127.0.0.1:9800/api/bootstrap 2>/dev/null || echo 000)
    [ "$code" = "200" ] && return 0
    sleep 2
  done
  return 1
}

# =====================================================================
# W1 not logged in: management API all 401 (curl 127.0.0.1:9800 inside server-a)
# =====================================================================
w1() {
  echo "== W1 management API all 401 when not logged in"
  local all=1
  for path in /api/me /api/peers /api/users /api/audit /api/dashboard/summary /api/config; do
    code=$($COMPOSE exec -T server-a curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:9800$path")
    body=$($COMPOSE exec -T server-a curl -s "http://127.0.0.1:9800$path")
    if [ "$code" = "401" ] && printf '%s' "$body" | grep -q '"not_logged_in"'; then
      echo "  401 $path OK"
    else
      echo "  401 $path FAIL (code=$code body=$body)"; all=0
    fi
  done
  for path in /api/logout /api/users; do
    code=$($COMPOSE exec -T server-a curl -s -o /dev/null -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' -H 'X-Flock-Web: 1' -d '{}' "http://127.0.0.1:9800$path")
    if [ "$code" = "401" ]; then echo "  401 POST $path OK"; else echo "  401 POST $path FAIL ($code)"; all=0; fi
  done
  [ "$all" = "1" ] && ok "W1 all 401 when not logged in" || bad "W1 not-logged-in 401 matrix"
}

# =====================================================================
# W2 loopback login → full CRUD chain (web-admin-add piped the password →
#    webui_login driver)
# =====================================================================
w2() {
  echo "== W2 first-admin bootstrap + full CRUD chain"
  # ① web-admin-add (service running ⇒ via the admin endpoint; pipe the
  #    password twice). Re-run tolerance: the volume persists ⇒ the
  #    "already has a password" rejection counts as pass (the password is the
  #    script constant; later logins use the same value).
  local add_out
  add_out=$(printf 'W2Boss-Pw\nW2Boss-Pw\n' | $COMPOSE exec -T server-a \
      flock-server --config /etc/flock/server.toml web-admin-add w2admin 2>&1)
  if echo "$add_out" | grep -q "web admin ready"; then
    echo "  web-admin-add w2admin OK"
  elif echo "$add_out" | grep -q "already has a password"; then
    echo "  web-admin-add w2admin OK (re-run: password already set)"
  else
    echo "$add_out" | sed 's/^/  /'; bad "W2 web-admin-add"; return
  fi
  local W B
  W="$COMPOSE exec -T server-a webui_login --base http://127.0.0.1:9800"
  B="--user w2admin --pass W2Boss-Pw"
  # ② Login (anchor signature check) + me.
  $W $B login | grep -q "login=ok" && echo "  login OK" || { bad "W2 login"; return; }
  $W $B me --expect-admin=1 | grep -q "admin=true" && echo "  me admin OK" || bad "W2 me"
  # ③ users create (one-time token) → pw-set (native OPAQUE) → list. Re-run
  #    tolerance: user_exists ⇒ already has a password (later steps use the
  #    same password constant).
  local token out
  out=$($W $B user-create w2bob)
  token=$(echo "$out" | sed -n 's/.*token=//p')
  if [ -n "$token" ]; then
    echo "  user-create w2bob OK"
    $W --user w2bob --token "$token" --pass W2Bob-Pw pw-set | grep -q "pw-set=w2bob ok" \
      && echo "  pw-set OK" || bad "W2 pw-set"
  elif echo "$out" | grep -q "user-create=w2bob"; then
    echo "  user-create w2bob OK (re-run: already exists)"
  else
    bad "W2 user-create ($out)"; return
  fi
  $W $B users | grep -q "users_count=2" && echo "  users list OK" || bad "W2 users"
  # Disable/reset/set-admin (after reset, set the password back for W3).
  $W $B user-disable w2bob | grep -q "ok" && echo "  user-disable OK" || bad "W2 user-disable"
  $W $B user-enable w2bob | grep -q "ok" && echo "  user-enable OK" || bad "W2 user-enable"
  local nt
  nt=$($W $B user-reset-password w2bob | sed -n 's/.*token=//p')
  $W --user w2bob --token "$nt" --pass W2Bob-Pw2 pw-set | grep -q "ok" \
    && echo "  reset-password+pw-set OK" || bad "W2 reset-password"
  # Self-demotion rejected (409 → exit code 42).
  $W $B user-set-admin w2admin 0 >/dev/null; rc=$?
  [ "$rc" = "42" ] && echo "  cannot_demote_self(42) OK" || bad "W2 cannot_demote_self (rc=$rc)"
  # ④ Device fixture (admin-endpoint device-add —— TOFU pre-provisioning;
  #    fixed 32B b64: x25519="A"*32, ed25519="B"*32) → peers list/revoke/audit.
  local dev_hex
  dev_hex=$($COMPOSE exec -T server-a flock-server --config /etc/flock/server.toml     device-add --user w2bob     --device-x QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE     --device-ed QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI     2>/dev/null | sed -n 's/device_id=//p')
  # Idempotent fallback: already registered (re-run) ⇒ take the device from the
  # peers list (deterministic device_id of the b64 fixture).
  if [ -z "$dev_hex" ]; then
    dev_hex=$($W $B peers | grep -v 'peers 100.64.0.1 ' | grep -o 'device_id=[0-9a-f]*' | head -1 | cut -d= -f2)
    [ -n "$dev_hex" ] && echo "  device fixture (peers lookup) = $dev_hex"
  fi
  if [ -n "$dev_hex" ]; then
    echo "  device-add fixture OK ($dev_hex)"
    $W $B peers | grep -q "peers_count=2" && echo "  peers list (server+device) OK" || bad "W2 peers"
    $W $B peer-op revoke "$dev_hex" | grep -q "ok epoch=" && echo "  peers revoke OK" || bad "W2 peers revoke"
    $W $B audit-grep peer.revoke "$dev_hex" | grep -q 'action="peer.revoke"\|action=peer.revoke'       && echo "  audit contains peer.revoke OK" || bad "W2 audit peer.revoke"
  else
    echo "  device-add fixture unavailable (skipping the peers-revoke sub-face)"; bad "W2 device-add fixture"
  fi
  # ⑤ dashboard/series.
  $W $B summary | grep -q "sync_mode=\"single\"" && echo "  summary OK" || bad "W2 summary"
  $W $B series --vip 100.64.0.1 | grep -q "series vip=100.64.0.1" && echo "  series OK" || bad "W2 series"
  # ⑥ audit contains the corresponding rows.
  $W $B audit-grep user.create w2bob | grep -q 'action="user.create"\|action=user.create' \
    && echo "  audit user.create OK" || bad "W2 audit user.create"
  $W $B audit-grep session.login w2admin | grep -q 'action="session.login"\|action=session.login' \
    && echo "  audit session.login OK" || bad "W2 audit session.login"
  # ⑦ logout invalidates.
  $W --user w2bob --pass W2Bob-Pw2 logout | grep -q "sid-invalidated=true" \
    && echo "  logout OK" || bad "W2 logout"
  ok "W2 full CRUD chain (per-item output above)"
}

# =====================================================================
# W3 non-admin account: read-only 200, users*/revoke/kick/audit 403
# =====================================================================
w3() {
  echo "== W3 non-admin three states"
  local W
  W="$COMPOSE exec -T server-a webui_login --base http://127.0.0.1:9800"
  # W2 already created w2bob (non-admin, password W2Bob-Pw2).
  if ! $W --user w2bob --pass W2Bob-Pw2 login | grep -q "login=ok"; then
    bad "W3 precondition (w2bob login)"; return
  fi
  $W --user w2bob --pass W2Bob-Pw2 me --expect-admin=0 | grep -q "admin=false" \
    && echo "  me admin=false OK" || bad "W3 me"
  local rc1 rc2
  $W --user w2bob --pass W2Bob-Pw2 probe-readonly >/dev/null; rc1=$?
  [ "$rc1" = "0" ] && echo "  read-only endpoints all 200 OK" || bad "W3 read-only 200 (rc=$rc1)"
  $W --user w2bob --pass W2Bob-Pw2 probe-admin-denied >/dev/null; rc2=$?
  [ "$rc2" = "0" ] && echo "  admin endpoints all 403 OK" || bad "W3 admin 403 (rc=$rc2)"
  [ "$rc1" = "0" ] && [ "$rc2" = "0" ] && ok "W3 non-admin read-only/403" || bad "W3 non-admin"
}

# =====================================================================
# W4 client-1 (flock-client network namespace) VIP:9800 login page reachable +
#    login chain works (VPN-segment path proof: peer → E2E tunnel → server-a
#    tun0 → VIP:9800)
# =====================================================================

# client-1 onboarding (single-server face: device-add → invite → login → ready;
# idempotent —— ready marker + peers VIP lookup for registered leftovers).
# endpoints pin the compose service names (server-side
# advertise_endpoint=127.0.0.1:9443 is unreachable from the client container).
w4_bootstrap_client() {
  if $COMPOSE exec -T client-1 sh -c 'test -f /var/lib/flock/ready' 2>/dev/null; then
    echo "  client-1 already ready (idempotent skip)"
    return 0
  fi
  # In-volume config ([auth] username + pinned endpoints —— shared by the
  # daemon and the login subcommand).
  $COMPOSE exec -T client-1 sh -c 'printf "state_dir = \"/var/lib/flock\"\ntun_name = \"tun0\"\nmtu = 1280\n\nendpoints = [\"server-a:9443\"]\n\n[auth]\nusername = \"w4client\"\n" > /var/lib/flock/client.toml' || return 1
  local keys dx de devid out vip
  keys=$($COMPOSE exec -T client-1 flock-client --config /var/lib/flock/client.toml gen-keys 2>/dev/null) || return 1
  dx=$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')
  de=$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')
  devid=$(printf '%s\n' "$keys" | sed -n 's/^device-id=//p')
  [ -n "$dx" ] && [ -n "$de" ] || { echo "  gen-keys output abnormal"; return 1; }
  out=$($COMPOSE exec -T server-a flock-server --config /etc/flock/server.toml \
      device-add --user w4client --device-x "$dx" --device-ed "$de" 2>&1)
  vip=$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')
  if [ -z "$vip" ] && printf '%s' "$out" | grep -q "already registered"; then
    # Idempotent fallback: a device left over from a previously failed run ——
    # recover the VIP from webui peers by device_id (w2admin; W2 precondition
    # already created it).
    vip=$($COMPOSE exec -T server-a webui_login --base http://127.0.0.1:9800 \
        --user w2admin --pass W2Boss-Pw peers 2>/dev/null \
      | grep "device_id=$devid" | sed -n 's/^peers \([0-9.]*\) .*/\1/p')
    echo "  device already registered (leftover) —— peers lookup vip=$vip"
  fi
  case "$vip" in
    100.64.*) ;;
    *) echo "  device-add/VIP abnormal: $out"; return 1;;
  esac
  $COMPOSE exec -T server-a flock-server --config /etc/flock/server.toml \
      invite --ttl-secs 86400 2>/dev/null | $COMPOSE exec -T client-1 sh -c 'cat > /var/lib/flock/invite.b64' || { echo "  invite issuance/persist failed"; return 1; }
  $COMPOSE exec -T client-1 flock-client --config /var/lib/flock/client.toml \
      invite /var/lib/flock/invite.b64 >/dev/null 2>&1 || { echo "  invite ingest failed"; return 1; }
  printf '%s\n' "$vip" | $COMPOSE exec -T client-1 sh -c 'cat > /var/lib/flock/vip' || return 1
  printf 'W4-Client-Pw\nW4-Client-Pw\n' | $COMPOSE exec -T client-1 \
      flock-client --config /var/lib/flock/client.toml login >/dev/null 2>&1 || { echo "  client login failed"; return 1; }
  $COMPOSE exec -T client-1 sh -c 'touch /var/lib/flock/ready' || return 1
  $COMPOSE restart client-1 >/dev/null 2>&1 || return 1
  echo "  client-1 onboarding complete (vip=$vip)"
}

# Copy webui_login from the server container into the client container (binary
# outside the image, relayed via the host; the compose command is passed
# explicitly —— the W4 single tier / W6 dual tier use separate projects).
cp_webui_login() { # cp_webui_login <compose-cmd> <src-service> <dst-service>
  local CC tmp
  CC="$1"
  tmp=$(mktemp)
  [ -n "$(command -v cygpath)" ] && tmp=$(cygpath -w "$tmp")
  $CC cp "$2:/usr/local/bin/webui_login" "$tmp" >/dev/null 2>&1 || return 1
  $CC cp "$tmp" "$3:/usr/local/bin/webui_login" >/dev/null 2>&1 || return 1
  $CC exec -T "$3" chmod +x /usr/local/bin/webui_login || return 1
  rm -f "$tmp"
}

w4() {
  echo "== W4 client VIP:9800 reachable + login chain (VPN-segment path)"
  # ① client-1 service up (tun ready + ping to server-a VIP works).
  w4_bootstrap_client || { bad "W4 client onboarding"; return; }
  local t=$((SECONDS + 90))
  until $COMPOSE exec -T client-1 sh -c 'ip link show tun0' >/dev/null 2>&1; do
    [ $SECONDS -ge $t ] && { bad "W4 tun0 not created within 90s"; return; }
    sleep 3
  done
  t=$((SECONDS + 90)); local ok=""
  while [ $SECONDS -lt $t ]; do
    $COMPOSE exec -T client-1 ping -c 1 -W 2 100.64.0.1 >/dev/null 2>&1 && { ok=1; break; }
    sleep 3
  done
  [ -n "$ok" ] && echo "  ping 100.64.0.1 OK" || { bad "W4 ping VIP"; return; }
  # ② curl login page reachable (GET / inside the VPN segment).
  local code body
  code=$($COMPOSE exec -T client-1 curl -s -o /dev/null -w '%{http_code}' http://100.64.0.1:9800/ 2>/dev/null)
  body=$($COMPOSE exec -T client-1 curl -s http://100.64.0.1:9800/ 2>/dev/null | head -c 4096)
  if [ "$code" = "200" ] && printf '%s' "$body" | grep -q "flockApp"; then
    echo "  curl VIP:9800 login page 200 OK"
  else
    bad "W4 login page reachable (code=$code)"; return
  fi
  # ③ Login chain works (webui_login driver pointed at the VIP endpoint;
  #    W2's w2admin).
  cp_webui_login "$COMPOSE" server-a client-1 || { bad "W4 webui_login copy"; return; }
  local WV
  WV="$COMPOSE exec -T client-1 webui_login --base http://100.64.0.1:9800"
  $WV --user w2admin --pass W2Boss-Pw login | grep -q "login=ok" \
    && echo "  VIP login chain login=ok OK" || { bad "W4 VIP login"; return; }
  # ④ origin=vpn (session tier set by the VPN segment) + read-only face +
  #    peers containing the server row.
  $WV --user w2admin --pass W2Boss-Pw me 2>/dev/null | grep -q 'origin="vpn"' \
    && echo "  me origin=vpn OK" || bad "W4 origin=vpn"
  $WV --user w2admin --pass W2Boss-Pw probe-readonly >/dev/null \
    && echo "  read-only face (VIP base) all 200 OK" || bad "W4 read-only face"
  $WV --user w2admin --pass W2Boss-Pw peers 2>/dev/null | grep -q "peers 100.64.0.1 " \
    && echo "  peers contains the server row OK" || bad "W4 peers"
  ok "W4 client VIP reachable + login chain (VPN-segment path)"
}

# =====================================================================
# W5 server-a's flockpub/LAN address :9800 unreachable from client-1
#    (connection-layer proof)
# =====================================================================
w5() {
  echo "== W5 LAN address :9800 unreachable at the connection layer"
  local out
  out=$($COMPOSE exec -T client-1 bash -c '
    ip=$(getent hosts server-a | awk "{print \$1}" | head -1)
    [ -n "$ip" ] || ip=$(ping -c1 -W1 server-a 2>/dev/null | sed -n "s/.*(\([0-9.]*\)).*/\1/p" | head -1)
    echo "server-a-lan-ip=$ip"
    if timeout 4 bash -c "exec 3<>/dev/tcp/$ip/9800" 2>/dev/null; then
      echo "reachable=YES"
    else
      echo "reachable=NO"
    fi')
  echo "$out" | sed 's/^/  /'
  if echo "$out" | grep -q "reachable=NO"; then
    ok "W5 LAN :9800 unreachable (unbound face)"
  else
    bad "W5 LAN :9800 reachable (binding leak!)"
  fi
}

# =====================================================================
# W7 config validation: port conflict refuses startup + no bind key in the
#    config face (whitelisted key set)
# =====================================================================
w7() {
  echo "== W7 config validation"
  # ① [webui] port=9443 (conflicts with bind) ⇒ refuses to start (the
  #    validate face runs before binding).
  out=$($COMPOSE exec -T server-a sh -c '
    cat >/tmp/bad1.toml <<EOF
state_dir = "/tmp/bad1"
bind = "0.0.0.0:9443"
admin_bind = "127.0.0.1:9444"
advertise_endpoint = "127.0.0.1:9443"
[webui]
port = 9443
EOF
    flock-server --config /tmp/bad1.toml 2>&1; echo "exit=$?"')
  echo "$out" | sed 's/^/  /'
  if echo "$out" | grep -q "conflicts with" && echo "$out" | grep -q "exit=2"; then
    echo "  port conflict refuses startup OK"
  else
    bad "W7 port conflict"
  fi
  # ② a bind key appearing in [webui] ⇒ parse layer rejects
  #    (deny_unknown_fields —— structural misconfiguration protection).
  out=$($COMPOSE exec -T server-a sh -c '
    cat >/tmp/bad2.toml <<EOF
state_dir = "/tmp/bad2"
bind = "0.0.0.0:9443"
admin_bind = "127.0.0.1:9444"
advertise_endpoint = "127.0.0.1:9443"
[webui]
bind = "0.0.0.0:9800"
EOF
    flock-server --config /tmp/bad2.toml 2>&1; echo "exit=$?"')
  echo "$out" | sed 's/^/  /'
  if echo "$out" | grep -qi "bind" && echo "$out" | grep -q "exit=2"; then
    echo "  webui key-set whitelist (bind rejected) OK"
  else
    bad "W7 whitelist keys"
  fi
  ok "W7 config validation"
}

# =====================================================================
# W6 both dual-server VIPs (100.64.0.1 / 100.64.0.2) reachable with consistent
#    data (same cluster)
#     Prerequisite: docker compose -p flock-webui-dual -f deploy/webui.yml \
#             --profile dual up -d --build
#     If the dual tier is not up ⇒ PENDING (a single-server topology run is
#     not a FAIL).
# =====================================================================
DUAL="docker compose -p flock-webui-dual -f deploy/webui.yml"
ed()  { $DUAL --profile dual exec -T "$@"; }

# Dual-cluster idempotent bootstrap: init-cluster (operator) → both enroll →
# cluster-bootstrap → both servers' stats ready → first admin → client onboard
# (device-add + cluster-invite + login).
w6_bootstrap() {
  # ① mat ready (the operator's idempotent init-cluster product).
  local t=$((SECONDS + 120))
  until ed dual-a sh -c 'test -f /mat/root.seed' 2>/dev/null; do
    [ $SECONDS -ge $t ] && { echo "  /mat/root.seed not ready within 120s"; return 1; }
    sleep 3
  done
  echo "  mat ready (root.seed in place)"
  # ② Both enroll (idempotent: skip if bundle.bin already present).
  local s b i=0
  for s in dual-a dual-b; do
    if ed "$s" sh -c 'test -f /var/lib/flock/bundle.bin' 2>/dev/null; then
      echo "  $s already enrolled (idempotent skip)"
    else
      ed "$s" flock-server --config /etc/flock/server.toml enroll --bundle "/mat/node-$i.bundle" \
        || { echo "  $s enroll failed"; return 1; }
    fi
    i=$((i+1))
  done
  # ③ cluster-bootstrap (via dual-a; idempotent; retry across the Raft
  #    startup window).
  t=$((SECONDS + 240))
  until ed dual-a flock-server --config /etc/flock/server.toml \
        cluster-bootstrap --root-seed /mat/root.seed 2>&1 | tee /tmp/w6-boot.txt | grep -q 'cluster-bootstrap ok\|idempotent: already bootstrapped'; do
    if [ $SECONDS -ge $t ]; then echo "  cluster-bootstrap not successful within 240s"; cat /tmp/w6-boot.txt; return 1; fi
    sleep 5
  done
  echo "  cluster-bootstrap OK"
  # ④ Both servers' stats ready (Bootstrap/SetOprf applied + admin up).
  t=$((SECONDS + 180)); local ok=""
  while [ -z "$ok" ]; do
    ok=1
    for s in dual-a dual-b; do
      ed "$s" flock-server --config /etc/flock/server.toml stats 2>/dev/null | grep -q '^epoch=' || ok=""
    done
    [ -n "$ok" ] && break
    [ $SECONDS -ge $t ] && { echo "  both servers' stats not ready (180s)"; return 1; }
    sleep 3
  done
  echo "  both servers' stats ready"
  # ⑤ First admin (dual-a loopback admin face; idempotent —— a password
  #    already set to the same value counts as pass).
  local add
  add=$(printf 'W6Boss-Pw\nW6Boss-Pw\n' | ed dual-a flock-server --config /etc/flock/server.toml web-admin-add w6admin 2>&1)
  if echo "$add" | grep -q "web admin ready" || echo "$add" | grep -q "already has a password"; then
    echo "  web-admin-add w6admin OK"
  else
    echo "$add" | sed 's/^/  /'; return 1
  fi
  # ⑥ dual-client onboarding (Raft face: device-add + root-signed
  #    cluster-invite + login; idempotent).
  if ed dual-client sh -c 'test -f /var/lib/flock/ready' 2>/dev/null; then
    echo "  dual-client already ready (idempotent skip)"
    return 0
  fi
  ed dual-client sh -c 'printf "state_dir = \"/var/lib/flock\"\ntun_name = \"tun0\"\nmtu = 1280\n\n[auth]\nusername = \"w6client\"\n" > /var/lib/flock/client.toml' || return 1
  local keys dx de out vip inv
  keys=$(ed dual-client flock-client --config /var/lib/flock/client.toml gen-keys 2>/dev/null) || return 1
  dx=$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')
  de=$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')
  out=$(ed dual-a flock-server --config /etc/flock/server.toml \
      device-add --user w6client --device-x "$dx" --device-ed "$de" 2>&1) || { echo "  device-add failed: $out"; return 1; }
  vip=$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')
  case "$vip" in 100.64.*) ;; *) echo "  VIP abnormal: $out"; return 1;; esac
  inv=$(ed dual-a flock-server --config /etc/flock/server.toml \
      cluster-invite --root-seed /mat/root.seed --bundle /mat/node-0.bundle --ttl-secs 86400 2>/dev/null | tail -1) \
    || { echo "  cluster-invite failed"; return 1; }
  printf '%s' "$inv" | ed dual-client sh -c 'cat > /var/lib/flock/invite.b64' || return 1
  ed dual-client flock-client --config /var/lib/flock/client.toml invite /var/lib/flock/invite.b64 >/dev/null 2>&1 || return 1
  printf '%s\n' "$vip" | ed dual-client sh -c 'cat > /var/lib/flock/vip' || return 1
  printf 'W6-Client-Pw\nW6-Client-Pw\n' | ed dual-client \
      flock-client --config /var/lib/flock/client.toml login >/dev/null 2>&1 || return 1
  ed dual-client sh -c 'touch /var/lib/flock/ready' || return 1
  $DUAL --profile dual restart dual-client >/dev/null 2>&1 || return 1
  echo "  dual-client onboarded (vip=$vip)"
}

w6() {
  echo "== W6 dual-VIP data consistency (multi-primary Raft)"
  # Precondition probe: dual tier not up ⇒ PENDING (not a FAIL —— the
  # single-server topology is running).
  if ! $DUAL --profile dual ps --status running 2>/dev/null | grep -q "dual-b"; then
    pending "W6 dual-VIP data consistency (dual tier not up: docker compose -p flock-webui-dual -f deploy/webui.yml --profile dual up -d --build)"
    return 0
  fi
  w6_bootstrap || { bad "W6 dual bootstrap"; return; }
  # ① Both servers' tun ready + both VIPs reachable from the client (.2 via
  #    the cross-server FRWD path).
  local t=$((SECONDS + 120))
  until ed dual-client sh -c 'ip link show tun0' >/dev/null 2>&1; do
    [ $SECONDS -ge $t ] && { bad "W6 tun0"; return; }
    sleep 3
  done
  local vip
  for vip in 100.64.0.1 100.64.0.2; do
    t=$((SECONDS + 90)); local ok=""
    while [ $SECONDS -lt $t ]; do
      ed dual-client ping -c 1 -W 2 "$vip" >/dev/null 2>&1 && { ok=1; break; }
      sleep 3
    done
    [ -n "$ok" ] && echo "  ping $vip OK" || { bad "W6 ping $vip"; return; }
  done
  # ② Both VIPs' login pages reachable.
  for vip in 100.64.0.1 100.64.0.2; do
    local code
    code=$(ed dual-client curl -s -o /dev/null -w '%{http_code}' "http://$vip:9800/" 2>/dev/null)
    [ "$code" = "200" ] && echo "  curl http://$vip:9800/ 200 OK" || { bad "W6 login page $vip ($code)"; return; }
  done
  # ③ Log in on each VIP (cookies are isolated per host domain —— two
  #    independent logins).
  cp_webui_login "$DUAL --profile dual" dual-a dual-client || { bad "W6 webui_login copy"; return; }
  local WA WB
  WA="ed dual-client webui_login --base http://100.64.0.1:9800"
  WB="ed dual-client webui_login --base http://100.64.0.2:9800"
  $WA --user w6admin --pass W6Boss-Pw login | grep -q "login=ok" \
    && echo "  VIP .1 login OK" || { bad "W6 VIP .1 login"; return; }
  $WB --user w6admin --pass W6Boss-Pw login | grep -q "login=ok" \
    && echo "  VIP .2 login OK" || { bad "W6 VIP .2 login"; return; }
  # ④ /api/peers (device_id, vip, owner, status) sets strictly identical (the
  #    online/ewma tolerance faces stripped —— the §M8.9 W6 tier).
  local fa fb
  fa=$(mktemp); fb=$(mktemp)
  $WA --user w6admin --pass W6Boss-Pw peers 2>/dev/null | grep '^peers ' \
    | sed 's/ online=[a-z]*//' | sort > "$fa"
  $WB --user w6admin --pass W6Boss-Pw peers 2>/dev/null | grep '^peers ' \
    | sed 's/ online=[a-z]*//' | sort > "$fb"
  echo "  peers (.1):"; sed 's/^/    /' "$fa"
  if cmp -s "$fa" "$fb"; then
    echo "  peers sets identical OK"
  else
    echo "  peers diff (.1 vs .2):"; diff "$fa" "$fb" | sed 's/^/    /'
    bad "W6 peers consistency"; rm -f "$fa" "$fb"; return
  fi
  # ⑤ /api/users lists identical (after Raft convergence).
  $WA --user w6admin --pass W6Boss-Pw users 2>/dev/null | grep '^users ' | sort > "$fa"
  $WB --user w6admin --pass W6Boss-Pw users 2>/dev/null | grep '^users ' | sort > "$fb"
  if cmp -s "$fa" "$fb"; then
    echo "  users lists identical OK"
  else
    echo "  users diff:"; diff "$fa" "$fb" | sed 's/^/    /'
    bad "W6 users consistency"; rm -f "$fa" "$fb"; return
  fi
  # ⑥ /api/dashboard/summary data identical (sync_mode=raft, servers=2, totals
  #    aligned; epoch is the local applied view —— a display-tier concern, the
  #    output contains no epoch, naturally tolerant).
  local sa sb
  sa=$($WA --user w6admin --pass W6Boss-Pw summary 2>/dev/null)
  sb=$($WB --user w6admin --pass W6Boss-Pw summary 2>/dev/null)
  echo "  summary (.1): $sa"
  echo "  summary (.2): $sb"
  if [ "$sa" = "$sb" ] && printf '%s' "$sa" | grep -q 'sync_mode="raft"' \
     && printf '%s' "$sa" | grep -q 'servers=2'; then
    echo "  summary identical (raft/two servers/totals aligned) OK"
  else
    bad "W6 summary consistency"
  fi
  rm -f "$fa" "$fb"
  ok "W6 dual-VIP data consistency (multi-primary Raft)"
}

echo "=== M8 Web UI container assertions (full W1–W7) ==="
if ! wait_webui; then
  bad "webui ready (server-a 127.0.0.1:9800 bootstrap 200)"
  echo "PASS=$PASS FAIL=$FAIL"; exit 1
fi
ok "webui ready"
w1
w2
w3
w4
w5
w7
w6
echo "=== PASS=$PASS FAIL=$FAIL ==="
[ "$FAIL" = "0" ]
