#!/usr/bin/env bash
# webui_assert.sh —— M8 Web UI 容器集成断言（docs/design.md §7-M8.9）。
#
#   docker compose -f deploy/webui.yml up -d --build
#   bash deploy/webui_assert.sh
#
# 本批（M8b）全量执行 W1–W7：W4（client VIP 可达 + 登录链）与 W6（双 VIP 数据
# 一致）为新增；W6 需 dual 档在跑（未起则 PENDING 输出、不判 FAIL）。
set -u
# 工作目录 = 仓库根（compose 文件路径 deploy/webui.yml 相对根解析）。
cd "$(dirname "$0")/.."
# Git Bash（MSYS）宿主：透传给 docker exec 的容器内绝对路径不做 POSIX→Windows
# 转换（Linux/macOS 宿主无此环境变量语义，空操作）。
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXEMPT='*'

COMPOSE="docker compose -f deploy/webui.yml"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL $1"; }
pending() { echo "PENDING $1"; }

# —— 就绪等待：server-a 的 webui loopback 面起响应（bootstrap 200）——
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
# W1 未登录：管理 API 全 401（server-a 容器内 curl 127.0.0.1:9800）
# =====================================================================
w1() {
  echo "== W1 未登录管理 API 全 401"
  local all=1
  for path in /api/me /api/peers /api/users /api/audit /api/dashboard/summary /api/config; do
    code=$($COMPOSE exec -T server-a curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:9800$path")
    body=$($COMPOSE exec -T server-a curl -s "http://127.0.0.1:9800$path")
    if [ "$code" = "401" ] && printf '%s' "$body" | grep -q '"not_logged_in"'; then
      echo "  401 $path OK"
    else
      echo "  401 $path FAIL（code=$code body=$body）"; all=0
    fi
  done
  for path in /api/logout /api/users; do
    code=$($COMPOSE exec -T server-a curl -s -o /dev/null -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' -H 'X-Flock-Web: 1' -d '{}' "http://127.0.0.1:9800$path")
    if [ "$code" = "401" ]; then echo "  401 POST $path OK"; else echo "  401 POST $path FAIL（$code）"; all=0; fi
  done
  [ "$all" = "1" ] && ok "W1 未登录全 401" || bad "W1 未登录 401 矩阵"
}

# =====================================================================
# W2 loopback 登录 → CRUD 全链（web-admin-add 管道喂口令 → webui_login 驱动）
# =====================================================================
w2() {
  echo "== W2 首 admin 引导 + CRUD 全链"
  # ① web-admin-add（服务在跑 ⇒ 经 admin 端点；管道喂两遍口令）。重跑容错：卷持久
  #    ⇒ 「已设置口令」拒答视为通过（口令即脚本常量，后续登录同值）。
  local add_out
  add_out=$(printf 'W2Boss-Pw\nW2Boss-Pw\n' | $COMPOSE exec -T server-a \
      flock-server --config /etc/flock/server.toml web-admin-add w2admin 2>&1)
  if echo "$add_out" | grep -q "web admin 就绪"; then
    echo "  web-admin-add w2admin OK"
  elif echo "$add_out" | grep -q "已设置口令"; then
    echo "  web-admin-add w2admin OK（重跑：口令已设）"
  else
    echo "$add_out" | sed 's/^/  /'; bad "W2 web-admin-add"; return
  fi
  local W B
  W="$COMPOSE exec -T server-a webui_login --base http://127.0.0.1:9800"
  B="--user w2admin --pass W2Boss-Pw"
  # ② 登录（anchor 验签）+ me。
  $W $B login | grep -q "login=ok" && echo "  login OK" || { bad "W2 login"; return; }
  $W $B me --expect-admin=1 | grep -q "admin=true" && echo "  me admin OK" || bad "W2 me"
  # ③ users 创建（令牌一次性）→ pw-set（原生 OPAQUE）→ 列表。重跑容错：user_exists
  #    ⇒ 已有口令（后续步骤用同一口令常量）。
  local token out
  out=$($W $B user-create w2bob)
  token=$(echo "$out" | sed -n 's/.*token=//p')
  if [ -n "$token" ]; then
    echo "  user-create w2bob OK"
    $W --user w2bob --token "$token" --pass W2Bob-Pw pw-set | grep -q "pw-set=w2bob ok" \
      && echo "  pw-set OK" || bad "W2 pw-set"
  elif echo "$out" | grep -q "user-create=w2bob"; then
    echo "  user-create w2bob OK（重跑：已存在）"
  else
    bad "W2 user-create（$out）"; return
  fi
  $W $B users | grep -q "users_count=2" && echo "  users 列表 OK" || bad "W2 users"
  # 禁用/重置/设 admin（重置后再把口令设回，供 W3 使用）。
  $W $B user-disable w2bob | grep -q "ok" && echo "  user-disable OK" || bad "W2 user-disable"
  $W $B user-enable w2bob | grep -q "ok" && echo "  user-enable OK" || bad "W2 user-enable"
  local nt
  nt=$($W $B user-reset-password w2bob | sed -n 's/.*token=//p')
  $W --user w2bob --token "$nt" --pass W2Bob-Pw2 pw-set | grep -q "ok" \
    && echo "  reset-password+pw-set OK" || bad "W2 reset-password"
  # 自降拒（409 → 退出码 42）。
  $W $B user-set-admin w2admin 0 >/dev/null; rc=$?
  [ "$rc" = "42" ] && echo "  cannot_demote_self(42) OK" || bad "W2 cannot_demote_self（rc=$rc）"
  # ④ 设备 fixture（admin 端点 device-add——TOFU 预置；固定 32B b64：x25519="A"*32、
  #    ed25519="B"*32）→ peers 列表/吊销/审计。
  local dev_hex
  dev_hex=$($COMPOSE exec -T server-a flock-server --config /etc/flock/server.toml     device-add --user w2bob     --device-x QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE     --device-ed QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI     2>/dev/null | sed -n 's/device_id=//p')
  # 幂等回退：已注册（重跑）⇒ 从 peers 列表取该设备（b64 fixture 的确定性 device_id）。
  if [ -z "$dev_hex" ]; then
    dev_hex=$($W $B peers | grep -v 'peers 100.64.0.1 ' | grep -o 'device_id=[0-9a-f]*' | head -1 | cut -d= -f2)
    [ -n "$dev_hex" ] && echo "  device fixture（peers 回取）= $dev_hex"
  fi
  if [ -n "$dev_hex" ]; then
    echo "  device-add fixture OK（$dev_hex）"
    $W $B peers | grep -q "peers_count=2" && echo "  peers 列表（server+device）OK" || bad "W2 peers"
    $W $B peer-op revoke "$dev_hex" | grep -q "ok epoch=" && echo "  peers 吊销 OK" || bad "W2 peers 吊销"
    $W $B audit-grep peer.revoke "$dev_hex" | grep -q 'action="peer.revoke"\|action=peer.revoke'       && echo "  audit 含 peer.revoke OK" || bad "W2 audit peer.revoke"
  else
    echo "  device-add fixture 不可用（跳过 peers 吊销子面）"; bad "W2 device-add fixture"
  fi
  # ⑤ dashboard/series。
  $W $B summary | grep -q "sync_mode=\"single\"" && echo "  summary OK" || bad "W2 summary"
  $W $B series --vip 100.64.0.1 | grep -q "series vip=100.64.0.1" && echo "  series OK" || bad "W2 series"
  # ⑥ audit 含对应行。
  $W $B audit-grep user.create w2bob | grep -q 'action="user.create"\|action=user.create' \
    && echo "  audit user.create OK" || bad "W2 audit user.create"
  $W $B audit-grep session.login w2admin | grep -q 'action="session.login"\|action=session.login' \
    && echo "  audit session.login OK" || bad "W2 audit session.login"
  # ⑦ logout 失效。
  $W --user w2bob --pass W2Bob-Pw2 logout | grep -q "sid-invalidated=true" \
    && echo "  logout OK" || bad "W2 logout"
  ok "W2 CRUD 全链（逐项见上）"
}

# =====================================================================
# W3 非 admin 账户：只读 200、users*/revoke/kick/audit 403
# =====================================================================
w3() {
  echo "== W3 非 admin 三态"
  local W
  W="$COMPOSE exec -T server-a webui_login --base http://127.0.0.1:9800"
  # W2 已建 w2bob（非 admin、口令 W2Bob-Pw2）。
  if ! $W --user w2bob --pass W2Bob-Pw2 login | grep -q "login=ok"; then
    bad "W3 前置（w2bob 登录）"; return
  fi
  $W --user w2bob --pass W2Bob-Pw2 me --expect-admin=0 | grep -q "admin=false" \
    && echo "  me admin=false OK" || bad "W3 me"
  local rc1 rc2
  $W --user w2bob --pass W2Bob-Pw2 probe-readonly >/dev/null; rc1=$?
  [ "$rc1" = "0" ] && echo "  只读端点全 200 OK" || bad "W3 只读 200（rc=$rc1）"
  $W --user w2bob --pass W2Bob-Pw2 probe-admin-denied >/dev/null; rc2=$?
  [ "$rc2" = "0" ] && echo "  管理端点全 403 OK" || bad "W3 管理 403（rc=$rc2）"
  [ "$rc1" = "0" ] && [ "$rc2" = "0" ] && ok "W3 非 admin 只读/403" || bad "W3 非 admin"
}

# =====================================================================
# W4 client-1（flock-client 网络命名空间）内 VIP:9800 登录页可达 + 登录链通
#     （VPN 段路径实证：peer → E2E 隧道 → server-a tun0 → VIP:9800）
# =====================================================================

# client-1 开户（单服面：device-add → invite → login → ready；幂等——ready 标记）。
w4_bootstrap_client() {
  if $COMPOSE exec -T client-1 sh -c 'test -f /var/lib/flock/ready' 2>/dev/null; then
    echo "  client-1 已就绪（幂等跳过）"
    return 0
  fi
  # 卷内配置（[auth] username——daemon 登录态与 login 子命令共用，m7 同法）。
  $COMPOSE exec -T client-1 sh -c 'printf "state_dir = \"/var/lib/flock\"\ntun_name = \"tun0\"\nmtu = 1280\n\n[auth]\nusername = \"w4client\"\n" > /var/lib/flock/client.toml' || return 1
  local keys dx de out vip
  keys=$($COMPOSE exec -T client-1 flock-client --config /var/lib/flock/client.toml gen-keys 2>/dev/null) || return 1
  dx=$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')
  de=$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')
  [ -n "$dx" ] && [ -n "$de" ] || { echo "  gen-keys 输出异常"; return 1; }
  out=$($COMPOSE exec -T server-a flock-server --config /etc/flock/server.toml \
      device-add --user w4client --device-x "$dx" --device-ed "$de" 2>&1) || { echo "  device-add 失败：$out"; return 1; }
  vip=$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')
  case "$vip" in 100.64.*) ;; *) echo "  VIP 异常：$out"; return 1;; esac
  $COMPOSE exec -T server-a flock-server --config /etc/flock/server.toml \
      invite --ttl-secs 86400 2>/dev/null | $COMPOSE exec -T client-1 sh -c 'cat > /var/lib/flock/invite.b64' || return 1
  $COMPOSE exec -T client-1 flock-client --config /var/lib/flock/client.toml \
      invite /var/lib/flock/invite.b64 >/dev/null 2>&1 || return 1
  printf '%s\n' "$vip" | $COMPOSE exec -T client-1 sh -c 'cat > /var/lib/flock/vip' || return 1
  printf 'W4-Client-Pw\nW4-Client-Pw\n' | $COMPOSE exec -T client-1 \
      flock-client --config /var/lib/flock/client.toml login >/dev/null 2>&1 || return 1
  $COMPOSE exec -T client-1 sh -c 'touch /var/lib/flock/ready' || return 1
  $COMPOSE restart client-1 >/dev/null 2>&1 || return 1
  echo "  client-1 开户完成（vip=$vip）"
}

# 把 webui_login 从 server 容器拷进 client 容器（镜外二进制、经宿主中转）。
cp_webui_login() { # cp_webui_login <src-service> <dst-service>
  local tmp
  tmp=$(mktemp)
  [ -n "$(command -v cygpath)" ] && tmp=$(cygpath -w "$tmp")
  $COMPOSE cp "$1:/usr/local/bin/webui_login" "$tmp" >/dev/null 2>&1 || return 1
  $COMPOSE cp "$tmp" "$2:/usr/local/bin/webui_login" >/dev/null 2>&1 || return 1
  $COMPOSE exec -T "$2" chmod +x /usr/local/bin/webui_login || return 1
  rm -f "$tmp"
}

w4() {
  echo "== W4 client VIP:9800 可达 + 登录链（VPN 段路径）"
  # ① client-1 起服（tun 就绪 + ping 通 server-a VIP）。
  w4_bootstrap_client || { bad "W4 client 开户"; return; }
  local t=$((SECONDS + 90))
  until $COMPOSE exec -T client-1 sh -c 'ip link show tun0' >/dev/null 2>&1; do
    [ $SECONDS -ge $t ] && { bad "W4 tun0 90s 未创建"; return; }
    sleep 3
  done
  t=$((SECONDS + 90)); local ok=""
  while [ $SECONDS -lt $t ]; do
    $COMPOSE exec -T client-1 ping -c 1 -W 2 100.64.0.1 >/dev/null 2>&1 && { ok=1; break; }
    sleep 3
  done
  [ -n "$ok" ] && echo "  ping 100.64.0.1 OK" || { bad "W4 ping VIP"; return; }
  # ② curl 登录页可达（VPN 段内 GET /）。
  local code body
  code=$($COMPOSE exec -T client-1 curl -s -o /dev/null -w '%{http_code}' http://100.64.0.1:9800/ 2>/dev/null)
  body=$($COMPOSE exec -T client-1 curl -s http://100.64.0.1:9800/ 2>/dev/null | head -c 400)
  if [ "$code" = "200" ] && printf '%s' "$body" | grep -q "flockApp"; then
    echo "  curl VIP:9800 登录页 200 OK"
  else
    bad "W4 登录页可达（code=$code）"; return
  fi
  # ③ 登录链通（webui_login 载具指向 VIP 端点；W2 的 w2admin）。
  cp_webui_login server-a client-1 || { bad "W4 webui_login 拷载"; return; }
  local WV
  WV="$COMPOSE exec -T client-1 webui_login --base http://100.64.0.1:9800"
  $WV --user w2admin --pass W2Boss-Pw login | grep -q "login=ok" \
    && echo "  VIP 登录链 login=ok OK" || { bad "W4 VIP 登录"; return; }
  # ④ origin=vpn（VPN 段会话定档）+ 只读面 + peers 含服务器行。
  $WV --user w2admin --pass W2Boss-Pw me 2>/dev/null | grep -q "origin=vpn" \
    && echo "  me origin=vpn OK" || bad "W4 origin=vpn"
  $WV --user w2admin --pass W2Boss-Pw probe-readonly >/dev/null \
    && echo "  只读面（VIP base）全 200 OK" || bad "W4 只读面"
  $WV --user w2admin --pass W2Boss-Pw peers 2>/dev/null | grep -q "peers 100.64.0.1 " \
    && echo "  peers 含服务器行 OK" || bad "W4 peers"
  ok "W4 client VIP 可达 + 登录链（VPN 段路径）"
}

# =====================================================================
# W5 client-1 内 curl server-a 的 flockpub/LAN 地址 :9800 不可达（连接层证明）
# =====================================================================
w5() {
  echo "== W5 LAN 地址 :9800 连接层不可达"
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
    ok "W5 LAN :9800 不可达（未绑定面）"
  else
    bad "W5 LAN :9800 可达（绑定泄漏！）"
  fi
}

# =====================================================================
# W7 配置校验：端口冲突拒起服 + 配置面不存在 bind 键（白名单键集）
# =====================================================================
w7() {
  echo "== W7 配置校验"
  # ① [webui] port=9443（与 bind 冲突）⇒ 拒起服（validate 面先于绑定）。
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
  if echo "$out" | grep -q "冲突" && echo "$out" | grep -q "exit=2"; then
    echo "  端口冲突拒起服 OK"
  else
    bad "W7 端口冲突"
  fi
  # ② [webui] 出现 bind 键 ⇒ 解析层拒（deny_unknown_fields——结构防误配）。
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
    echo "  webui 键集白名单（bind 拒）OK"
  else
    bad "W7 白名单键"
  fi
  ok "W7 配置校验"
}

# =====================================================================
# W6 双 server VIP（100.64.0.1 / 100.64.0.2）均可访问且数据一致（同集群）
#     前置：docker compose -p flock-webui-dual -f deploy/webui.yml \
#             --profile dual up -d --build
#     未起 dual 档 ⇒ PENDING（单服拓扑运行不判 FAIL）。
# =====================================================================
DUAL="docker compose -p flock-webui-dual -f deploy/webui.yml"
ed()  { $DUAL --profile dual exec -T "$@"; }

# dual 集群幂等引导：init-cluster（operator）→ 双 enroll → cluster-bootstrap →
# 双服 stats 就绪 → 首 admin → client 入网（device-add + cluster-invite + login）。
w6_bootstrap() {
  # ① mat 就绪（operator 的 init-cluster 幂等产物）。
  local t=$((SECONDS + 120))
  until ed dual-a sh -c 'test -f /mat/root.seed' 2>/dev/null; do
    [ $SECONDS -ge $t ] && { echo "  /mat/root.seed 120s 未就绪"; return 1; }
    sleep 3
  done
  echo "  mat 就绪（root.seed 在位）"
  # ② 双 enroll（幂等：bundle.bin 已在即跳过）。
  local s b i=0
  for s in dual-a dual-b; do
    if ed "$s" sh -c 'test -f /var/lib/flock/bundle.bin' 2>/dev/null; then
      echo "  $s 已 enroll（幂等跳过）"
    else
      ed "$s" flock-server --config /etc/flock/server.toml enroll --bundle "/mat/node-$i.bundle" \
        || { echo "  $s enroll 失败"; return 1; }
    fi
    i=$((i+1))
  done
  # ③ cluster-bootstrap（经 dual-a；幂等；Raft 起服窗口重试）。
  t=$((SECONDS + 240))
  until ed dual-a flock-server --config /etc/flock/server.toml \
        cluster-bootstrap --root-seed /mat/root.seed 2>&1 | tee /tmp/w6-boot.txt | grep -q 'cluster-bootstrap ok\|幂等'; do
    if [ $SECONDS -ge $t ]; then echo "  cluster-bootstrap 240s 未成功"; cat /tmp/w6-boot.txt; return 1; fi
    sleep 5
  done
  echo "  cluster-bootstrap OK"
  # ④ 双服 stats 就绪（Bootstrap/SetOprf 已 apply + admin 已起）。
  t=$((SECONDS + 180)); local ok=""
  while [ -z "$ok" ]; do
    ok=1
    for s in dual-a dual-b; do
      ed "$s" flock-server --config /etc/flock/server.toml stats 2>/dev/null | grep -q '^epoch=' || ok=""
    done
    [ -n "$ok" ] && break
    [ $SECONDS -ge $t ] && { echo "  双服 stats 未齐（180s）"; return 1; }
    sleep 3
  done
  echo "  双服 stats 就绪"
  # ⑤ 首 admin（dual-a loopback admin 面；幂等——已设口令同值视为通过）。
  local add
  add=$(printf 'W6Boss-Pw\nW6Boss-Pw\n' | ed dual-a flock-server --config /etc/flock/server.toml web-admin-add w6admin 2>&1)
  if echo "$add" | grep -q "web admin 就绪" || echo "$add" | grep -q "已设置口令"; then
    echo "  web-admin-add w6admin OK"
  else
    echo "$add" | sed 's/^/  /'; return 1
  fi
  # ⑥ dual-client 入网（Raft 面：device-add + 根签 cluster-invite + login；幂等）。
  if ed dual-client sh -c 'test -f /var/lib/flock/ready' 2>/dev/null; then
    echo "  dual-client 已就绪（幂等跳过）"
    return 0
  fi
  ed dual-client sh -c 'printf "state_dir = \"/var/lib/flock\"\ntun_name = \"tun0\"\nmtu = 1280\n\n[auth]\nusername = \"w6client\"\n" > /var/lib/flock/client.toml' || return 1
  local keys dx de out vip inv
  keys=$(ed dual-client flock-client --config /var/lib/flock/client.toml gen-keys 2>/dev/null) || return 1
  dx=$(printf '%s\n' "$keys" | sed -n 's/^device-x=//p')
  de=$(printf '%s\n' "$keys" | sed -n 's/^device-ed=//p')
  out=$(ed dual-a flock-server --config /etc/flock/server.toml \
      device-add --user w6client --device-x "$dx" --device-ed "$de" 2>&1) || { echo "  device-add 失败：$out"; return 1; }
  vip=$(printf '%s\n' "$out" | sed -n 's/^vip=//p' | tr -d '\r')
  case "$vip" in 100.64.*) ;; *) echo "  VIP 异常：$out"; return 1;; esac
  inv=$(ed dual-a flock-server --config /etc/flock/server.toml \
      cluster-invite --root-seed /mat/root.seed --bundle /mat/node-0.bundle --ttl-secs 86400 2>/dev/null | tail -1) \
    || { echo "  cluster-invite 失败"; return 1; }
  printf '%s' "$inv" | ed dual-client sh -c 'cat > /var/lib/flock/invite.b64' || return 1
  ed dual-client flock-client --config /var/lib/flock/client.toml invite /var/lib/flock/invite.b64 >/dev/null 2>&1 || return 1
  printf '%s\n' "$vip" | ed dual-client sh -c 'cat > /var/lib/flock/vip' || return 1
  printf 'W6-Client-Pw\nW6-Client-Pw\n' | ed dual-client \
      flock-client --config /var/lib/flock/client.toml login >/dev/null 2>&1 || return 1
  ed dual-client sh -c 'touch /var/lib/flock/ready' || return 1
  $DUAL --profile dual restart dual-client >/dev/null 2>&1 || return 1
  echo "  dual-client 入网完成（vip=$vip）"
}

w6() {
  echo "== W6 双 VIP 数据一致（多主 Raft）"
  # 前置检测：dual 档未起 ⇒ PENDING（非 FAIL——单服拓扑运行面）。
  if ! $DUAL --profile dual ps --status running 2>/dev/null | grep -q "dual-b"; then
    pending "W6 双 VIP 数据一致（dual 档未起：docker compose -p flock-webui-dual -f deploy/webui.yml --profile dual up -d --build）"
    return 0
  fi
  w6_bootstrap || { bad "W6 dual 引导"; return; }
  # ① 双服 tun 就绪 + 双 VIP 从 client 皆可达（.2 经跨服 FRWD 路径）。
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
  # ② 双 VIP 登录页可达。
  for vip in 100.64.0.1 100.64.0.2; do
    local code
    code=$(ed dual-client curl -s -o /dev/null -w '%{http_code}' "http://$vip:9800/" 2>/dev/null)
    [ "$code" = "200" ] && echo "  curl http://$vip:9800/ 200 OK" || { bad "W6 登录页 $vip（$code）"; return; }
  done
  # ③ 双 VIP 各自登录（cookie 按 host 域隔离——各自独立登录）。
  cp_webui_login dual-a dual-client || { bad "W6 webui_login 拷载"; return; }
  local WA WB
  WA="ed dual-client webui_login --base http://100.64.0.1:9800"
  WB="ed dual-client webui_login --base http://100.64.0.2:9800"
  $WA --user w6admin --pass W6Boss-Pw login | grep -q "login=ok" \
    && echo "  VIP .1 登录 OK" || { bad "W6 VIP .1 登录"; return; }
  $WB --user w6admin --pass W6Boss-Pw login | grep -q "login=ok" \
    && echo "  VIP .2 登录 OK" || { bad "W6 VIP .2 登录"; return; }
  # ④ /api/peers (device_id, vip, owner, status) 集合严格一致（online/ewma 容差面
  #    剥离——§M8.9 W6 档位）。
  local fa fb
  fa=$(mktemp); fb=$(mktemp)
  $WA --user w6admin --pass W6Boss-Pw peers 2>/dev/null | grep '^peers ' \
    | sed 's/ online=[a-z]*//' | sort > "$fa"
  $WB --user w6admin --pass W6Boss-Pw peers 2>/dev/null | grep '^peers ' \
    | sed 's/ online=[a-z]*//' | sort > "$fb"
  echo "  peers（.1）:"; sed 's/^/    /' "$fa"
  if cmp -s "$fa" "$fb"; then
    echo "  peers 集合一致 OK"
  else
    echo "  peers 差异（.1 vs .2）:"; diff "$fa" "$fb" | sed 's/^/    /'
    bad "W6 peers 一致性"; rm -f "$fa" "$fb"; return
  fi
  # ⑤ /api/users 列表一致（Raft 收敛后）。
  $WA --user w6admin --pass W6Boss-Pw users 2>/dev/null | grep '^users ' | sort > "$fa"
  $WB --user w6admin --pass W6Boss-Pw users 2>/dev/null | grep '^users ' | sort > "$fb"
  if cmp -s "$fa" "$fb"; then
    echo "  users 列表一致 OK"
  else
    echo "  users 差异:"; diff "$fa" "$fb" | sed 's/^/    /'
    bad "W6 users 一致性"; rm -f "$fa" "$fb"; return
  fi
  # ⑥ /api/dashboard/summary 数据一致（sync_mode=raft、servers=2、totals 对齐；
  #    epoch 为本机已 apply 视图——展示面档位，输出不含 epoch，天然容差）。
  local sa sb
  sa=$($WA --user w6admin --pass W6Boss-Pw summary 2>/dev/null)
  sb=$($WB --user w6admin --pass W6Boss-Pw summary 2>/dev/null)
  echo "  summary（.1）: $sa"
  echo "  summary（.2）: $sb"
  if [ "$sa" = "$sb" ] && printf '%s' "$sa" | grep -q 'sync_mode=raft' \
     && printf '%s' "$sa" | grep -q 'servers=2'; then
    echo "  summary 一致（raft/双服/totals 对齐）OK"
  else
    bad "W6 summary 一致性"
  fi
  rm -f "$fa" "$fb"
  ok "W6 双 VIP 数据一致（多主 Raft）"
}

echo "=== M8 Web UI 容器断言（W1–W7 全量）==="
if ! wait_webui; then
  bad "webui 就绪（server-a 127.0.0.1:9800 bootstrap 200）"
  echo "PASS=$PASS FAIL=$FAIL"; exit 1
fi
ok "webui 就绪"
w1
w2
w3
w4
w5
w7
w6
echo "=== PASS=$PASS FAIL=$FAIL ==="
[ "$FAIL" = "0" ]
