#!/usr/bin/env bash
# webui_assert.sh —— M8 Web UI 容器集成断言（docs/design.md §7-M8.9）。
#
#   docker compose -f deploy/webui.yml up -d --build
#   bash deploy/webui_assert.sh
#
# 本批（M8a）执行 W1/W2/W3/W5/W7；W4（client VIP 可达 + 登录链）与 W6（双 VIP
# 数据一致）留 M8b 全链（前端 wasm 装配后）——断言位以 PENDING 占位输出。
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
pending() { echo "PENDING $1（M8b）"; }

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

echo "=== M8 Web UI 容器断言（W1/W2/W3/W5/W7；W4/W6 为 M8b）==="
if ! wait_webui; then
  bad "webui 就绪（server-a 127.0.0.1:9800 bootstrap 200）"
  echo "PASS=$PASS FAIL=$FAIL"; exit 1
fi
ok "webui 就绪"
w1
w2
w3
w5
w7
pending "W4 client VIP 可达 + 登录链（VPN 段路径）"
pending "W6 双 VIP 数据一致（多主）"
echo "=== PASS=$PASS FAIL=$FAIL ==="
[ "$FAIL" = "0" ]
