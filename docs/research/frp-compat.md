# FRP compatibility research (original fatedier/frp vs ChmlFrp)

- Research date: 2026-10-31 (conclusions as of today)
- Method: line-by-line reading of upstream source (fatedier/frp dev branch HEAD `93b5279`,
  2026-10-23, with `pkg/util/version/version.go` identifying 0.71.1; plus spot checks across the
  v0.46.0–v0.71.1 tags), source diff of the ChmlFrp modified repository (TechCat-Team/ChmlFrp-Frp
  @ `9899607`), gofrp.org official docs, chmlfrp.net official site/docs, live testing of
  ChmlFrp's public API, and hands-on frp tunnel pass-through experiments on this machine.
- Conventions: claims marked [proven] have a primary source (source line numbers / experiment
  commands and outputs / official doc URLs); claims marked [inferred] state their basis;
  anything unfindable goes into "open questions" at the end.
- Source shorthand: `frp-src/` = the local clone of the upstream repository (`.tmp/frp-src`, dev @
  93b5279); `chml/` = the local clone of the ChmlFrp-Frp repository (`.tmp/chmlfrp-frp`); `golib`
  = fatedier/golib v0.8.2 (the version pinned by upstream's go.mod).

---

## 0. Executive summary

1. **The data plane is pure pass-through** [proven]: with tcp proxies and
   `useEncryption=false, useCompression=false`, frps/frpc make zero modifications and add zero
   framing to the user byte stream, just bidirectional `io.Copy` over 16 KiB blocks; in the local
   v0.71.1 experiment, a round trip containing all 256 byte values, a `0x17` first byte, and 1
   MiB of random data came back sha256-identical. ChmlVPN's application-layer end-to-end
   encryption protocol can traverse the frp relay unmodified.
2. **But there are two traps that must be avoided** [proven]: ① TCP half-close (`SHUT_WR`) is not
   preserved — either direction closing tears down the whole chain; measured return path 0/65536
   bytes; ② frps applies a first-byte TLS probe (0x16/0x17) on the **frpc entry connection**
   (bindPort) but none on the **proxy user port** — the application-layer protocol must never
   appear on the frpc entry side (that side is frp's own), only on the proxy user-port side;
   measured: no constraint there.
3. **Original and ChmlFrp are two mutually incompatible generations of control-plane protocol**
   [proven]: the ChmlFrp client/node is modified from original **v0.51.2** (2023-07), with no
   control-plane token encryption; original v0.53.0 (2023-12) onward **mandates** AES-128-CFB
   (key derived from the token) on the control connection after login, so ChmlFrp frpc ↔ original
   frps ≥v0.53.0 are incompatible in both directions; v0.69.0 (2026-05) further introduced the
   optional wire protocol v2 (framing + negotiated AEAD), with v1 still the default and the
   official plan to remove v1 in v0.78.0. **The only robust path compatible with both is
   subprocess supervision of two frpc binaries**.
4. **Recommended option A (subprocess supervision)**: lowest risk, zero protocol-drift cost,
   ample empirical support; ChmlFrp's frpc has a modification that "exits the process after
   three reconnect failures", so the supervision layer must do process supervision + restart.
   Option B (a native Rust implementation) would require maintaining both generations
   simultaneously — the unencrypted v0.51.2 control plane and the encrypted v0.53+ control plane
   — while hitting the v1→v2 transition; the drift risk is high; not recommended now. Option C
   (visitor/xtcp) is unavailable on ChmlFrp (the panel cannot create stcp/xtcp + the server-side
   CheckProxy validation).

---

## 1. Original frp (v0.71.1, released 2026-10-14) protocol essentials

Version facts: the GitHub Releases API shows `v0.71.1 / 2026-10-14`; dev HEAD `93b5279`
(2026-10-23) has `pkg/util/version/version.go` = `"0.71.1"`. License Apache-2.0
(`frp-src/LICENSE`).

### 1.1 Architecture and connection model [proven, frp-src source]

- frps listens on `bindPort` (default 7000, `frp-src/pkg/config/v1/server.go:113`); frpc dials
  out; no hole-punching needed on the frpc side.
- **One control connection**: TCP (or kcp/quic/websocket/wss; `frp-src/pkg/config/v1/client.go:152`
  default tcp) → TLS (on by default) → **yamux multiplexing** (`transport.tcpMux` default true,
  `client.go:159`; `frp-src/client/connector.go:142-162` builds the session with
  `fatedier/yamux`, `MaxStreamWindowSize=6MiB`, KeepAlive default 30s). The control connection
  and all work conns are yamux streams on this one TCP.
- Login: `Login{version,user,privilege_key,timestamp,run_id,pool_count,metas}`
  (`frp-src/pkg/msg/msg.go:76-93`) → `LoginResp{version,run_id,error}`. `PrivilegeKey =
  GetAuthKey(token, timestamp)` (HMAC, `frp-src/pkg/auth/token.go:40`).
- **Proxy model**: frpc sends `NewProxy` (type/remote port/bandwidth limit etc., `msg.go:102-134`)
  → frps listens on the user port → when a user connection arrives, frps sends `ReqWorkConn`
  over the control connection → frpc opens a new yamux stream sending
  `NewWorkConn{run_id,privilege_key}` → frps replies
  `StartWorkConn{proxy_name,src/dst addr/port}` → both sides `Join`
  (`frp-src/client/control.go:124-162`, `frp-src/server/proxy/proxy.go:270-342`).
- **Visitor model** (stcp/sudp/xtcp): both ends run frpc. The visitor side connects to frps
  sending `NewVisitorConn{run_id,proxy_name,sign_key,timestamp,use_encryption,use_compression}`
  (`msg.go:163-170`), `sign_key = GetAuthKey(secret_key, ts)`
  (`frp-src/client/visitor/visitor.go:165-201`); frps validates and then bridges the visitor
  connection with the proxy side's work conn. **A visitor is not a general "connect to any frps
  port" mechanism; it can only reach stcp/sudp/xtcp proxies registered by the peer frpc**.
- Heartbeat: with tcpMux on, the application-layer heartbeat is disabled by default
  (interval=-1), relying on yamux keepalive 30s; with tcpMux off, send every 30s / timeout at 90s
  (`frp-src/pkg/config/v1/client.go:158-164`).
- Reconnection: the frpc side uses FastBackoff (1s start, exponential ×2, cap =
  heartbeatInterval, `frp-src/client/control.go:256-265`); the server disconnects after a 90s
  heartbeat timeout. On reconnect the old `run_id` is carried (`client/control_session.go:117`),
  and frps replaces the old session (v0.70.1 fixed a session-replacement leak under half-open
  TCP mux; see the v0.70.1 release notes).

### 1.2 Message wire formats [proven]

| Generation | Frame format | Status |
|---|---|---|
| v1 (since v0.46.0) | `1 type byte ('o','1','p',…) + 8-byte big-endian int64 length + JSON payload`; single-message cap 10240 bytes (frp does not override golib's default) | **default**; planned for removal in v0.78.0 |
| v2 (since v0.69.0, optional) | magic `FRP\x00\x02\r\n` + 8-byte frame header (2B type / 2B flags=0 / 4B len, payload ≤ 64 KiB) + ClientHello/ServerHello capability-negotiation frames + message frames (2B type ID + JSON) | enabled only when frpc explicitly sets `transport.wireProtocol="v2"` |

Sources: v1 codec `frp-src/pkg/msg/ctl.go:17-44` delegates to golib `msg/json` (pack.go/
process.go: Write one typeByte + `binary.Write(BigEndian, int64)` + JSON;
`defaultMaxMsgLength=10240`); v2 `frp-src/pkg/msg/wire_v2.go:27-47`,
`frp-src/pkg/proto/wire/wire.go:28-167`; v1/v2 selection `frp-src/pkg/msg/handler.go:79-90`; the
server recognizes v2 by the first 7 magic bytes, otherwise falls back to v1
(`frp-src/server/service.go:645-674`). The v1 default and the deprecation timetable come from
the official v0.69.0 release notes.

### 1.3 Control-plane security evolution (this project's most critical version divide) [proven]

| Version | Date | Change | Source |
|---|---|---|---|
| ≤ v0.52.x | ≤2023-10 | control connection plaintext (optional TLS the only protection) | v0.52.3 source has no ConnEncrypted (git grep on the local tag) |
| **v0.53.0** | 2023-12-14 | **after login, both sides unconditionally encrypt the control connection with AES-128-CFB using a key derived from auth.token** (except ssh-tunnel VirtualClient); key = PBKDF2-SHA1(token, salt="frp", 64 iters), IV prefixed | v0.53.0 `server/control.go:161-193` (`NewControl(..., !internal, ...)`), `client/control.go:90-97`; current `frp-src/server/service.go:548-553,688-702`, `frp-src/client/control_session.go:211-225`; algorithm golib `crypto/encode.go`/`decode.go`, salt in `client/service.go` init `crypto.DefaultSalt="frp"` |
| v0.61.0 | 2024-10-17 | (the lower anchor of the compatibility window) | v0.69.0 release notes |
| **v0.69.0** | 2026-05-21 | optional wire v2: framing + negotiated AEAD (`xchacha20-poly1305`/`aes-256-gcm`, derived via HKDF(token, bidirectional Hello transcript)); v1 remains default; **official compatibility policy: each minor is supported until the 9th minor after it (frpc v0.69.0 ↔ frps v0.61.0–v0.77.0); upgrade frps first, then frpc** | v0.69.0 release notes; `frp-src/pkg/proto/wire/wire.go:169-251`, `frp-src/pkg/util/net/conn.go:260-303` |

Corollary (a hard constraint for ChmlVPN): **ChmlFrp frpc (v0.51.2 baseline, no control-plane
encryption) and original frps ≥v0.53.0 are mutually incompatible; original frpc ≥v0.53.0 and
ChmlFrp nodes (which don't decrypt) are likewise incompatible**. Mixing the two generations is
guaranteed to break — the root reason "dual-FRP compatibility" must use two client binaries (or
a native implementation of both protocol generations).

### 1.4 Exact behavior of useEncryption / useCompression / TLS [proven]

**All are per-proxy, effective only on the frpc↔frps work conn, unrelated to user-connection
content:**

- `useEncryption`: both ends of the work conn each wrap an AES-128-CFB stream (same algorithm as
  §1.3, key=token). Client `frp-src/client/proxy/proxy.go:144-151` (`libio.WithEncryption`),
  server `frp-src/server/proxy/proxy.go:297-304`. **Default false**.
- `useCompression`: snappy stream compression (`golang/snappy`; golib `io.go:21,78-95`
  `WithCompressionFromPool`). **It is snappy, not gzip** — frp has never offered a gzip option
  (a whole-repo grep finds gzip only in the HTTP scenario of `pkg/util/net/http.go`).
  **Default false**.
- With both false (ChmlVPN's usage), the work conn is a bare TCP/yamux stream;
  `wrapWorkConn` returns it as-is (`frp-src/client/proxy/proxy.go:137-157`), and the server's
  `local` is just the workConn (`server/proxy/proxy.go:294-312`).
- TLS (between frpc↔frps): since v0.50.0, `tls.enable=true` by default and the custom first byte
  is **not** sent by default (`DisableCustomTLSFirstByte` default true, i.e. a standard TLS
  ClientHello 0x16), `frp-src/pkg/config/v1/client.go:186-200`. On frps, the bindPort entry
  reads the first byte: 0x17→custom-prefix TLS, 0x16→standard TLS, anything else→non-TLS pass-
  through (with `tls.force=true`, non-TLS is rejected) (`frp-src/pkg/util/net/tls.go:22-54`).
  **TLS covers only the frpc↔frps leg; the proxy user port and the local service never get
  TLS**.
- The bandwidth limit `bandwidthLimit` (in client mode, effective on the client side by
  default), the server's maxPoolCount=5, etc. do not change byte semantics
  (`frp-src/pkg/config/v1/server.go` transport section; gofrp.org server-configures reference).

### 1.5 Data plane: buffering, timeouts, sticky packets, half-close [proven (source + local
experiments)]

Data path: `userConn ⇄ frps(Join) ⇄ workConn(yamux stream) ⇄ frpc(Join) ⇄ localConn`. The Join
implementation (golib `io.go:28-52`): two goroutines each hold a **16 KiB** buffer and
`io.CopyBuffer`; **EOF or error in either direction closes both**. The proxy user port is
accepted directly by `net.Listen` (`frp-src/server/proxy/tcp.go:49-81`), with **no first-byte
probing and no protocol parsing whatsoever** (contrast the frpc entry
`server/service.go:766-797`, which has the TLS probe).

Local experiments (2026-10-31, Windows, self-built frps/frpc from dev sources — the officially
downloaded exe was blocked from executing by local security policy; the self-built `--version`
prints `0.71.1`, matching the release; topology `python echo(127.0.0.1:18099) ← frpc →
frps(7000) → user port 18100`, no encryption no compression, token=`chmlvpn-research-test`):

| # | Experiment | Result | Conclusion |
|---|---|---|---|
| T1 | transmit `bytes(range(256))×64 + 1 MiB random` (first byte 0x00), echoed back, compare sha256 | **PASS** (1,064,960 bytes, hashes identical) | the full binary character set passes through, zero tampering |
| T2 | 10 13-byte chunks starting with `0x17` sent one by one; read the reply | **PASS** (60 bytes bit-for-bit identical) | no first-byte interference at the user port; no framing; TCP sticky-packet/coalescing transparent |
| T3 | send 64 KiB then `shutdown(SHUT_WR)`, read the echo | **FAIL: return path 0/65536 bytes** | **half-close not preserved**: EOF in one direction closes the whole chain; all in-flight return data lost |
| T4 | 10 MiB round trip, timed | 0.06 s ≈ **166.7 MiB/s** (loopback-magnitude reference) | no application-layer bottleneck on a single stream |

Timeout and keepalive facts: login read timeout 10 s (`frp-src/server/service.go:65`
connReadTimeout); `userConnTimeout` default 10 s (waiting for frpc to answer StartWorkConn);
**the data plane has no idle timeout** (Join has no read deadline); the underlying TCP keepalive
defaults to 7200 s (`frp-src/pkg/config/v1/client.go:153 DialServerKeepAlive`).

**Direct constraints on ChmlVPN's protocol layer**:
1. Relying on TCP half-close to express "this direction is done sending" is forbidden — an
   application-layer length prefix or an explicit EOF frame must be used;
2. Long idle connections are not actively dropped by frp, but **node restarts/frpc exit/NAT
   timeouts all hard-drop the TCP**; the protocol layer must carry its own heartbeat + make
   sessions recoverable (re-handshake after reconnecting);
3. Single-stream throughput is affected by the yamux window (6 MiB) and RTT; in high-latency
   cross-node scenarios, avoid handshake designs that depend on "many small messages in serial
   round trips";
4. The first byte of the application-layer encrypted stream may be anything (0x16/0x17 both
   safe; only the frpc entry direction has probe semantics, the user port has no constraint,
   proven by T2).

### 1.6 yamux / tcpmux are two different things [proven]

- `transport.tcpMux` (default true) = **yamux multiplexing** on the single frpc↔frps TCP
  connection (the `fatedier/yamux` fork); the control connection and all work conns are streams;
  turned off, each connection gets its own TCP.
- The `tcpmux` **proxy type** = frps routing, on a single listening port, by the HTTP `CONNECT`
  host to different proxies (sole multiplexer: `httpconnect`; the `tcpmuxPassthrough` option
  passes the CONNECT header through) (gofrp.org/docs/features/tcpmux; `frp-src/pkg/config/types`,
  `frp-src/server/proxy/tcpmux.go`). Unrelated to yamux; usually useless in ChmlVPN.

### 1.7 visitor / xtcp (P2P) capabilities [proven]

- xtcp: both ends' frpc + frps coordinate (NatHoleVisitor/Client/Resp/Sid/Report messages over
  the control connection, `msg.go:192-247`); the client discovers its public mapping via STUN
  (default server `stun.easyvoip.com:3478`, `frp-src/pkg/config/v1/client.go:90`); on a
  successful punch-through they connect directly (default QUIC, optional kcp,
  `frp-src/client/visitor/xtcp.go:55-60` + `pkg/config/v1/visitor.go:160`); on failure it can
  `fallbackTo` an stcp visitor (timeout configurable, gofrp.org/docs/features/xtcp). **The
  official word: availability/stability not guaranteed**.
- stcp: secret tcp; both ends' frpc + frps relay; `secretKey` authentication; suitable when both
  ends are controllable (gofrp.org/docs/examples/stcp).

### 1.8 frpc CLI (original v0.71.1) [proven, `frp-src/pkg/config/flags.go:150-172`]

`-c/--config` (config file, default `./frpc.ini`), `-u/--user` (a **username prefix**, not an
auth token), `-p/--protocol` (tcp/kcp/quic/websocket/wss), `-P` (server_port), `-t/--token`
(the auth token). **The original has no "`-u <token> -p <tunnel-id>`" semantics — that is a
ChmlFrp modification (see §2.2)**.

---

## 2. ChmlFrp (chmlfrp.cn → chmlfrp.net)

### 2.1 Identity and current state (measured 2026-10-31) [proven]

| Item | Fact | Source |
|---|---|---|
| Website | `www.chmlfrp.cn` 301 → `www.chmlfrp.net` ("ChmlFrp Panel Version 3.x.x") | live curl + site footer |
| Panel / docs / API | `panel.chmlfrp.net` (download page HTTP 200) / `docs.chmlfrp.net` / `cf-v1/v2.uapis.cn` | live curl |
| Source | GitHub org `TechCat-Team`: `ChmlFrp-Frp` (client/server, Go), `ChmlFrp-Panel-v3`, `ChmlFrp-Docs`, `ChmlFrpLauncher` (a graphical launcher), etc. | live GitHub API |
| Client essence | **modified from fatedier/frp v0.51.2**: `pkg/util/version/version.go` = `"ChmlFrp-0.51.2_251023"`; the README self-describes as "based on the open-source project frp on github"; Apache-2.0 retained | `chml/pkg/util/version/version.go:22` |
| Download source | official direct link `https://cf-v1.uapis.cn/download/ChmlFrp-0.51.2_251023_<os>_<arch>.tar.gz` (download verified, 12 MB, containing frpc+frps+ini samples+LICENSE); the panel `panel.chmlfrp.net/tunnel/download`; supports amd64/386/arm/arm64/mips family/riscv64 | verified download + the official docs download page |
| Plans | free 8 Mbps rate cap / 4 tunnels / unlimited traffic; membership 8–12–18 CNY/month up to 32 Mbps / 16 tunnels | the site's pricing section |
| Nodes measured | `GET https://cf-v2.uapis.cn/node` (no login needed): **all 32 nodes online**; 16 user-group + 16 vip-group; 31 allow UDP; **only 1 supports quic**; fields include area/china (rate-cap attribution)/fangyu/ipv6/web/notes | live curl 2026-10-31 (node.json archived under `.tmp/chmlfrpc/`) |

### 2.2 The usertoken / tunnel-ID model (showroom's bootstrap) [proven, modified source]

The real semantics of `frpc -u <usertoken> -p <tunnel-id>` (`chml/cmd/frpc/sub/root.go:92-93,
133-174`):

- `-u` = `--token` ("The Token of ChmlFrp", the panel user's **usertoken**, not an frp token);
- `-p` = `--id` ("The ProxyID of ChmlFrp", the **numeric tunnel ID**; comma-separated for
  several);
- startup flow: `GET https://cf-v2.uapis.cn/cfg?action=getcfg&token=<usertoken>&id=<ids>`
  (**InsecureSkipVerify HTTPS**, `chml/pkg/api/api.go:30-46`) → the panel returns the full
  **frpc.ini text** for those tunnels of that user (`{success,message,cfg}`) → overwrite the
  local `frpc.ini` → start via the original v0.51.2 flow. API live test: a wrong token returns
  HTTP 400 `{"success":false,"message":"<panel message: invalid user token>","status":400}` (the
  panel's own message text is Chinese; translated here).
- Without `-u/-p`, the local `frpc.ini` is read directly (the path the official docs push: panel
  "Tunnel Management → Config File", pick a node, generate, paste into frpc.ini).
- The panel v2 API also has the formal `/tunnel_config` (token+node+tunnel_names → ini text) and
  the `/node` node list (docs.chmlfrp.net/API/v2).

### 2.3 Differences from original (the fork's diff against v0.51.2, `git diff v0.51.2 HEAD`)
[proven]

| Difference | Content | Impact |
|---|---|---|
| CLI bootstrap | the `-u/-p` above → the API pulls the config (root.go + the new 331-line `pkg/api`) | ChmlVPN's supervision layer can reuse that API directly or use the `-c` config-file mode |
| **Reconnect behavior** | a login failure **exits directly with `os.Exit(1)`**; after the control connection drops it retries at **5s/10s/20s three times, then exits the process** (the original does unbounded exponential backoff, cap 20s) | **the supervision layer must watch for process exit and restart it**; "multi-primary active-active" failover is ChmlVPN's own job |
| Server auth | frps login calls the panel API `CheckToken(user, privilege_key, ts)`; usernames must match `^[A-Za-z0-9]{1,64}$` (server/service.go diff) | the usertoken never enters the frp protocol directly; the panel issues short-lived keys |
| **Proxy allowlist** | `NewProxy` must pass the panel's `CheckProxy` comparison against the record; any mismatch is rejected ("client proxy parameters wrong; config file does not match the record" — the official FAQ corroborates; log sample user=`token-6e447a2e28fdb4d0`, proxy name `<user>.<name>`) | **ChmlVPN cannot invent its own proxy parameters on a ChmlFrp node** (type/port/name are panel-generated); the E2E protocol can only live inside the tunnel payload |
| **Server-side rate limiting** | the panel's `GetProxyLimit` delivers in/out KB/s; frps wraps the work conn with `limit.NewLimitConn` (server/control.go diff) | plan rate caps of 8–32 Mbps are enforced at the node |
| Other | localized logs, the `cs.json` node-status export (CPU/memory/bandwidth), UDP proxy logging-only changes | no protocol impact |

**The protocol layer is untouched**: `pkg/msg` (the JSON v1 codec) is fully identical to
original v0.51.2 [proven; the diff does not touch it]. v0.51.2 traits: JSON v1 messages (already
so since v0.46.0), **no control-plane token encryption** (introduced only in v0.53.0), INI
config, no ClientID field (introduced in v0.67.0).

### 2.4 STUN/P2P capability [inferred (from the negative evidence of verified material)]

- The official docs (a full crawl of docs.chmlfrp.net) contain **no xtcp/stcp/visitor/P2P
  content whatsoever**; the panel's tunnel creation offers only TCP/UDP/HTTP/HTTPS (the official
  tutorial pages); the node API has no xtcp-related fields.
- The fork's source retains the original xtcp code, but the server-side `CheckProxy` accepts
  only panel records → **stcp/xtcp tunnels the panel cannot create are effectively unusable**.
  The cs.json sample contains `bind_udp_port=7001` (a fork-repo file), mainly serving kcp port
  reuse.
- Conclusion: **ChmlFrp provides TCP/UDP/HTTP/HTTPS relaying only, no P2P**. ChmlVPN's P2P
  evolution can rely only on self-hosted nodes (original xtcp) or homegrown hole-punching.

### 2.5 Docs and download-source status [proven]

- The docs site is active (docs.chmlfrp.net, VitePress; the ChmlFrp-Docs repo last pushed
  2026-08-26; Panel-v3 still updated 2026-10-30); the v1 API docs carry a "deprecated soon,
  migrate to v2" notice.
- The download direct link (cf-v1.uapis.cn) and the panel download page both work; the graphical
  client ChmlFrpLauncher (Win/macOS/Linux) is the pushed path.
- The client version is **stuck at the frp v0.51.2 baseline** (the fork repo's last commit
  2025-10-25, package name `_251023`) — **three years without following upstream**; neither
  v0.53+ control-plane encryption nor v0.69+ wire v2 exists.

---

## 3. Integration options compared and recommended

| Dimension | A: subprocess-supervised frpc (showroom's status quo) | B: native Rust implementation of the frp client protocol | C: frp visitor / xtcp mode |
|---|---|---|---|
| Dual-FRP compatibility | ✅ just bundle two binaries (ChmlFrp frpc to ChmlFrp nodes; original frpc ≥v0.61 to self-hosted nodes), each version pinned | ⚠️ must implement both control-plane generations simultaneously (v0.51.2 unencrypted + v0.53+ AES-CFB; future v2 AEAD), and must reverse-align the ChmlFrp server's CheckProxy semantics (proxy name `<user>.<name>`, parameters matching the panel record) | ❌ unavailable on ChmlFrp nodes (no panel stcp/xtcp + CheckProxy rejection); usable on self-hosted nodes but requires both ends to run frpc |
| Protocol-drift risk | none (an upstream upgrade just swaps the binary) | **high**: the v1→v2 transition (v1 to be removed in v0.78.0); historical precedent: the v0.49 xtcp rework was incompatible; ChmlFrp's modifications do not follow upstream | medium (xtcp behavior shifts across versions; v0.49 broke it once) |
| Workload | low: process supervision + config generation + log watching | high: yamux (or disable tcpMux for multi-TCP) + TLS + JSON v1 codec + AES-CFB + login/heartbeat/work-conn state machines + an error matrix; dual-version branching | medium (orchestrating frpc on both ends + fallback logic) |
| Licensing | Apache-2.0 binary distribution compliant (keep LICENSE/NOTICE) | a clean-room protocol re-implementation has no copyright issue; porting the Go code would make it a derivative work needing Apache-2.0 compliance | same as A |
| Performance | one extra process per instance (measured frps+frpc loopback 166 MiB/s, not a bottleneck); the data plane is equivalent to B (both are userspace copies) | a single binary, no extra-hop feel, can do zero-copy/fine-grained flow control | genuinely P2P after a successful punch (optimal); falls back to relay on failure |
| Controllability | logs/status via the child's stdout and probing; the ChmlFrp frpc's exit-after-3-reconnects needs supervision | fully controllable (reconnect/multi-active/traffic scheduling programmable) | managed automatically by frp; a black box |
| For ChmlVPN's "multi-primary active-active" | one frpc instance per server attached to its own relay node, clients access any — naturally orthogonal to application-layer active-active | same, plus in-protocol node speed-testing and switching possible | a visitor can only reach registered peer proxies — misaligned with the "any server equivalent" goal |

**Recommendation: A (subprocess supervision) as the primary path, with dual frpc variants
(ChmlFrp frpc pinned at v0.51.2 + original frpc pinned); B listed as long-term evolution; C not
adopted.**

Rationale:
1. §1.3 proved the two control-plane generations mutually incompatible; A is the only path
   "compatible with both at zero protocol-maintenance cost"; B carries bidirectional drift risk
   in the v1→v2 transition and must additionally align with ChmlFrp's modified auth/naming
   rules — the cost/benefit ratio is at its worst right now.
2. Every known shortcoming of A has an engineering fix: process supervision (ChmlFrp frpc exit
   → restart + exponential backoff), health probing (local tunnel port + the frpc admin API),
   config generation (ChmlFrp: the panel `/tunnel_config` or the `-u/-p` bootstrap; original:
   TOML templates).
3. C's core value (P2P relay-free bandwidth) maps directly onto ChmlVPN's "8–32 Mbps node rate
   cap" pain point, but it is unavailable on ChmlFrp; it can go on the long-term roadmap as an
   **optional acceleration layer on self-hosted nodes** (original xtcp + fallback stcp); the
   main path does not use it.

---

## 4. Requirements checklist for a protocol layer "compatible with original FRP and ChmlFrp"
(testable)

Each item below can be written as an automated acceptance case. Items already proven on original
v0.71.1 are ✅ (experiment reproduction commands in §1.5 and `.tmp/frp-test/`):

| # | Requirement | Verification | Status |
|---|---|---|---|
| R1 | **byte pass-through**: any binary (including first bytes 0x00/0xFF/0x16/0x17, all 256 byte values) crosses either relay with unchanged sha256 | echo 1 MiB random + `bytes(range(256))×64` back through the tunnel and compare hashes | ✅ original v0.71.1 (T1/T2); ChmlFrp real node to be tested (see open questions) |
| R2 | **no framing / sticky-packet transparency**: byte streams agree across arbitrary segmented writes and coalesced reads; the relay injects no delimiters/heartbeat bytes | 10×13 B segmented writes → one 130 B read, compare; then the reverse (one big write, small segmented reads) | ✅ original (T2) |
| R3 | **half-close semantics banned**: the protocol must not rely on `SHUT_WR`; one-directional end expressed by an explicit EOF frame or length prefix | unit tests asserting the protocol state machine never calls shutdown(write); integration tests simulating "send then await reply" without depending on FIN | ✅ risk proven (T3: return path 0/65536); design constraint in force |
| R4 | **free first byte**: the first byte of the E2E encrypted stream's first frame may be any value (not avoiding 0x16/0x17) | handshake packets with first bytes 0x00/0x16/0x17 respectively cross the tunnel; 100% handshake success | ✅ proven on the original user port (T2 used an 0x17 first block); note the frpc↔frps entry side is frp's own protocol, where the application layer never appears |
| R5 | **idle resilience**: a connection with ≥10 minutes of zero traffic is not actively dropped by the relay (the data plane has no idle timeout), but an application-layer heartbeat is still needed against NAT/node restarts | idle-connection timer + heartbeat on/off two-state tests; assert idle survival and, with the heartbeat unplugged, link-failure detection within heartbeatTimeout | ⏳ design item (source-proven no idle timeout: Join has no deadline) |
| R6 | **disconnect/reconnect consistency**: after any restart of the relay/frpc/node, the TCP presents a hard drop to ChmlVPN — the session layer must recover after reconnecting (new TCP) with a handshake result equivalent to pre-drop; on ChmlFrp nodes, also cover "frpc exits after 3 reconnects and is restarted by the supervisor" | three scenarios — kill frpc / restart frps / 60s network cut — asserting: recovery time, session-key renegotiation, no stuck streams | ⏳ (ChmlFrp's exit-on-reconnect behavior proven: §2.3) |
| R7 | **throughput consistency**: through "original node vs ChmlFrp node" to the same peer, throughput should differ only by the node rate cap (ChmlFrp 8–32 Mbps server-enforced) and RTT; the protocol layer's own overhead <10% | timed 10 MiB transfers, normalized comparison; a ChmlFrp free node should converge to ~8 Mbps | ⏳ (the original loopback 166.7 MiB/s baseline measured) |
| R8 | **dual-stack bootstrap**: the same ChmlVPN binary can be launched both as "usertoken+tunnel-id → cfg API → INI → ChmlFrp frpc" and as "TOML → original frpc"; both config generators have independent unit tests | golden-file tests for both generators; recorded response samples for the cfg API (the wrong-token 400 behavior already live-tested) | ⏳ |
| R9 | **version matrix lock**: ChmlFrp node ⇔ ChmlFrp frpc (v0.51.2); self-hosted original node ⇔ original frpc (same minor generation as frps, per the official 9-minor window); crossing forbidden. The version pairs are fixed in CI | matrix smoke: run R1 once per each of the 4 combinations; assert only the diagonal succeeds | ⏳ (the mechanism of cross failure source-proven: §1.3) |
| R10 | **UDP semantics**: over a UDP tunnel, frp wraps UDP in UDPPacket messages over TCP/yamux (`udpPacketSize` default 1500, both ends must match, gofrp.org server reference); the VPN's UDP carriage must be designed as "best effort, possibly reordered/lost" and the UDP switch confirmed on ChmlFrp nodes (31/32 nodes allow) | UDP-tunnel loss/reorder injection tests + node-field assertions | ⏳ |
| R11 | **multi-instance isolation**: one frpc instance per tunnel (or config_dir multi-instance); the ChmlFrp free plan's 4-tunnel cap ⇒ ChmlVPN's server exposure model is designed as "one tcp tunnel per node carrying all VPN traffic (the protocol layer multiplexes on its own)", not relying on multiple tunnels | multi-session concurrency stress on a single tunnel (≥100 concurrent streams) | ⏳ design item |
| R12 | **compliance red line**: never tamper with the panel-generated proxy parameters (CheckProxy would reject); HTTP mappings on mainland nodes need an ICP-registered domain — ChmlVPN uses only tcp-type tunnels to avoid this | config-generator assertions that the output matches the panel sample field for field (golden comparison) | ⏳ |

---

## 5. Open questions (gaps)

1. **No live end-to-end test on a real ChmlFrp node**: it needs a real-name-registered
   usertoken + tunnel ID (this research registered no account). All §2 conclusions rest on the
   modified repo's line-by-line diff + live public-API tests + the official docs — high
   confidence — but the final acceptance of R1/R6/R7 on ChmlFrp nodes still awaits an account.
2. **The frps version running on ChmlFrp nodes**: inferred to be the frps of the ChmlFrp-Frp
   repo (basis: the repo description, the frps-side modifications mapping one-to-one onto panel
   behavior, the cs.json status export matching the panel node fields, and the release package
   containing frps); no official architecture document directly confirms it.
3. **The concrete default field values of panel-generated frpc.ini** (user/token/tls_enable
   etc.) were not obtained (needs a panel login); from FAQ logs, `user = token-<hash>` and proxy
   name `<user>.<name>` are inferred.
4. **The official frp Windows binary was blocked from executing on this machine** by security
   policy (the "the volume containing the file has been externally changed" error; reproduced
   across re-downloads and paths); the experiments were done with self-built binaries of the
   same version from source (`--version` prints 0.71.1 in both cases). Distributing frpc.exe to
   user machines will need antivirus false-positive and allowlisting/signing assessment.
5. **wire v2 has no formal protocol spec**: the current basis is the v0.69.0/v0.70.x release
   notes and the source; the v1 removal date (v0.78.0) is the official current plan and may
   shift. If ChmlFrp upgrades its baseline or upstream flips v2 to default, the §1.3 version
   matrix here needs re-checking.
6. **xtcp's unavailability on ChmlFrp is inferred** (negative evidence: docs/panel/API all lack
   the capability + the CheckProxy mechanism), not live-tested (with nowhere to create an xtcp
   tunnel there is nothing to test).

---

## Appendix: outputs of this research

- Upstream source clone: `.tmp/frp-src` (dev @ 93b5279, with the v0.46.0–v0.71.1 tags for
  archaeology)
- ChmlFrp modified-repo clone: `.tmp/chmlfrp-frp` (main @ 9899607; the v0.51.2 tag fetched and
  diffed)
- ChmlFrp official release package: `.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/`
- Pass-through experiments: `.tmp/frp-test/` (frps.toml/frpc.toml/echo_server2.py/
  passthrough_test.py/halfclose_detail.py; self-built frps.exe/frpc.exe from source)
- Node-list snapshot: `.tmp/chmlfrpc/node.json` (2026-10-31, 32 nodes)
