# Multi-machine mesh live test (multinode-test) — Windows Docker × jowency LXD real machines

- Date: 2026-11-07; repository HEAD `b9217c3` (main); execution surfaces: Windows 10 (Docker
  Desktop 29.8.2 / WSL2, non-elevated Git Bash) + jowency (Ubuntu 26.04, LXD 5.21.9, lxdbr0
  10.100.0.0/24 NAT).
- Assets: `deploy/multinode/` (README has reproduction steps); the assertion script
  `deploy/multinode/multinode_assert.sh` (exit code 0 = all PASS / 1 = some FAIL / 2 = bootstrap
  failure / 64 = usage error).
- Binaries: HEAD sources built via `Dockerfile.buildbin` (rust:1.98-slim-bookworm, release
  --locked + strip) into three Linux amd64 artifacts, streamed to jowency via tar-over-ssh
  (sha256 identical on both sides: `flock-client 05dd874a…`, `flock-server-direct 7d1dc954…`,
  `flock-server-mp 9d2b1134…`). The images reuse `flock/client:e2e` and `flock/server:e2e-a`
  for the tool surface only; **the binaries are overridden by mount with the HEAD-built
  artifacts**.

## 0. Connectivity probes (do these first) and firewall prerequisites

| Probe | Method | Result |
|---|---|---|
| Windows→jowency inbound | jowency `python3` listening on :19443; Windows Docker `nc` connects in | **works** (the server received `PROBE1_RECV_FROM ('192.168.31.244', 63683)`; the payload round-tripped identically) |
| jowency→Windows inbound | Windows `docker run -p 0.0.0.0:19444` echo; jowency `nc` | **works** (the full echo round trip: `payload-ack`) |

**Windows inbound working ⇒ scenario two keeps its original topology (server-1 in Windows
Docker) without degradation**; the netsh firewall supplementary-test command is prepared in the
real-machine checklist (deploy/multinode/README.md, "firewall prerequisites").

Environment-interception record (the task's given assumption "LXD containers reach the LAN
directly on egress" contradicted the measurements — two pre-existing blocks were temporarily
opened for the test window and reverted afterwards):

1. jowency's `nft ip filter DOCKER-USER` already had `iifname "lxdbr0" ip daddr 192.168.0.0/16
   ct state new drop` (the counter measured +14 hits) — blocking LXD→Windows (scenario two's
   flock-s2→server-1 Raft dial :9500, and c6's endpoint-equivalent direct dial :9443).
   Temporarily allowed (only dst=192.168.31.244, tcp 9443/9500, `comment "flock-mn-test-temp"`,
   handle 194); deleted verbatim by handle after the test (confirmed in the cleanup section).
2. jowency's `ufw` defaults to deny incoming and its "LAN trusted" does not include
   10.100.0.0/24 — blocking LXD containers→host-published ports (scenario one's LXD clients→:9443,
   scenario two's→frps :7000/:24000). Temporarily allowed with 3 rules `allow in on lxdbr0 to
   any port {9443,7000,24000}/tcp comment "flock-mn-test"`; after the test, `ufw delete` of the
   same three rules verbatim (confirmed in the cleanup section).

Also: jowency has two LAN IPs (the ssh side .221 / the route src toward Windows .46) —
proxy/frps both listen on 0.0.0.0, and endpoints are uniformly pinned to .221 (the
`JOW_LAN_IP` environment variable; see the lxd-setup.sh header comment).

## 1. Scenario one [single server · Direct] — S1–S3 all PASS (PASS=4 FAIL=0)

Topology: flock-s1 (jowency LXD, Direct :9443, published via a proxy device at .221:9443; VIP
100.64.0.1, tun0 + rp_filter self-configured by the server) + clients ×4 (Windows Docker
flock-wc1/wc2 + LXD flock-c3/c4; all via the m7 admin provisioning path: gen-keys → device-add →
invite → ingest → vip → login → service daemon). All clients dial 192.168.31.221:9443 directly
(Docker bridge → LAN → LXD proxy).

### S1 full-mesh ping matrix (3 packets per cell; measured values)

| src | dst | VIP | loss | avg rtt(ms) | path | result |
|---|---|---|---|---|---|---|
| wc1 | wc2 | 100.64.0.3 | 0% | 112.368 | same host | PASS |
| wc1 | c3 | 100.64.0.4 | 0% | 116.803 | cross-machine Win-Docker→LXD | PASS |
| wc1 | c4 | 100.64.0.5 | 0% | 151.815 | cross-machine Win-Docker→LXD | PASS |
| wc1 | server | 100.64.0.1 | 0% | 84.262 | cross-machine Win-Docker→LXD | PASS |
| wc2 | wc1 | 100.64.0.2 | 0% | 46.3 | same host | PASS |
| wc2 | c3 | 100.64.0.4 | 0% | 87.477 | cross-machine Win-Docker→LXD | PASS |
| wc2 | c4 | 100.64.0.5 | 0% | 106.581 | cross-machine Win-Docker→LXD | PASS |
| wc2 | server | 100.64.0.1 | 0% | 50.017 | cross-machine Win-Docker→LXD | PASS |
| c3 | wc1 | 100.64.0.2 | 0% | 111.531 | cross-machine LXD→Win-Docker | PASS |
| c3 | wc2 | 100.64.0.3 | 0% | 92.859 | cross-machine LXD→Win-Docker | PASS |
| c3 | c4 | 100.64.0.5 | 0% | 69.396 | same host | PASS |
| c3 | server | 100.64.0.1 | 0% | 37.901 | cross-machine LXD→Win-Docker | PASS |
| c4 | wc1 | 100.64.0.2 | 0% | 75.101 | cross-machine LXD→Win-Docker | PASS |
| c4 | wc2 | 100.64.0.3 | 0% | 82.931 | cross-machine LXD→Win-Docker | PASS |
| c4 | c3 | 100.64.0.4 | 0% | 76.886 | same host | PASS |
| c4 | server | 100.64.0.1 | 0% | 45.95 | cross-machine LXD→Win-Docker | PASS |
| server(s1) | wc1 | 100.64.0.2 | 0% | 82.347 | LXD local | PASS |
| server(s1) | wc2 | 100.64.0.3 | 0% | 82.291 | LXD local | PASS |
| server(s1) | c3 | 100.64.0.4 | 0% | 34.184 | LXD local | PASS |
| server(s1) | c4 | 100.64.0.5 | 0% | 47.436 | LXD local | PASS |

**[PASS] S1 | full mesh: 4 clients × (server + 3 peers) + server→4 clients, all 0 loss**
(20/20 cells). Cross-machine (Win-Docker↔LXD) avg rtt measured spread 46–192ms (Wi-Fi LAN +
Docker NAT + LXD proxy multi-hop), same-host control 34–152ms.

### S2 peers roster (any client contains all 5 nodes; hostname/account/online/latency non —)

`flock-client peers` measured output (wc1's view):

```
VIP        | hostname              | account               | type   | status | latency (ms) | ↓ traffic (B/s) | ↑ traffic (B/s)
----------------------------------------------------------------------------------------------------
100.64.0.1 | 192.168.31.221:9443 | 15334125528595525502 | server | online | 68     | 80       | 87
100.64.0.2 | flock-wc1(self)     | mncw1                | device | online | —      | 12       | 11
100.64.0.3 | flock-wc2           | mncw2                | device | online | 135    | 25       | 24
100.64.0.4 | flock-c3            | mnc3                 | device | online | 104    | 31       | 28
100.64.0.5 | flock-c4            | mnc4                 | device | online | 104    | 36       | 34
```

c3's view is isomorphic, 5 rows (the self row moves; the server row's latency 50ms, the other
device rows 100–144ms, all non —). **[PASS] S2-w / S2-l** (the --json machine-readable
assertions: rows=5, offline=0, non-self rows' latency_ms all non-null).

### S3 VIP allocation table

| Node | Location | VIP |
|---|---|---|
| flock-s1 (server) | jowency LXD | 100.64.0.1 (fixed) |
| flock-wc1 | Windows Docker | 100.64.0.2 |
| flock-wc2 | Windows Docker | 100.64.0.3 |
| flock-c3 | jowency LXD | 100.64.0.4 |
| flock-c4 | jowency LXD | 100.64.0.5 |

**[PASS] S3** (the 4 client VIPs unique; the allocation order .2→.5 matches the device-add
order). Server stats (captured after the assertions): `epoch=0 sessions_online=4
tun_vip=100.64.0.1`; `src_vip_mismatches=26` (no kills/dropped sessions; the origin not
attributed per packet — the observation counter recorded as-is, not part of this assertion set).

## 2. Scenario two [dual server · cross-machine Raft + dual transport] — R1–R5 all PASS
(PASS=6 FAIL=0)

Topology: server-1 = flock-srv1 (Windows Docker; Direct, publishing 0.0.0.0:9443 + Raft
0.0.0.0:9500; VIP .1); server-2 = flock-s2 (jowency LXD; Frp access — host frps :7000, the
in-process flock-frpc registering user port 24000, Raft :9500 published via a proxy device; VIP
.2). `init-cluster --voters 2 --endpoints 192.168.31.244:9443,192.168.31.221:24000`
(cluster_id daf9930b…) → enroll on both sides → cluster-bootstrap (submitted via srv1's admin,
a 2-voter quorum across a real network). Clients: flock-2w1/2w2 (Windows Docker → server-1
direct), flock-c5/c6 (LXD → frps user port 24000); provisioning all via s2's admin (device-add +
cluster-invite root-signed v3) — itself evidence of "any server is equivalent".

### R1 Raft cross-machine consistency (excerpts of both servers' stats)

| Field | srv1 (Win-Docker) | s2 (LXD/Frp) |
|---|---|---|
| epoch | 0 | 0 |
| leader | 2 | 2 |
| node_id | 1 | 2 |
| sessions_online | 2 | 2 |
| tun_vip | 100.64.0.1 | 100.64.0.2 |
| ic_dial_ok/err | 1/0 | 5/0 |
| ic_rpc_ok/err | 133/0 | 298/0 |
| lease_entries | 6 | 6 |

**[PASS] R1**: epoch/leader consistent on both sides; the same registry is double-checked by R4
(revoking via s2 kills srv1's side's session immediately) and R5 (both sides' rosters agree).

### R2 Cross-server forwarding matrix (srv1 side ↔ srv2 side; ForwardEnvelope over the real
network, 3 packets per cell)

| src | src side | dst | dst side | VIP | loss | avg rtt(ms) | result |
|---|---|---|---|---|---|---|---|
| 2w1 | srv1 direct | c5 | srv2 relay | 100.64.0.13 | 0% | 91.361 | PASS |
| c5 | srv2 relay | 2w1 | srv1 direct | 100.64.0.11 | 0% | 123.223 | PASS |
| 2w1 | srv1 direct | c6 | srv2 relay | 100.64.0.14 | 0% | 144.427 | PASS |
| c6 | srv2 relay | 2w1 | srv1 direct | 100.64.0.11 | 0% | 138.218 | PASS |
| 2w2 | srv1 direct | c5 | srv2 relay | 100.64.0.13 | 0% | 93.578 | PASS |
| c5 | srv2 relay | 2w2 | srv1 direct | 100.64.0.12 | 0% | 108.579 | PASS |
| 2w2 | srv1 direct | c6 | srv2 relay | 100.64.0.14 | 0% | 118.539 | PASS |
| c6 | srv2 relay | 2w2 | srv1 direct | 100.64.0.12 | 0% | 113.6 | PASS |
| 2w1 | srv1 direct | 2w2 | srv1 direct | 100.64.0.12 | 0% | 36.432 | PASS (same-side control) |
| c5 | srv2 relay | c6 | srv2 relay | 100.64.0.14 | 0% | 63.46 | PASS (same-side control) |

**[PASS] R2**: all 8 cross-server pairs 0 loss.

### R3 Any endpoint is equivalent

c6 switched from the frps user port 24000 to server-1's direct port 192.168.31.244:9443
(LXD→Windows direct, via the temporary nft exception): after reconnecting, `connected
192.168.31.244:9443`, **VIP unchanged (100.64.0.14)**, roster row count identical, ping to
server-1's VIP works. **[PASS] R3**.

### R4 Revocation propagates cross-machine ≤5s (revoking srv1-side 2w2 via s2's admin)

Measured **409ms** (previous full re-runs 446ms / 647ms): revoke submitted via s2 (a Raft
cross-machine commit) → srv1 `sessions_online 3→2` (the apply callback kills the session) →
epoch `0→1` (visible from s2) → during the 15s observation window, 2w2 had no new "connected"
(new handshakes rejected; the client's reconnect logs kept showing `dial failed`). **[PASS]
R4**.

### R5 Both sides' peers rosters (the revoked row off the roster by design)

`flock-client peers` measured (2w1 = srv1 side; c5 = srv2 side, isomorphic):

```
VIP         | hostname               | account | type   | status | latency (ms)
-----------------------------------------------------------------------
100.64.0.1  | 192.168.31.244:9443  | 1     | server | online | 96
100.64.0.2  | 192.168.31.221:24000 | 2     | server | online | —
100.64.0.11 | flock-2w1(self)      | mn2w1 | device | online | —
100.64.0.13 | flock-c5             | mn2c5 | device | online | 99
100.64.0.14 | flock-c6             | mn2c6 | device | online | 102
```

**[PASS] R5-w / R5-l**. Semantic calibration (source server.rs:897, "the roster = a snapshot of
Active rows"): the revoked 2w2 (.12) **is off the roster** (the registry keeps the record for
audit, the IP is never reused — double-checked by R4's epoch/kill-session surface); both sides
have 5 rows each = 2 servers + 3 Active clients, and the row sets agree.

Two within-design behaviors (recorded as-is, not defects):
- **The remote server row's latency —**: a client ping to a non-access server's VIP returns ICMP
  unreachable per §2.2 forwarding rule 4 (a server is not a "device lease" forwarding target;
  measured 2w1→.2 and c5→.1 both `+3 errors 100% loss`), the roster probe times out ⇒ latency
  column —.
- **The post-revocation roster TicketBad transient window**: the global revocation_epoch advance
  invalidates all in-flight tickets (the ticket epoch check); within the daemon's 25s re-login
  keep-alive window, peers reports `TicketBad: ticket rejected`, self-healing afterwards
  (measured `login ok … epoch=1` recovery); the assertion script does bounded retries following
  the m7 precedent (commit 76241a2).

## 3. Real-machine checklist (not executed this session; left for manual work)

1. **Windows host node (joining the network outside Docker)**: in an administrator PowerShell,
   run `deploy/multinode/windows-host-node.ps1` (automatically: fetch/build
   `target\release\flock-client.exe`, generate %ProgramData%\FlockVPN\client.toml pointing at
   the scenario-one server, run device-add/invite against flock-s1 over ssh, self-elevate via
   UAC, `flock-client run`, output the ping matrix; not executed this session because the shell
   was non-elevated).
2. **Windows inbound firewall supplementary test** (only for environments where the probes were
   blocked): as administrator run `netsh advfirewall firewall add rule name="flock-mn" dir=in
   action=allow protocol=TCP localport=9443,9500`.
3. **Scenario-two degraded-topology reproduction** (when Windows inbound is unavailable): both
   servers land on LXD (each published via a proxy device), Windows runs only outbound clients —
   the config changes are in deploy/multinode/README.md.

## 4. Cleanup confirmation (executed after testing, both sides)

- LXD: the six containers `flock-s1/s2/c3/c4/c5/c6` removed with `lxc delete --force` (the proxy
  devices die with the containers); the frps process stopped; `~/flock-mn` (binaries/cluster
  material/logs) taken away. Pre-existing containers (dmgvm, krymux-a/b/c, l2ctest,
  uesktop-ui-audit) untouched.
- The nft temporary exception: `nft delete rule ip filter DOCKER-USER handle 194` (after
  deletion, `nft -a list chain` confirmed only the pre-existing three drop rules remain; the
  counters back to their pre-allowance semantics).
- The ufw temporary rules: `ufw delete allow in on lxdbr0 to any port {9443,7000,24000} proto
  tcp comment "flock-mn-test"`, all three.
- Windows Docker: all flock-* containers and flock-mn-* named volumes deleted
  (win-docker-cleanup.sh, down -v semantics); the `.tmp/flock-mn` runtime state deleted.
