# M5 e2e measured results (docs/design.md §6.3 A1–A16)

- Executed: from 2026-11-07 02:55:23; host = Windows + Docker Desktop 29.8.2 (WSL2); script deploy/e2e_assert.sh
- Topology: deploy/e2e.yml —— three isolated networks (flockpub 172.28.0.0/24 / srvmesh 172.29.0.0/24 / link-a·b one /29 each); frps-a/b = stock frp 0.71.1 + frpc-a/b sidecars; server-a/b/c = 3 voters (Frp/Frp/Direct mix, srvmesh server-server profile interconnect); client-1/2/3 pinned to frps-a:23000 / frps-b:23001 / 172.28.0.22:9443
- VIPs: server a/b/c = 100.64.0.1/100.64.0.2/100.64.0.3; client 1/2/3 = 100.64.0.11/100.64.0.17/100.64.0.13 (Raft-assigned, starting at .11)

| Result | Assertion | Notes |
|---|---|---|
| PASS|A1|Full 256-byte set + 1MiB random round-tripped via frps-a:23100 and frps-b:23101 echo, sha256 identical |
| PASS|A2|Same-server ping 100.64.0.1 and cross-server mutual pings (c1↔c2) all 3/3 0% loss |
| PASS|A3|tun0 mtu=1280; -s 1252 -M do passes (1252+28=1280) |
| PASS|A4|iperf3 sender = 577 Mbits/sec (≥ 100) |
| PASS|A5|Switched to frps-b:23001 in 6s (fresh handshake), ping 100.64.0.2 recovered, VIP unchanged (100.64.0.11), no I0 (no TOFU log on server-b) |
| PASS|A6|≤5s (measured within 1s): server-b session killed (apply callback), epoch advanced (server-b view 2→3), new handshakes rejected (no new connection in the 15s observation window) |
| PASS|A7-A2|After stopping a, same-server (c1→B, c3→C) and cross-server (c2↔c3 via B→C FRWD) all 0 loss |
| PASS|A7-A6|≤5s (measured within 1s): server-b session killed (apply callback), epoch advanced (server-c view 3→4), new handshakes rejected (no new connection in the 15s observation window) |
| PASS|A7|Re-election in 0s (≤15s, leader=node2); A2/A6 re-runs passed; server-a recovered and rejoined the cluster; client-1 back on the pinned endpoint |
| PASS|A8|100 streams × 60s × 4KiB bidirectional without error (hundred_streams_sixty_seconds_sustained really executed ok) |
| PASS|A9|Both sides detected dead-link in 25s and entered reconnect; after network recovery + re-pin, ping recovered (≤30s budget) |
| PASS|A10|300s under load, rekey 3 times (≥2); minimum per-second interval 290.29 Mbps (no >1s plateau) |
| PASS|A11|Relay byte volume zeros=4752000B ≈ random=4751000B (difference <5% ⇒ compression not enabled); compress unit tests (default off / non-expansion fallback) all green |
| PASS|A12|Replay reject + count (replayed_record_rejected_and_counted), forgery ≤N keeps link + 100 breaks it (both forge cases) re-run with real execution, passed |
| PASS|A13|172.28.0.20/.21:9443 both unreachable (the two Frp-form servers are not on flockpub —— topology validity) |
| PASS|A14|FRWD count 0→4; after the srvmesh cut cross-ping dead / same-server works, recovered after reconnect; forged src violations +20 and client-2 received nothing (capture-plane control valid) |
| PASS|A15|After migration 1s (≤35s) client-1→client-2 ping recovered; locate redirect count unchanged (lease event push ≤1s took effect before the stale window; the redirect path is covered by the flock-sync forward unit tests) |
| PASS|A16|Direct session (no I0, endpoint 172.28.0.22:9443); ping 100.64.0.3 and c1/c2↔c3 mutual pings 0 loss (Direct↔Frp cross-server isomorphic); server-c has no frp process, no sidecar |

PASS=18 FAIL=0

Footnotes (recorded as-is):
1. client-2's final VIP is above .12: the two revocations in A6/A7-A6 each
   consume one device identity (revocation is terminal, IPs are not reused);
   the script revives the channel via re-enroll with a "new device identity";
   the A15 migration assertion runs against the then-current VIP.
2. If A15's locate redirect count did not move: migration recovery (measured
   1s) is completed by the lease event push (≤1s) before the stale window
   takes effect —— recorded as-is when the NOT_HERE→location_query path was
   never triggered; that path is covered by the flock-sync tests/forward unit
   tests.
3. A8/A11/A12 are the design-designated unit-test re-run entries (A8:
   session_mux #[ignore] tier 100 streams×60s, really executed via --ignored
   —— the criterion requires the named test ok plus ≥1 passed, an empty run
   must not record PASS; A11: the compress tier; A12: replay/forge —— same
   criterion discipline as A8: every re-run must show the named test ok +
   ≥1 passed; an empty run / no filter match is a FAIL).
4. Three product defects exposed and fixed by the measured runs: redb vote
   codec asymmetry (tests/store_reopen regression); long-lived session lease
   evaporation (lease_refresh_loop TTL/3 renewal); interconnect global lock
   awaited across the network + no dialing budget (dial outside the lock +
   TcpFabric 3s budget).
5. link-a/b subnets are /29: a Docker bridge needs one address each for the
   gateway and broadcast; a /30 cannot hold the "gateway + sidecar + server"
   triple (isolation semantics unchanged).
