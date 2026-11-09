# deploy/multinode —— real multi-machine networking test (Windows local Docker × remote jowency LXD)

Results and evidence: `docs/manual/multinode-test.md` (measured 2026-11-07, HEAD
b9217c3).
The topology paradigm reuses the existing `deploy/` assets (the Direct form of
`Dockerfile.server-direct`, the init-cluster/enroll/cluster-bootstrap bootstrap
of `e2e.yml/e2e_assert.sh`, and the device-add→invite→login onboarding path of
`m3/m7_assert.sh` —— taken cross-machine).

## Topology

```
Scenario 1 [single server · Direct] (S1–S3)
  Windows host 192.168.31.244 —— Docker bridge
    ├─ flock-wc1 / flock-wc2 (flock-client, service daemon)
  jowency 192.168.31.221 —— LXD (lxdbr0 10.100.0.0/24 NAT)
    ├─ flock-s1 (flock-server, Direct :9443; a proxy device publishes host 0.0.0.0:9443)
    ├─ flock-c3 / flock-c4 (flock-client)
  All clients connect directly to 192.168.31.221:9443; full-mesh ping (20
  cells) + a 5-node peers roster.

Scenario 2 [two servers · cross-machine Raft + dual transport] (R1–R5)
  server-1 = flock-srv1 (Windows Docker; Direct, publishing 0.0.0.0:9443 for
             clients + 0.0.0.0:9500 for the Raft fabric)
  server-2 = flock-s2 (jowency LXD; Frp access —— host frps :7000/:24000,
             in-process flock-frpc registration; Raft :9500 published via a
             proxy device)
  2-voter init-cluster --endpoints 192.168.31.244:9443,192.168.31.221:24000
  Clients split across both sides: flock-2w1/2w2 (→ server-1 direct),
  flock-c5/c6 (→ the frps user port 24000).
```

## Firewall prerequisites (jowency, read first)

The measured environment has two pre-existing blocks that **must be allowed
temporarily for the test window and reverted afterwards** (the commands and
reversion also in the `lxd-cleanup.sh` header and multinode-test.md's
"environment blocks encountered"):

1. The `DOCKER-USER` chain of the `nft` table `ip filter` has a pre-set rule
   `iifname lxdbr0 → 10/8, 172.16/12, 192.168/16 ct state new drop` (blocking
   LXD containers toward private networks —— in scenario 2 both flock-s2 →
   server-1 Raft dialing and c6's endpoint-change direct connection were
   blocked):
   ```sh
   # Allow (only dst=Windows host + this test's ports; note the handle,
   # revert after the test with nft delete rule as recorded)
   sudo nft insert rule ip filter DOCKER-USER iifname "lxdbr0" ip daddr <WIN_IP> \
        tcp dport { 9443, 9500 } ct state new counter accept comment "flock-mn-test-temp"
   ```
2. `ufw` default deny incoming: LXD container sources (10.100.0.0/24) to the
   host's published ports are not inside "LAN trusted 192.168.0.0/16" (the
   container→host INPUT face blocked —— scenario 1's LXD clients and scenario
   2's frps user/registration ports):
   ```sh
   sudo ufw allow in on lxdbr0 to any port 9443  proto tcp comment "flock-mn-test"
   sudo ufw allow in on lxdbr0 to any port 7000  proto tcp comment "flock-mn-test"
   sudo ufw allow in on lxdbr0 to any port 24000 proto tcp comment "flock-mn-test"
   # Revert: sudo ufw delete allow <the same three lines verbatim>
   ```

Windows inbound probe (do this first): after `docker run -d -p
0.0.0.0:19444:19444 alpine …nc -l…`, from jowency run `nc -w5 <WIN_IP> 19444`.
**Measured bidirectionally working in this environment** (Windows inbound
usable), so scenario 2 keeps the original topology of "server-1 in Windows
Docker" without degradation. If inbound is blocked: switch scenario 2 to both
servers in LXD (each publishing ports via a proxy device, still cross-container)
+ Windows Docker running only outbound clients; and add the firewall allowance
on the real machine (admin):
`netsh advfirewall firewall add rule name="flock-mn" dir=in action=allow protocol=TCP localport=9443,9500`

## Replication steps

```sh
# 0) Build the Linux amd64 release binaries (three: the single-server Direct
#    tier / the multi-primary tier / the client)
docker buildx build -f deploy/multinode/Dockerfile.buildbin \
    --output type=local,dest=deploy/multinode/out .
# 1) Stream to jowency (tar over ssh; scp/lxc pull silently truncate large files)
tar -C deploy/multinode/out -cf - flock-server-direct flock-server-mp flock-client \
  | ssh jowency@192.168.31.221 "mkdir -p ~/flock-mn/bin && tar -C ~/flock-mn/bin -xf - && chmod +x ~/flock-mn/bin/*"
tar -C .tmp/frp_0.71.1_linux_amd64 -cf - frps frpc \
  | ssh jowency@192.168.31.221 "tar -C ~/flock-mn/bin -xf - && chmod +x ~/flock-mn/bin/frp*"
tar -C deploy/multinode -cf - lxd-setup.sh server-*.toml frps-mn.toml client.toml.example \
  | ssh jowency@192.168.31.221 "mkdir -p ~/flock-mn/assets && tar -C ~/flock-mn/assets -xf -"
# 2) Firewall prerequisites (see the section above)
# 3) Provision
ssh jowency@192.168.31.221 "JOW_LAN_IP=192.168.31.221 bash ~/flock-mn/assets/lxd-setup.sh 1"
bash deploy/multinode/win-docker-setup.sh 1
# 4) Assert (idempotent bootstrap + S1–S3; exit codes 0/1/2/64)
bash deploy/multinode/multinode_assert.sh 1
# Scenario 2: lxd-setup.sh 2 / win-docker-setup.sh 2 / multinode_assert.sh 2 (R1–R5)
# 5) Teardown (both sides)
ssh jowency@192.168.31.221 "bash ~/flock-mn/assets/lxd-cleanup.sh"   # or --keep-files
bash deploy/multinode/win-docker-cleanup.sh
```

## Asset inventory

| File | Purpose |
|---|---|
| `Dockerfile.buildbin` | Linux amd64 release-binary build (dependency-layer caching; two server tiers + client, stripped) |
| `server-s1-direct.toml` | Scenario-1 server config template (Direct, no [sync]) |
| `server-2w-direct-mp.toml` | Scenario-2 server-1 (Windows Docker, Direct + cross-machine raft_peers) |
| `server-2s-frp-mp.toml` | Scenario-2 server-2 (LXD, Frp→frps:24000 + cross-machine raft_peers) |
| `frps-mn.toml` | Scenario-2 frps (jowency host, bind 7000) |
| `client.toml.example` | Client config template (pinned endpoints + [auth] username) |
| `lxd-setup.sh` / `lxd-cleanup.sh` | jowency-side provisioning/teardown (via ssh; idempotent; touches only flock-*) |
| `win-docker-setup.sh` / `win-docker-cleanup.sh` | Windows Docker-side provisioning/teardown (HEAD-binary override mounts + named volumes) |
| `multinode_assert.sh` | Assertions (S1–S3/R1–R5; matrix+roster+Raft+revocation; exit 0=all PASS/1=FAIL present/2=bootstrap failure/64=usage) |
| `windows-host-node.ps1` | Windows-host (non-Docker) one-shot network node (for the real-machine checklist, needs an administrator) |

## Real-machine checklist (parts not executed in this session)

- Windows host node (non-Docker): `deploy/multinode/windows-host-node.ps1`
  (admin PowerShell; builds/takes `target\release\flock-client.exe`, config
  pointing at the scenario-1 server, UAC self-elevation, `flock-client run`,
  prints the ping matrix).
- Windows inbound firewall allowance (only if the probe is blocked): `netsh
  advfirewall firewall add rule name="flock-mn" dir=in action=allow
  protocol=TCP localport=9443,9500` (admin).
- If scenario 2 needs the degraded topology with "both servers in LXD": change
  the server-2w config following the server-2s pattern for advertise/proxy
  publication (update the raft_peers endpoints on the jowency side to match).
