# Windows real-machine --smoke record (docs/design.md §7-M3 manual checklist)

> 2026-11-02 project rename ChmlVPN → **Flock VPN**: the binary names (flock-client/
  flock-server), container/network names (flock-m3-*), and paths (/etc/flock, /var/lib/flock) in
  this document's command examples and output samples have been synced to the new naming; the
  repository directory rename to `E:\Works\FlockVPN` transitioned via a junction (the directory
  was named ChmlVPN at recording time; closing steps in dir-rename-final.md). Console output
  samples are rendered in their English-locale forms (recorded on a Chinese-locale system).

- Date: 2026-11-01
- Real machine: Windows 10 Pro 26H2 (build 26300, x64), administrator **no** (`net session` →
  `ADMIN=no`; the checklist requires recording this truthfully — rerun without elevation, do not
  elevate)
- Docker: Docker Desktop 29.8.2 (`docker info --format '{{.ServerVersion}}'`)
- Repository: `E:\Works\FlockVPN` @ main 306688f (ChmlVPN at recording time)
- Conclusion first: **wintun adapter creation and `route add` both require administrator
  privileges; in a non-elevated shell they fail with `os error 5 (access is denied)` and "The
  requested operation requires elevation." respectively**. Of the checklist items that depend on
  a tun device (route print, real-machine tun MTU, ping the server VIP via the relay), three were
  **blocked** in the non-elevated session; the blocking points and evidence are listed item by
  item in §4; the remaining items (topology, bootstrap, wintun.dll behavior, host unit tests)
  were tested live. The in-container control group with the same-version data plane passed
  everything (§5).

---

## 1. Preparation

### 1.1 wintun.dll (R13: distribute the official signed DLL with the program)

The repository does not carry wintun.dll (`find . -iname wintun*` finds nothing); take 0.14.1
from the official build:

```
$ curl -fsSL -o wintun-0.14.1.zip https://www.wintun.net/builds/wintun-0.14.1.zip
$ sha256sum wintun-0.14.1.zip
07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 *wintun-0.14.1.zip
$ unzip -o -q wintun-0.14.1.zip -d extracted     # extracted into the fresh directory .tmp/wintun-dl/
$ cp .tmp/wintun-dl/extracted/wintun/bin/amd64/wintun.dll target/debug/wintun.dll
```

Signature check (PowerShell `Get-AuthenticodeSignature`): `Status=Valid`, signer
`CN=WireGuard LLC, O=WireGuard LLC, L=Boulder, S=Colorado, C=US` (427552 bytes, amd64).

tun-rs (pinned at 2.8.16) on Windows loads `wintun.dll` at runtime via `libloading` (default
filename, `tun-rs-2.8.16/src/platform/windows/device.rs:48`:
`config.wintun_file.as_deref().unwrap_or("wintun.dll")`); placing it in the same directory as
the executable (`target/debug/`) is enough for it to load — in this live test the DLL loaded
successfully (a load failure would produce a module-not-found class of error, not the error 5
observed in §3).

### 1.2 Topology: m3.yml port mapping to the host

The committed `deploy/m3.yml` originally mapped nothing to the host (comment: "user ports
27500/27501 reachable inside the container network, not mapped to the host"). To satisfy this
checklist's "host client points at the localhost-mapped endpoint", a loopback-only port mapping
was added to the `frps` service (`git diff deploy/m3.yml` = 7 insertions, 1 deletion):

```yaml
    ports:
      - "127.0.0.1:27500:27500"
      - "127.0.0.1:27501:27501"
```

`server-m3.toml`'s advertise endpoint is from the container's perspective (`frps:27500`),
unresolvable on the host. Following the M2 `server-frp.toml` pattern ("M2 client on the host ⇒
127.0.0.1 mapped ports"), a host-perspective variant `.tmp/server-m3-host.toml` (the only
differences: `advertise_endpoint = "127.0.0.1:27500"`, `extra_endpoints = ["127.0.0.1:27501"]`)
was injected at runtime and the server restarted:

```
$ export MSYS_NO_PATHCONV=1
$ docker compose -f deploy/m3.yml up -d
 Container flock-m3-frps-1 Recreated / Started (new 127.0.0.1:27500-27501 mappings)
$ docker compose -f deploy/m3.yml cp .tmp/server-m3-host.toml server:/etc/flock/server.toml
$ docker compose -f deploy/m3.yml restart server
$ docker compose -f deploy/m3.yml ps --format '{{.Name}} {{.Status}} {{.Ports}}'
flock-m3-frps-1   Up  127.0.0.1:27500-27501->27500-27501/tcp
flock-m3-server-1 Up
flock-m3-client-1 Up
```

Server ready (log): `dataplane up: tun tun0 vip 100.64.0.1 route 100.64.0.0/16 + rp_filter=1`,
`listening on 0.0.0.0:9443 (mode: frp)`. Host loopback connectivity:

```
PS> Test-NetConnection 127.0.0.1 -Port 27500
TcpTestSucceeded : True
```

### 1.3 Host client test config and bootstrap

Test config `.tmp/host-client.toml` (pointing at the localhost-mapped endpoints):

```toml
state_dir = "E:/Works/FlockVPN/.tmp/host-client-state"
tun_name = "tun0"
mtu = 1280
endpoints = ["127.0.0.1:27500", "127.0.0.1:27501"]
```

Bootstrap sequence (same order as m3_assert.sh, by hand on the host):

```
$ cargo run -p flock-client -- --config .tmp/host-client.toml gen-keys
device-id=2b7ddf35560aca5528e53f138393822e7f800333c9735ebeb3517a27052d017b
device-x=b+PDQoL3xTKMxgxumlunRkKLYWeL+0i9P96tB2tC5Uo
device-ed=XVFeoYKi5OA/PoDGa60ObX1bTCmJHbn1/Hcq7zg40c4

$ docker compose -f deploy/m3.yml exec -T server flock-server \
    --config /etc/flock/server.toml device-add \
    --user winhost --device-x "b+PDQoL3…" --device-ed "XVFeoYKi…"
device_id=5d515ea182a2e4e03f3e80c66bad0e6d7d5b4c29891db9f5fc772aef3838d1ce
vip=100.64.0.3                       # the container client already holds 100.64.0.2; this machine gets .3

$ docker compose -f deploy/m3.yml exec -T server flock-server \
    --config /etc/flock/server.toml invite --ttl-secs 86400 > .tmp/host-invite.b64
$ printf '100.64.0.3' > .tmp/host-client-state/vip

$ cargo run -p flock-client -- --config .tmp/host-client.toml invite .tmp/host-invite.b64
invite ok: cluster=d638c699732c629abeedb52dd1e722fc endpoints=2 (root pubkey pinned + directory stored)
```

`endpoints=2` is exactly the injected host-perspective directory (127.0.0.1:27500 + 27501) — the
config's endpoint override agrees with the directory (the `override_endpoints`
endpoint↔material same-signature check passes, app/flock-client/src/main.rs:218-233).

## 2. --smoke live test

Per the checklist's command shape (`--config` and `--smoke` order-independent; parsed at
main.rs:58-85):

```
$ cargo run -p flock-client -- --smoke --config .tmp/host-client.toml
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.14s
     Running `target\debug\flock-client.exe --smoke --config .tmp/host-client.toml`
flock-client: tun: tun-rs create tun0: Access is denied. (os error 5)
error: process didn't exit successfully: … (exit code: 2)
```

- The `--smoke` path (main.rs:137-162): `TunIo::open` (creates the wintun adapter) → print
  `tun: tun0 mtu=1280 vip=…` → `route::apply` → sleep 2s → tear the device down.
- **The live test failed at the first step** (tun-rs `build_sync` creating the adapter,
  tun.rs:99-104) **with Windows error 5 (ERROR_ACCESS_DENIED, access denied)**, exit code 2; so
  the tun print, the routing Unsupported print, and `smoke done` were never reached.

## 3. Administrator-privilege behavior of wintun.dll first-time driver install / adapter
creation (key record)

- On this machine the **wintun kernel driver is already installed and running** (not a first
  install by this checklist; the origin is inferred to be the local Tailscale — the adapter list
  contains `Tailscale Tunnel`):
  ```
  $ sc query wintun
  SERVICE_NAME: wintun
          TYPE               : 1  KERNEL_DRIVER
          STATE              : 4  RUNNING
  PS> Get-CimInstance Win32_SystemDriver | ? {$_.Name -match 'wintun'}
  Name    State    PathName
  wintun  Running  C:\WINDOWS\system32\drivers\wintun.sys
  PS> (Get-Item C:\Windows\System32\drivers\wintun.sys).VersionInfo
  FileVersion : 0.14   ProductVersion : 0.14   CompanyName : WireGuard LLC
  ```
- Behavioral conclusion: **even with the driver already in the driver store and running, a
  non-elevated process calling `WintunCreateAdapter` (via tun-rs `DeviceBuilder::build_sync`)
  is still rejected — `os error 5, access denied`**; that is, the wintun adapter "creation" step
  itself requires administrator privileges, independent of whether the driver was already
  installed. Loading the DLL itself (including signature verification) needs no administrator —
  this run loaded it successfully from a normal-user process and only got rejected at adapter
  creation. The true "first-install" form on a real machine (`WintunCreateAdapter` triggering
  driver installation when the driver is not in the store) cannot be reproduced on this machine
  (the driver already exists) — not verified, marked as-is.

## 4. Item-by-item checklist results

| Checklist item | Result | Evidence |
|---|---|---|
| wintun device creation behavior | **Blocked (permissions)**: creation in a non-elevated shell fails with `os error 5 (access is denied)`, process exit code 2; no adapter residue (`Get-NetAdapter` shows no new tun0/wintun entry) | §2 output |
| Route injection (route print 100.64.0.0/10) | **Blocked (permissions)**, doubly: ① code path — on Windows `route::apply` already returns an explicit `Unsupported` with manual instructions (route.rs:84-92: `route add 100.64.0.0/16 mask 255.255.0.0 <vip> metric 5`; in the smoke run it was never printed because tun failed first; the host unit test `route::tests::non_linux_apply_is_explicit_unsupported` covers that path); ② manual injection — a non-elevated `route add` is rejected by the system (below). The full route print table has **no** 100.64.0.0-subnet route | the two output blocks below |
| tun MTU 1280 | **Blocked (same as tun creation)**: the spec-level MTU=1280 is already in the config and `TunSpec` (config.rs:19-21 default 1280; tun.rs:33 `MTU=1280`), but the real-machine interface-level MTU needs a live device to observe (`netsh interface ipv4 show subinterface`); with creation blocked non-elevated, it went unmeasured | §2 |
| Ping the server VIP via the relay | **Blocked (same as tun creation)**: host `ping 100.64.0.1`, 2 sent 0 received, 100% loss (no tun/no route; goes out the default gateway into a black hole); the relay TCP path itself is reachable from the host (`Test-NetConnection 127.0.0.1:27500 → True`), and the same-version data plane inside the container pings fine through the same frps relay (the §5 control group) | this section's output |
| Administrator-privilege behavior of wintun.dll first-time driver install | **Recorded** (§3): DLL loading needs no administrator; adapter creation does (error 5); the driver was preinstalled (wintun.sys 0.14 RUNNING); the true "first-install" form unverified | §3 |

Manual route-injection live test (both prefix forms tried; the /16 form from the `route.rs`
instruction + the /10 form from the §7-M5 checklist):

```
$ route add 100.64.0.0 mask 255.255.0.0 100.64.0.3 metric 5
The requested operation requires elevation.
rc=1
$ route add 100.64.0.0 mask 255.192.0.0 100.64.0.3 metric 5
The requested operation requires elevation.
rc=1
```

Host ping (corroborating the block):

```
$ ping -n 2 -w 2000 100.64.0.1
Request timed out. ×2
Ping statistics for 100.64.0.1: Packets: Sent = 2, Received = 0, Lost = 2 (100% loss)
```

Host unit tests (§7-M3's "on the Windows host, `cargo test -p flock-client`", including the real
execution of the routing-Unsupported path):

```
$ cargo test -p flock-client
test route::tests::non_linux_apply_is_explicit_unsupported ... ok
test route::tests::plan_defaults_to_100_64_slash16 ... ok
test route::tests::pool_mask_dotted ... ok
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.63s
```

## 5. Container control group (Linux container, same topology and binary semantics; not a host
checklist item)

The container client (VIP 100.64.0.2, via the frps relay) of the same m3 topology — logs and
live test:

```
client-1 | flock-client: tun tun0 mtu=1280 vip=100.64.0.2
client-1 | flock-client: route 100.64.0.0/16 → tun0 + rp_filter=1
client-1 | flock-client: connected frps:27500 (server=f2220c4ee069b62c93554fa5cdf05e09)
$ docker compose -f deploy/m3.yml exec -T client ip addr show tun0
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 …
    inet 100.64.0.2/32 scope global tun0
$ docker compose -f deploy/m3.yml exec -T client ping -c 3 -W 3 100.64.0.1
3 packets transmitted, 3 received, 0% packet loss, rtt min/avg/max = 8.220/35.302/52.428 ms
```

That is: the client code paths (tun-rs MTU 1280 + /16-pool route + the data plane via the frps
relay) all pass inside the container; the host's blocking point reduces to **the Windows
permission surface (adapter creation + route add)**, not client logic.

## 6. Blocked-item summary and elevated re-test guidance

The single root cause of the blocks: **the current session is not an administrator**. The
checklist forbids elevating, so the following is left for an administrator session:

1. In an administrator terminal, re-run `cargo run -p flock-client -- --smoke --config
   .tmp/host-client.toml` — expected: the wintun adapter is created successfully (the driver is
   already in the store) → prints `tun: tun0 mtu=1280 vip=100.64.0.3` → the route line prints
   the Windows `Unsupported` (with manual instructions; expected behavior, not a failure) → the
   device is torn down after 2s; meanwhile, in another terminal, `netsh interface ipv4 show
   subinterface` to see tun0 MTU=1280 and `Get-NetAdapter` to watch the wintun adapter
   appear/disappear (tun-rs Drop teardown).
2. Administrator `route add 100.64.0.0 mask 255.192.0.0 100.64.0.3 metric 5` (the /10 assertion
   form of §7-M5; the code's instruction is /16, see route.rs:87) + if `route add … <vip>` is
   rejected because the gateway is not on-link, first `netsh interface ip add address "tun0"
   100.64.0.3 255.255.255.255` or use `route add … 0.0.0.0 IF <tun0 ifindex>` — this branch
   could not be verified this time (permission-blocked); adjust per the actual error during the
   re-test.
3. In an administrator session, run `run` mode (same config), and after the session is up, `ping
   100.64.0.1` (via the 127.0.0.1:27500 relay; host → frps → server tun VIP).
4. "First-install behavior when the driver is not preinstalled" (whether a UAC/driver-signature
   dialog appears) cannot be reproduced on this machine (wintun.sys already in the store); a
   clean Windows real machine is needed to record it.

## 7. Cleanup

After the record was complete, the following was run:

```
$ docker compose -f deploy/m3.yml down -v
```

(Output at the end of the record; includes deletion of the server-state/client-state volumes and
the flock-m3net network.)
Added/changed inside the repository: `deploy/m3.yml` (+7/-1, frps host loopback mappings); the
test artifacts under `.tmp/` (host-client-state, host-client.toml, host-invite.b64,
server-m3-host.toml, wintun-dl/) are one-shot items in the gitignore scope, not committed.
