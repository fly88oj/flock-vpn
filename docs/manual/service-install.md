# Service installation manual (M6: daemon side + tray; docs/design.md §7-M6)

> Covers: service install/uninstall on Windows/Linux/macOS, tray autostart registration,
> elevation requirements, quit semantics, and no-GUI behavior. The `flock-client install` /
> `uninstall` / `service` / `status` / `tray` subcommands. The tray UI shipped with M6 phase two
> (design §7-M6.7; the IPC contract is `app/flock-client/src/ipc.rs`).

## 0. Two-process model at a glance (§7-M6.1)

| Process | Context | Responsibilities |
|---|---|---|
| `flock-client service` | system service (auto-start at boot, no GUI) | all supervise/data-plane logic + the control-IPC server |
| `flock-client tray` | user session (autostart at login) | tray only (three-item menu: connection status/VPN IP/quit); queries/controls via IPC |

A Windows service runs in session 0 and cannot create a tray — the two-process split is a hard
constraint; Linux/macOS are isomorphic (a systemd system unit / a LaunchDaemon separate from the
user session).

## 1. Common

```
flock-client install [--user|--service] [--config <client.toml>]   # both by default
flock-client uninstall [--user|--service]
flock-client service [--config <client.toml>]                      # run the daemon in the foreground (launched by the service manager)
flock-client status                                                 # one-shot Status query and print
```

- Install writes the **install-time** `--config` path (resolved to an absolute path) into the
  service definition — the SCM working directory is system32, and systemd/launchd do not inherit
  the shell CWD, so **the config must be an absolute path** (installing with a relative path
  resolves it against the CWD automatically, but moving the directory afterwards breaks it).
- Uninstall/reinstall is idempotent: `install` deletes the old service definition before creating
  the new one; `uninstall` skips items that do not exist.
- `status` exits with code 2 when there is no daemon (token file missing or the control plane
  unreachable; the error message distinguishes the two).

## 2. Windows

| Item | Content |
|---|---|
| Service name | `flock-client` (LocalSystem, OWN_PROCESS, SERVICE_AUTO_START) |
| Command line | `<exe> service --config <abs>` (exe = the binary path at install time) |
| Failure recovery | restart on the 1st/2nd failure (5s delay), no action from the 3rd on; the counter resets after 24h |
| Event log | source `flock-client` registered into the Application log (HKLM, with install); service start/stop/errors land in the event log; no message DLL ⇒ messages appear as insertion strings (a template DLL is a later polish item) |
| Tray autostart | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `flock-client-tray` = `"<exe>" tray` (exe quoted — safe for paths with spaces; **no elevation needed**) |
| Control IPC | named pipe `\\.\pipe\flock-client-control`, explicit DACL: SYSTEM + Administrators + the interactive-users group (IU); token file `%ProgramData%\flock\control-token` (ACL: Users read) |

**Elevation**: service install/uninstall needs an administrator (opening the SCM with
CREATE_SERVICE/DELETE rights). Running `install`/`uninstall --service` in a non-elevated session
yields a clear error — for precedent and procedure see `docs/manual/windows-smoke.md` (this
repository's Windows real-machine checklist convention: record truthfully whether elevated; rerun
without elevation). Registering the tray autostart (`install --user`) needs no administrator.

**Real-machine manual checklist (to be executed in an administrator session; an M6 acceptance
item)**:
1. [ ] Elevated session: `flock-client install` → `sc query flock-client` (RUNNING),
   `sc qc flock-client` (AUTO_START; the binary path contains `service --config <abs>`);
2. [ ] Reboot the machine → the service auto-starts; `flock-client status` returns a snapshot;
3. [ ] `flock-client status` → `state=connected` (when the access server is reachable); after
   `flock-client uninstall --user`, the Run key is cleared;
4. [ ] The Event Viewer's Application log shows start/stop events from source `flock-client`;
5. [ ] With the service running, `flock-client uninstall`: first an SCM Stop (graceful), then
   delete the definition.

**Running directly in a terminal**: `flock-client service` outside an SCM context (terminal/
container) automatically falls back to the foreground daemon (logs straight to stderr) — the debug
form, synonymous with the Unix `service` subcommand.

## 3. Linux (systemd)

| Item | Content |
|---|---|
| Unit | `/etc/systemd/system/flock-client.service` (rendered by install; sample `deploy/systemd/flock-client.service`) |
| Key directives | `WantedBy=multi-user.target`, `After=network-online.target` + `Wants=`, `Restart=on-failure`, `RestartSec=5`, `ExecStart=<exe> service --config <abs>` |
| Install actions | write the unit → `systemctl daemon-reload` → `systemctl enable --now flock-client` |
| Tray autostart | `~/.config/autostart/flock-client-tray.desktop` |
| Control IPC | Unix socket `/run/flock/client.sock` (0660; directory /run/flock 0755); token `/var/lib/flock/client/control-token` (0640 root) |

**Elevation**: writing `/etc/systemd/system` and the systemctl actions need root — as non-root,
the error message carries a sudo hint (`sudo flock-client install`).

**Group authorization (optional; opening control beyond root)**: the default is root:root
(works out of the box = root-only control). To let the tray user query/stop the service, write
`control_group = "flock"` (the group must exist first) into client.toml — at daemon startup, the
token and socket get chgrp'ed to that group where possible (only local /etc/group names or a
numeric gid are resolved; failure warns without blocking).

**Container note**: `systemctl enable` requires systemd running (PID 1 = systemd); dev/test
containers have no systemd ⇒ the install command returns the error as-is (unit rendering is
already covered by unit tests; the host can run `flock-client service` to verify the daemon
behavior itself).

### 3.1 Linux live test (systemd container: S1–S6 all PASS, 2026-11-07)

The full semantics of the M6 service form were verified inside a **systemd container** (Docker
Desktop WSL2, cgroup v2, `--privileged`; `docker restart` of the container = STOPSIGNAL
SIGRTMIN+3 clean shutdown → the "boot" semantics of powering on again). Assets and assertions:

- Topology `deploy/systemd-test.yml`: server (Direct mode + the M3 data plane, tun0 VIP
  100.64.0.1; `deploy/server-systemd-test.toml` — the endpoint is server:9443 from the container
  network's perspective) + client (`deploy/Dockerfile.systemd-test`: flock-client + systemd as
  PID 1, stripped to the single-machine surface; no dbus/display stack installed);
- Assertions `deploy/systemd_assert.sh` (S1–S6 each PASS/FAIL; any FAIL ⇒ non-zero exit code).

Results (two consecutive runs both PASS=6 FAIL=0, exit code 0; bootstrap idempotent):

| Item | Assertion | Result |
|---|---|---|
| S1 install | `flock-client install --config /etc/flock/client.toml` (root, default scope) → the unit lands at `/etc/systemd/system/flock-client.service`, `is-enabled`=enabled, `LoadState`=loaded + `FragmentPath` pointing at the new path (evidence daemon-reload ran), `enable --now` already started it (is-active=active), and ExecStart/Restart=on-failure/WantedBy directives all present | PASS |
| S2 boot autostart | `docker restart` the container (simulating a boot) → systemd starts the service (is-active=active) | PASS |
| S3 VPN connectivity | after the service starts, tun0 appears (inet 100.64.0.2/32 mtu 1280) + ping to the server VIP 100.64.0.1 works | PASS |
| S4 IPC | `flock-client status` → state=connected, vip=100.64.0.2 (matching the device-add assignment), endpoint=server:9443 | PASS |
| S5 headless | the daemon process environment has no DISPLAY/WAYLAND_DISPLAY/DBUS_SESSION_BUS_ADDRESS/XDG_RUNTIME_DIR (5 environment variables in total); the process surface is only `flock-client service` (no tray process); `flock-client tray` prints "no GUI session detected (no DISPLAY/WAYLAND_DISPLAY or no session DBus), tray not started" with **exit code 0** and no leftover process; no panic in the journal | PASS |
| S6 quit semantics | the IPC `CtrlReq::Shutdown` frame hand-injected (postcard over the Unix socket — isomorphic to the tray stopping the service; `[u32 LE len][variant number 1][32B raw token]`, layout verified by a Status probe) → response `01 00 00 00 01` = CtrlResp::Ok; the service exits 0 and stops (`Result`=success, `ExecMainStatus`=0) and stays dead for >RestartSec (5s) (**no revival**; the Restart=on-failure semantics); another `docker restart` autostarts it again (enabled retained) | PASS |

Boundaries (as-is): this live test covers the systemd semantics surface (unit write/enable/
daemon-reload/boot start/failure-restart policy/graceful stop without revival) and the full daemon
chain (tun/routing/connectivity/IPC/headless), with the runtime environment being a container
(the image has network-online.target.wants emptied — `After=` does not block startup; a physical
machine's network-online wait and distro-specific preset surface are not covered). The physical
real-machine checklist (distro installation, `systemctl preset` interactions, the sudo-hint path
for non-root users) still follows the elevation notes above this section, executed manually.

## 4. macOS (launchd) — **not verified (no device on this machine)**

| Item | Content |
|---|---|
| daemon | `/Library/LaunchDaemons/com.flockvpn.client.plist` (RunAtLoad, **no KeepAlive**; sample `deploy/launchd/com.flockvpn.client.plist`) |
| Logs | `StandardErrorPath=/var/log/flock-client.log` (already in the sample); rotation via newsyslog — `/etc/newsyslog.d/flock-client.conf`: `/var/log/flock-client.log root:wheel 640 3 1024 * J` |
| Install actions | write the plist → `launchctl load -w <path>` (uninstall: `unload -w` + delete the file) |
| Tray autostart | `~/Library/LaunchAgents/com.flockvpn.client-tray.plist` (RunAtLoad) + `launchctl load -w` |
| Control IPC | same layout as Linux (/run/flock/client.sock, /var/lib/flock/client/control-token) |

**Elevation**: writing/loading the LaunchDaemon needs root (sudo hint as on Linux). **No macOS
device on this machine ⇒ this whole section is marked not verified** (rendering and the command
sequence have unit tests/review; a real-machine checklist slot is reserved):
1. [ ] `sudo flock-client install` → `sudo launchctl list | grep flockvpn`;
2. [ ] Reboot → the daemon autostarts + `flock-client status`;
3. [ ] After Shutdown, launchd does not revive it (no KeepAlive).

## 5. Quit semantics (§7-M6.1, identical across the three platforms)

- The tray "Quit" menu = stop the VPN + the tray process exits: send `CtrlReq::Shutdown` (with
  the token) to the daemon → the daemon stops gracefully: drop the session (tunnel GoAway/FIN;
  the peer sees the session terminate) → stop the data plane → tear down tun → process exit code
  0.
- **The service stays installed** and auto-starts next boot; a graceful stop is **not revived**
  (systemd `Restart=on-failure` only fires on failed exits; launchd has no KeepAlive; the Windows
  recovery policy only hooks failure codes).
- Signals: SIGTERM/SIGINT (Unix) and SCM Stop (Windows) go down the same graceful-stop path.
- Starting again: systemd `systemctl start flock-client` / `sc start flock-client` /
  `launchctl load`, or reboot the machine.

## 6. No-GUI behavior

- `flock-client service` has no GUI dependencies of any kind (the `tray` feature gate keeps it
  out of the daemon path; the `--no-default-features` build is the headless-server form — the
  tray subcommand is not compiled in).
- `flock-client tray`'s GUI detection: on Linux, check that at least one of
  `DISPLAY`/`WAYLAND_DISPLAY` is set + a session DBus (`DBUS_SESSION_BUS_ADDRESS` or
  `$XDG_RUNTIME_DIR/bus`); any missing ⇒ the log line "no GUI session detected, tray not started"
  with **exit code 0**; on Windows/macOS, a tray-creation failure likewise exits gracefully (no
  panic). When the tray is absent: the `status` subcommand provides the equivalent query
  (printing state/vip/endpoint/epoch/uptime).
- For the tray feature's platform-default differences (cargo cannot express per-platform default
  features), see the limitation statement in design §7-M6.5: the GUI dependencies
  (tray-icon/objc2*/ksni) all hang target-gated optional, pulled in by the `tray` feature — the
  Linux default build has a zero-GUI-dependency surface, and the headless release build uses
  `--no-default-features`.

## 7. Tray real-machine checklist (M6 phase two; an automation blind spot, awaiting visual
confirmation by the user)

The IPC surface of `flock-client tray` (polling/copy projection/quit-adjudication ordering/
Shutdown stopping the service) is already covered by unit tests (a real-transport IPC mock) and a
real Windows process test on the host (a mock daemon on a real endpoint/token: the tray stays
alive ≥10s without panic, 2s refresh logs, state consistent with `flock-client status`, and a
token `Shutdown` ⇒ the daemon exits + the tray shows "service not running" and keeps retrying).
**The visual items cannot be automated** — confirm one by one:

1. [ ] **Icon appears**: after starting the daemon (real topology or the §2 service), run
   `flock-client tray` — the flock icon appears in the system tray (a 32×32 dark-teal rounded
   base + a white goose-formation arrow); the tooltip shows the status summary (e.g. "Flock VPN:
   connected · frps-a:23000 · VPN IP 100.64.0.11");
2. [ ] **Three menu items**: right-click the icon — "Connection status: …" and "VPN IP: …" greyed
   read-only + "Quit" clickable;
3. [ ] **Text refresh**: after the daemon's state changes (connect/disconnect/stop), the menu
   text follows within ≤2s (when stopped it shows "Connection status: service not running" /
   "VPN IP: —");
4. [ ] **Quit action**: click "Quit" ⇒ the daemon stops gracefully (`flock-client status`
   unreachable, the service still installed) + the tray icon disappears and the tray process
   exits (exit code 0);
5. [ ] With the daemon absent, start `flock-client tray`: the icon is still there, the menu shows
   "service not running", and after the daemon starts, the real state returns within ≤2s (the
   token auto-reloads — same for the daemon-restart-changes-token scenario).
6. [ ] (Linux desktop real machine) with a GUI session the tray appears (KDE/GNOME+extension);
   on a headless host `flock-client tray` prints "no GUI session detected, tray not started"
   with exit code 0.
7. [ ] (macOS, unverified — no device) the tray appears + the quit semantics as above;
   `cargo check --target aarch64-apple-darwin -p flock-client --features tray` compile-level
   verification (this session's toolchain download was too slow to finish; to re-run when an
   environment exists).
8. [ ] (Windows real-machine daemon joint test) after starting the real service in an elevated
   session (the §2 checklist), re-run items 1–5 — in a non-elevated session, wintun/route
   injection is blocked (the windows-smoke.md precedent); this session's live testing substituted
   a mock daemon on the IPC surface.
9. [ ] **(M7 `peers` on real machines)** after starting the real service + real topology in an
   elevated session: `flock-client login` (password bootstrap) → the `flock-client peers` table
   appears (with the server and remote peer entries, numbers in the latency column — raw ICMP
   needs an administrator/service context; the container Linux path was already tested live by
   `deploy/m7_assert.sh`; the Windows/macOS raw surface is confirmed here on real machines) →
   `peers --json` parses under `jq` → after an iperf3 flow, the ↓/↑ traffic columns are non-zero
   (the EWMA convergence window is ~10s).

## 8. Verified/unverified boundaries (as-is)

| Surface | Status |
|---|---|
| IPC contract/server/client (duplex mock + a real Windows named-pipe loopback) | unit tests pass (host) |
| daemon assembly and Shutdown semantics (mock tun + real IPC) | unit tests pass (host; `daemon_loop_shutdown_via_ipc`) |
| tray core logic (all copy-projection branches / token-stale reload / polling recovery / quit ordering with a real-transport IPC mock / icon pixels) | unit tests pass (host, 9 items in `tray::tests`) |
| tray as a real Windows process (mock daemon on a real endpoint / token in place) | live test passes (host: alive/refresh logs/state consistency/Shutdown stops the service then shows "service not running"; visual items → the §7 checklist) |
| tray platform-backend compile surface | Windows host compile + clippy all green; the Linux container tiers (--features tray incl. ksni / --no-default-features) check + clippy all green; macOS **not verified** (no device; the aarch64-apple-darwin toolchain download was too slow for compile-level verification; the API checked against crate sources, §7 checklist) |
| Windows HKCU Run register/unregister round trip | unit tests pass (host, non-elevated) |
| Windows SCM service install/uninstall/autostart/recovery policy | **compile-level verification**; real machines need an administrator → the §2 checklist |
| Windows event-log reporting | code path compile-level + events still land in the log when the source is unregistered; real-machine confirmation → the §2 checklist |
| Linux systemd unit rendering | unit tests pass (host); **systemd container live test passes** (2026-11-07, `deploy/systemd_assert.sh` S1–S6: install/enable/daemon-reload/boot autostart/VPN connectivity/IPC status/headless/Shutdown without revival → §3.1) |
| Unix socket server/permissions | unit tests pass (the Linux container tier with the linux compile surface; this host is Windows — socket unit tests run on a Unix host) |
| Linux desktop tray (ksni/SNI host) on a real machine | **not verified** (the container tier covers only the compile surface; §7 checklist item 6) |
| macOS full chain | **not verified** (no device; rendering/command sequence unit-tested + reviewed; §4/§7 checklist slots reserved) |
| M7 peers full chain (login keep-alive/roster pull/raw ICMP latency/traffic columns) | **container live test passes** (Linux root, `deploy/m7_assert.sh`; re-run on 2026-11-07 after the review fixes with P1–P3 all PASS, exit code 0 — the assertion script gained bounded retries for the daemon re-login window's transient "login in progress (retry shortly)", with no lowering of the numeric/semantic thresholds); unit-test surface (the login state machine with pake on both ends / poison-reconnect / table rendering / IPC contract / probe median) passes on the host; Windows/macOS raw ICMP on real machines → §7 checklist item 9 |
