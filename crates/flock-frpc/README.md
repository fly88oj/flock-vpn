# flock-frpc

Dual-stack subprocess supervision of frpc (docs/design.md §3.9 / §5 /
§7-M2, ★VPN-16). The Flock VPN server exposes its listening port via FRP
relays, but does not compile the frp protocol into itself — two pinned frpc
binaries are supervised as subprocesses:

- **ChmlFrp nodes** ⇔ `ChmlFrp-0.51.2_251023` pinned frpc (panel-hosted);
- **self-hosted nodes** ⇔ original frp `v0.71.1` pinned frpc.

Root reason for the dual stack: the two control-plane generations are
mutually incompatible (ChmlFrp is based on v0.51.2 without control-plane
encryption; the original ≥v0.53.0 enforces AES-128-CFB after login — both
directions break, `docs/research/frp-compat.md` §1.3); subprocess supervision
is the only path that is "compatible with both at zero protocol-maintenance
cost" (frp-compat §3, option A).

## Surface

| Module | Contents |
|---|---|
| `spec` | `RelaySpec::ChmlFrp{mode} / Original{toml}`; `ChmlFrpMode::ConfigFile` (the default `-c`) / `UserTokenAuto` (explicit opt-in, R20 risks in the type docs); the R9 version-matrix lock (cross pairing forbidden + pin check + `--version` measured cross-check) |
| `config` | Config-generator seam: ChmlFrp INI (v0.51.2 dialect) generation/parsing/`[common]`-only admin injection (proxy sections pass through byte for byte, R12); original TOML (v0.71.1 dialect) generation/read-only parsing |
| `probe` | Health probing: local tunnel port over TCP + frpc admin (`/healthz`, present in both generations) |
| `supervisor` | `Supervisor::start(spec) -> ManagedRelay`, `health() -> RelayStatus`, `stop()`; ChmlFrp's three-reconnect exit (the modded behavior) → supervised re-spawn + exponential backoff |

## Tests

`cargo test -p flock-frpc --all-features` — includes golden-file (R8/R12:
generated output matches the official release-archive samples byte for byte /
field by field), matrix (R9: of the 4 combinations only the diagonal passes),
and supervision (fake process stub: 3 exits → 3 restarts + backoff lower
bounds + stop semantics + the probe surface). Real frpc binaries never enter
the tests (the fake stub stands in); golden samples are copied byte for byte
from `.tmp/chmlfrpc/.../frpc.ini` and
`.tmp/frp_0.71.1_linux_amd64/frpc.toml`.

## Security profile (R20)

The cfg API bootstrapped by ChmlFrp `-u/-p` is HTTPS with
InsecureSkipVerify (the all-powerful panel usertoken can be intercepted by a
MITM) ⇒ the `-c` config-file mode is the default (paste-export from the
panel's "Tunnel Management → Config File"); `UserTokenAuto` is retained but
requires explicit opt-in — do not enable it on organizational/multi-user
machines.
