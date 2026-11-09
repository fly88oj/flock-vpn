# Flock VPN

[![CI](https://github.com/fly88oj/flock-vpn/actions/workflows/ci.yml/badge.svg)](https://github.com/fly88oj/flock-vpn/actions/workflows/ci.yml)

A self-hosted, multi-primary active-active open-source VPN: direct connection first (`Direct` by
default, zero frp dependency), with FRP relay as an optional dual stack; the cryptographic contract
layer is provided as a git dependency by the standalone protocol repository
[`flock-protocol`](https://github.com/fly88oj/flock-protocol) (tag
[`v0.1.0`](https://github.com/fly88oj/flock-protocol/releases/tag/v0.1.0)) — hybrid KEM
(X25519 + ML-KEM-768), Noise-IK-style 1-RTT tunnel sessions, OPAQUE login, and TOFU/invite trust
anchors.

- Overall design (authoritative document): [docs/design.md](docs/design.md)
- Standalone protocol-library repository: [fly88oj/flock-protocol](https://github.com/fly88oj/flock-protocol)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · Security: [SECURITY.md](SECURITY.md)

## Core features

| Feature | Description |
|---|---|
| Direct-first + frp dual stack | One access endpoint per server: `Direct` (default; direct listening, zero frp logic) / `Frp` (relay via [flock-frpc](crates/flock-frpc)-supervised frpc; choose when the server has no public IP). The two forms are fully isomorphic to the protocol layer; a single cluster may mix them per machine |
| Multi-primary active-active control plane | [flock-sync](crates/flock-sync): openraft strongly consistent state machine + redb storage + inter-server E2E profile transport + gossip online leases; any server gives the same access experience; revocations replicate via Raft and take effect network-wide in ≤5s |
| flock-protocol embedded at three layers | The protocol layer is its own repository: transport-layer embedding (the tunnel tier is generic over any reliable ordered byte stream — direct/frp/QUIC adapters unchanged), application-layer embedding (envelope/sig/pake trimmed by feature), runtime embedding (wasm32 + C-ABI shim) — see the [protocol repo README](https://github.com/fly88oj/flock-protocol#readme) |
| Post-quantum hybrid KEM | X25519 + ML-KEM-768 (FIPS 203) dual-stack encapsulation; during the quantum-migration era both the classical and post-quantum security boundaries hold |
| 1-RTT tunnel sessions | With a pinned server, one round trip establishes the encrypted tunnel: counter-nonce AEAD, anti-replay, dual-threshold rekey, forgery-limit disconnect |
| OPAQUE login + trust anchor | RFC 9807 aPAKE (the password never leaves the client; offline dictionary attacks require compromising the server); two pinning paths: TOFU first connect / the strong invite-file path |
| Roster and observability | `flock-client peers` (VIP/hostname/account/online/latency/traffic, `--json` machine-readable); server `stats` snapshot + Web UI (M8) |
| Cross-platform client | Windows / macOS / Linux first (tun-rs native paths), Android/iOS reserved via the fd-injection seam; system service + tray |

## Architecture

Layered overview (excerpted from [docs/design.md §0](docs/design.md#0-design-overview)):

```
┌─ Client app (flock-client) ─────────────────────────────────────┐
│ tun(tun-rs) → PacketChannel → yamux streams ─┐                   │
│ routing (rtnetlink/wintun/VpnService)         │                   │
└───────────────────────────────────────────────┼───────────────────┘
                                                │ single TCP (ciphertext; path = access endpoint:
                                                │   Direct connection or via FRP relay)
┌─ flock-protocol (session layer, standalone repo) ─┼──────────────┐
│ SecureStream (record layer: counter-nonce AEAD + anti-replay + rekey) ← yamux runs inside the encryption │
│ Handshake: pinned 1-RTT Noise-IK / TOFU first-connect 2-RTT; X25519+ML-KEM-768  │
│       hybrid KEM + server identity signature (invite file carries the static hybrid pubkey) │
└───────────────────────────────────────────────┼─────────────────┘
                                                │ TCP byte stream (direct or relayed, transparent either way)
┌─ Server app (flock-server) ─────────────────────┼─────────────────┐
│ Listener ListenerMode: Direct (default, zero frp) │ tun + routing + peer forwarding │
│   or Frp (flock-frpc Supervisor-managed relay)    │ flock-sync: openraft + leases  │
│ Control flow: OPAQUE login + device registry + config push │                    │
└─────────────────────────────────────────────────────────────────┘
```

The first-version data plane is hub-and-spoke (client-to-client traffic routes via the server;
threat boundaries in the [security model](#security-model) below); virtual network
`100.64.0.0/10` (RFC 6598 CGNAT), MTU 1280.

## Quick start

### One-shot experience (container direct-connection smoke, no prepare needed)

```bash
git clone https://github.com/fly88oj/flock-vpn.git
cd flock-vpn
docker compose -f deploy/m2-direct.yml up -d --build   # builds inside the image via git deps; zero frp assets
cargo test -p flock-server --test smoke -- --ignored direct
docker compose -f deploy/m2-direct.yml down -v
```

Three smoke assertions: with Direct, after startup the container has no frp process; TOFU
full-chain login + root-signed directory pull; dual-endpoint switching simulation (9443/9444 as
container ports on the same container).

### Three steps (start the server → client login → view the roster)

1. **Server install**: edit `server.toml` (`listener.mode` defaults to `direct`), bootstrap and
   start,

   ```bash
   flock-server --config /etc/flock/server.toml init-cluster   # bootstrap the state store
   flock-server --config /etc/flock/server.toml                # = run, TCP :9443
   ```

   Provision the account (the client first runs `flock-client gen-keys` to print the
   `device-x=`/`device-ed=` public keys):

   ```bash
   flock-server invite > invite.b64
   flock-server redeem --user alice --invite-b64 "$(cat invite.b64)" \
       --device-x <b64> --device-ed <b64>
   ```

2. **Client login**: load the invite (pins the root pubkey), then log in and stay connected,

   ```bash
   flock-client invite invite.b64
   flock-client login        # password → 0600 credentials + login verification + hostname onto the roster
   flock-client service      # daemon: tun + routing + access supervision + control-plane IPC
   ```

3. **View the roster**:

   ```bash
   flock-client peers        # VIP/hostname/account/status/latency/traffic (--json machine-readable)
   ```

Multi-primary cluster (×3 minimum, Raft odd voters): `flock-server init-cluster --voters N`
generates the root key and each node's enrollment bundle; `enroll` / `cluster-bootstrap` /
`cluster-invite` finish the mesh — the full real-machine topology walkthrough is in
[docs/manual/multinode-test.md](docs/manual/multinode-test.md).

## CLI quick reference

`flock-server [--config <server.toml>] [<subcommand>]`

| Subcommand | Purpose |
|---|---|
| `(run)` | Start the server (default; listener.mode: `direct` default / `frp`; `[sync] mode=raft` assembles the multi-primary stack) |
| `init-cluster [--voters N --out DIR --endpoints e1,e2,…]` | Bootstrap the state store; `--voters` generates multi-primary cluster material (root key + enrollment bundles) |
| `enroll --bundle FILE` | Load and verify a node bundle (root-signed directory + enrollment credential) |
| `cluster-bootstrap --root-seed FILE` | Root-key-signed Bootstrap (ticket root) + SetOprf (shared OPRF); idempotent, safe to re-run |
| `cluster-invite --root-seed FILE --bundle FILE [--ttl-secs N]` | Root-key-signed v3 invite → stdout b64 |
| `stats` | Runtime status snapshot (epoch/leader/forwarding counters/online sessions) |
| `invite [--ttl-secs N]` | Issue an invite → stdout single-line b64 (single-server form) |
| `redeem --user U --invite-b64 B --device-x B64 --device-ed B64` | Redeem an invite to provision the account (creates user/device + assigns a VIP) |
| `device-add --user U --device-x B64 --device-ed B64` | Register a device directly (TOFU preset) |
| `revoke --device HEX64` | Revoke a device (advances revocation_epoch + kills sessions) |
| `web-admin-add <username>` | Web UI first-admin bootstrap (password twice from stdin; native OPAQUE registration) |

`flock-client [--config <client.toml>] [<subcommand>]`

| Subcommand | Purpose |
|---|---|
| `(run)` | Foreground debug mode (default): tun + routing + access supervision |
| `service` | daemon: supervise + control-plane IPC + graceful stop + login keep-alive |
| `status` | Sends one Status request to the daemon and prints it |
| `login` | First-time setup: read password → 0600 credentials → login verification + hostname onto the roster |
| `peers [--json]` | Member roster (VIP/hostname/account/status/latency/traffic) |
| `install / uninstall [--user\|--service]` | Install/uninstall the service + tray autostart (both by default) |
| `tray` | Tray process (connection status/VPN IP/quit) |
| `invite <path>` | Load an invite (b64 text/raw bytes) → pin the root pubkey + store the root-signed directory |
| `gen-keys` | Generate/reuse device keys and print the public keys |

## Repository layout

```
.
├── app/
│   ├── flock-server/        # server assembly: listener (Direct/Frp) + control flow + Web UI
│   └── flock-client/        # client assembly: tun adapter + access + roster/tray/service
├── crates/
│   ├── flock-frpc/          # frpc subprocess dual-stack supervision (ChmlFrp 0.51.2 / original frp 0.71.1)
│   └── flock-sync/          # multi-primary active-active sync: openraft + redb + inter-server E2E transport
├── deploy/                  # Docker Compose topologies (m2/m3/m7/e2e/webui/multinode) + assertion scripts
├── docs/
│   ├── design.md            # overall design (authoritative; § numbering is cited by code comments)
│   ├── manual/              # field-test/deployment manuals (multinode/service-install/windows-smoke…)
│   └── research/            # technology-selection research reports (crypto/compression/vpn-mesh/frp-compat…)
├── .github/workflows/ci.yml # CI: three-platform matrix test + check; ubuntu clippy/fmt
└── Cargo.lock               # contains the git-source pinning of flock-protocol (rev level)
```

The cryptographic protocol proper (kem/envelope/sig/pake/session/mux/compress/trust/roster) does
not live in this repository — see the standalone repository
[flock-protocol](https://github.com/fly88oj/flock-protocol).

## Development

Environment: Rust **1.98.1** (pinned in `rust-toolchain.toml`) + Docker Desktop (for container
e2e).

```bash
cargo test --workspace --all-features                     # test gate
cargo clippy --workspace --all-features -- -D warnings    # lint gate
cargo fmt --all -- --check                                # format gate
cargo check -p flock-client --no-default-features         # headless-build compile surface
```

Protocol co-debugging (hacking a local [flock-protocol](https://github.com/fly88oj/flock-protocol)
checkout while the main repository's dependency stays put) goes through a temporary `[patch]` —
examples and caveats in
[CONTRIBUTING.md](CONTRIBUTING.md#protocol-co-debugging-the-patch-workflow); container e2e
guidance and the pre-PR checklist are also in that document.

## Security model

Any third party on the wire (including FRP relay nodes) sees only this protocol's ciphertext and
its lengths. **Boundary statement** (full text in
[docs/design.md §2.5](docs/design.md#25-threat-model-boundaries-explicit-statement-to-prevent-security-claims-from-being-misread-as-peer-level-e2e)):

1. **Cross-peer traffic is plaintext on the access server**: the first version is hub-and-spoke;
   client-to-client traffic is decrypted and then forwarded on the access server — fundamentally
   different from Tailscale's "the coordination server cannot decrypt": any enrolled server can
   observe/tamper with the cross-peer traffic it forwards. Mitigations: server host hardening +
   admission control; long term: peer-to-peer end-to-end overlay encryption (on the roadmap).
2. **Any server can offline-dictionary all passwords**: compromising any enrolled server yields
   the OPRF key (inherent in the OPAQUE model; argon2id is the only speed bump). Mitigations:
   keys 0600/memory-resident + admission red lines; long term: OPRF key thresholding.
3. **TOFU does not defend against an online MITM on first login**: acceptable for personal
   self-hosting; organizational deployments enforce the invite file.
4. **Relay and link**: FRP relay/link observers see only ciphertext and lengths (length
   side-channel countermeasures in the compression tiers); the ChmlFrp panel credential-channel
   risk is in design §5.

Vulnerability reporting: [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting).

## Roadmap

- [ ] Peer-to-peer end-to-end overlay encryption (client-client inner session; the server degrades
      to a blind relay)
- [ ] OPRF key thresholding (quorum unsealing; removes the single-server password-dictionary surface)
- [ ] Android / iOS clients (the tun fd-injection seam is already reserved)
- [ ] `pq-sign` (the ML-DSA-65 parallel-signature tier) to become default-on after an independent
      audit
- [x] Protocol library released standalone (flock-protocol v0.1.0)

## License

Dual license (Apache-2.0 OR MIT), at your choice:

- [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)
- [LICENSE-MIT](LICENSE-MIT)

© 2026 Flock VPN contributors
