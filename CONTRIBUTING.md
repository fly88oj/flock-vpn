# Contributing (CONTRIBUTING)

Welcome to contributing to Flock VPN. Before starting, please read [README.md](README.md) and the
overall design [docs/design.md](docs/design.md) (code comments link back to the design doc heavily
by `§ number` — find the corresponding §section before changing behavior, and keep design and
implementation evolving in sync).

## Environment requirements

| Item | Requirement |
|---|---|
| Rust | **1.98.1** (pinned by `rust-toolchain.toml` at the repo root; rustup auto-switches when you enter the repo) |
| Docker Desktop | container e2e / smoke tests (the compose topologies under deploy/; Linux containers; Windows/macOS hosts both fine) |
| Network | the first build needs GitHub access: `flock-protocol` comes in as a git dependency (tag `v0.1.0`); same for in-image builds |
| Platform | develop on any of Windows/macOS/Linux; CI gates with a three-platform matrix |

## Cloning

```bash
git clone https://github.com/fly88oj/flock-vpn.git
cd flock-vpn
cargo test --workspace --all-features    # the first run doubles as a gate self-check
```

The protocol library is a **standalone repository** (no longer vendored in this repo):

```bash
git clone https://github.com/fly88oj/flock-protocol.git   # needed only for co-debugging/protocol changes
```

Day-to-day work on the main repo needs no protocol-repo clone — the dependency is pinned by
Cargo.lock to a git rev (`?tag=v0.1.0#<rev>`).

## The usual gate commands

```bash
cargo fmt --all -- --check                                # format
cargo clippy --workspace --all-features -- -D warnings    # lint (warnings are errors)
cargo test --workspace --all-features                     # full test suite
cargo check -p flock-client --no-default-features         # headless compile surface (same as CI)
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs exactly these four: three-platform
(ubuntu-24.04 / windows-2025 / macos-14) test + check, with ubuntu adding clippy and fmt. Get
everything green locally before opening a PR.

## Protocol co-debugging: the [patch] workflow

Scenario: you changed a local [flock-protocol](https://github.com/fly88oj/flock-protocol)
checkout and want to verify the effect in the main repo immediately, **without waiting for the
protocol repo to cut a new tag**.

How: **temporarily** add a `[patch]` section to `.cargo/config.toml` at the main repo root. Note:
that file itself is checked in (its existing content = the getrandom rustflags for wasm32, which
must stay) — **do not commit the patch section**; remove it once verification is done (you can
also put it in a parent directory's `.cargo/config.toml` outside the repo; see "multi-repo
co-debugging" below):

```toml
# .cargo/config.toml — temporarily append next to the existing [target.wasm32-unknown-unknown] section
# (delete after co-debugging; do not commit! Adjust the path to your protocol clone location):
[patch."https://github.com/fly88oj/flock-protocol.git"]
flock-protocol = { path = "../flock-protocol" }
```

For multi-repo co-debugging (main repo + protocol + other consumers developed on the same
machine), put the same patch in the shared parent directory's `.cargo/config.toml` — cargo
discovers configs walking up from cwd, so running the gates inside any of the repositories picks
it up.

Key points:

- With the patch active, `cargo tree -p flock-server | head` should show flock-protocol pointing
  at the local path; after verifying, **delete the patch section and confirm `git diff .cargo/`
  is clean**, so what you commit is also green in a clean clone (pure git dependency).
- After a protocol change lands in the protocol repo and a new tag is cut, upgrade the main
  repo's dependency: change `tag =` in the three manifests (`crates/flock-sync`,
  `app/flock-server`, `app/flock-client`) and regenerate `Cargo.lock`, verifying **zero version
  drift** except the `flock-protocol` source entry.
- CI carries no patch: if a PR is green only under the local patch but red in CI, the protocol
  API change was most likely not synced to the main repo's call sites.

## Container e2e guidance

Precondition: Docker Desktop running. The two profiles (relay / direct) use non-conflicting ports
(27500/27501 vs 9443/9444), so you can **bring both stacks up in parallel and run all six smoke
tests with one command**:

```bash
# The relay profile needs the frp binary assets (the named build context):
mkdir -p .tmp && cd .tmp
# Download frp v0.71.1 linux_amd64 (github.com/fatedier/frp/releases) and extract it as
#   .tmp/frp_0.71.1_linux_amd64/ (containing frps/frpc)
cd ..

docker compose -f deploy/m2.yml        up -d --build   # frp relay variant
docker compose -f deploy/m2-direct.yml up -d --build   # direct variant (no prepare needed)

cargo test -p flock-server --test smoke -- --ignored            # all 6
cargo test -p flock-server --test smoke -- --ignored direct     # only the 3 direct ones

docker compose -f deploy/m2.yml        down -v
docker compose -f deploy/m2-direct.yml down -v
```

For the heavier multi-machine/multi-primary topologies (e2e.yml, multinode/), see [deploy/](deploy/)
and the manuals under [docs/manual/](docs/manual/); all `#[ignore]` tests are of the "actually
run against containers" kind and are not in CI (rationale in the ci.yml header comment).

## Commit style

**Imperative one-liner + scope prefix**, one line stating "what and why"; review/fix commits
cite their source. (Early history used Chinese imperatives; since the repo-wide English
migration, use English with the same shape — scope prefix, dense one-liner, source annotations
for review/fix items.) Example shapes:

```
build(deps): switch flock-protocol to a standalone-repo git dependency (tag v0.1.0) — …
deploy: adapt the six Dockerfiles and build-wasm.sh to git dependencies — …
test(sync): make the traffic-counter cross-server test explicit — wait for C's lease gossip to reach n0 before ingest (fixes flakiness under parallel load: …)
webui(ui): round-2 review item 8 desktop dashboard layout — cluster card and server zone side by side
```

Common scopes: `build` / `deploy` / `ci` / `docs` / `test` / module names (`sync`, `frpc`,
`webui`, `client`, `server`, `protocol`…). One logical item per commit — dependency switches,
build-surface adaptations, and docs each get their own commit; do not mix them.

## Pre-PR checklist

- [ ] `cargo fmt --all -- --check` green
- [ ] `cargo clippy --workspace --all-features -- -D warnings` green
- [ ] `cargo test --workspace --all-features` green (new behavior has matching tests)
- [ ] `cargo check -p flock-client --no-default-features` green (headless build not broken)
- [ ] Touching protocol interfaces → commit/cut a tag in the
      [flock-protocol](https://github.com/fly88oj/flock-protocol) repo first; the main repo's
      lockfile is synced with zero version drift
- [ ] Touching deployment/topology → the corresponding container e2e profile (previous section)
      has been run
- [ ] Touching behavior → the corresponding §section of docs/design.md is revised in sync (the
      numbering is cited by comments; do not delete it outright)
- [ ] Any temporary [patch] removed — buildable in a clean clone (pure git dependency)
- [ ] Commits split per the style above

For security-relevant work (new cryptographic paths, authentication/trust-anchor changes), please
read [SECURITY.md](SECURITY.md) and docs/research/crypto-2026.md first, and state the threat-model
impact in the PR description.
