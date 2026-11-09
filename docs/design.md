# Flock VPN Overall Design

- Designer: chief designer (dynamic workflow subagent); date: 2026-10-31
- Input materials (all read in full):
  `docs/research/verdict.md` (evaluation conclusions + upgradeList of 16 items, the hard input of this design),
  `docs/research/showroom-analysis.md`, `crypto-2026.md`, `compression-2026.md`,
  `vpn-mesh-2026.md`, `frp-compat.md`; showroom source code (`E:\Works\showroom`, read-only spot checks).
- Design vocabulary: deep modules / interfaces / seams / adapters / leverage (depth·locality), used per the
  glossary of `C:\Users\FLYING\.zcode\skills\codebase-design\SKILL.md`.
- Evidence discipline: every key claim in this document carries a source annotation (report §section /
  source `file:line` / commands and outputs executed in this session).
  Verifications performed first-hand in this session are in Appendix B; anything not executed is
  explicitly marked "not verified".
- Hard-constraint tracking: verdict §4 upgradeList has 16 items in total (P0-1..P2-13, ★VPN-14..16),
  none omitted; the placement cross-reference table is in Appendix A.

---

## 0. Design overview

In one sentence: **Flock VPN = an "upgrade-tiered extraction into a library" of the showroom protocol
layer + a long-lived tunnel session layer + access endpoints (Direct by default / FRP relay optional)
+ an openraft multi-primary active-active control plane**. The protocol layer is extracted into the
standalone library `flock-protocol` (deep module: seven small interfaces — file envelope / signature /
authentication / session / multiplexing / compression / trust anchor — hiding large implementations),
shared by the Flock VPN and showroom projects; the VPN-specific tun adaptation, frpc supervision, and
multi-primary sync live as "seams + adapters" in the Flock VPN workspace crates around the protocol
library.

**Hard constraint (user mandate, highest priority, overrides any statement to the contrary)**: Flock VPN
**must not be tightly bound to frp/chmlfrp**. frp serves only the "server has no public IP, or the
client cannot reach the server IP directly" scenario; when the server is directly reachable, **no
frp-related logic is executed** (no frpc subprocess, no config generation) — the default listener mode
is `Direct`, and `Frp` is an optional adapter, not a prerequisite (§2.1/§2.2/§3.11/§5).

Layering (bottom-up):

```
┌─ Client app (flock-client) ─────────────────────────────────────┐
│ tun(tun-rs) → PacketChannel → yamux streams ─┐                   │
│ routing (rtnetlink/wintun/VpnService)         │                   │
└───────────────────────────────────────────────┼───────────────────┘
                                                │ single TCP (ciphertext; path = access endpoint:
                                                │   Direct connection or via FRP relay)
┌─ flock-protocol (session layer) ────────────────┼─────────────────┐
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

Over an FRP relay only ciphertext is visible end to end (frp useEncryption/useCompression off by
default, frp-compat §0.1/S20; byte pass-through proven by T1/T2, including the full 0x00–0xFF byte
set and 0x16/0x17 first bytes); with Direct, the only thing on the wire is this protocol's ciphertext.

---

## 1. Shared protocol library: `flock-protocol`

### 1.1 Name and placement

- **crate name**: `flock-protocol` (lib name `flock_protocol`).
- **Placement**: workspace member of this repository, `E:\Works\FlockVPN\crates\flock-protocol`.
  Workspace layout:

  ```
  E:\Works\FlockVPN\
  ├── Cargo.toml            # workspace root (members below)
  ├── crates/
  │   ├── flock-protocol/    # ★ shared protocol library (referenced by both Flock VPN and showroom)
  │   ├── flock-frpc/        # frpc subprocess supervision, dual stack (Flock VPN only)
  │   └── flock-sync/        # openraft state machine + gossip leases (Flock VPN only)
  ├── app/
  │   ├── flock-server/
  │   └── flock-client/
  ├── deploy/               # Docker compose topologies + assertion scripts (§6)
  └── docs/
  ```

- Rationale: the protocol library must be independently referenceable by showroom (showroom is a
  separate repository `E:\Works\showroom`, whose workspace members = showroom-common/showroomctl/
  showroom, showroom/Cargo.toml:3 verified in this session), so it cannot be an internal module of
  the Flock VPN app; at the same time it is this repository's main deliverable (milestone M1), and
  placing it in this repository's `crates/` is the only placement that satisfies both "directory in
  this repository" and "referenceable across repositories".

### 1.2 How the two projects reference it (path / release strategy)

Dual-track referencing: zero friction during development, pinnable versions in production:

1. **Flock VPN (this repository)**: workspace path member dependency
   `flock-protocol = { path = "crates/flock-protocol" }`.
2. **showroom (external repository)**: git dependency pinned to a tag:
   `flock-protocol = { git = "<Flock VPN repository URL>", tag = "flock-protocol-v0.1.0", default-features = false, features = ["legacy", "wasm"] }`;
   during development, in the showroom repository's `.cargo/config.toml`, use `[patch."<git-url>"]`
   to override it with the local path `path = "../FlockVPN/crates/flock-protocol"` (standard patch
   workflow; showroom can co-debug locally without touching Cargo.toml).
3. **Release strategy**: phase one git+tag (sufficient, no release ceremony); if showroom CI or third
   parties need it, phase two publishes to crates.io (license Apache-2.0 OR MIT, consistent with the
   RustCrypto ecosystem, crypto-2026 §5).
   Version discipline: showroom-common's `pub use {ed25519_dalek, rsa}` "version funneling" semantics
   are preserved (showroom-analysis §2 re-export caveats) — flock-protocol continues to re-export its
   pinned dalek/x25519-dalek etc.; neither project may pull in separate versions.

showroom's migration surface (compatibility preserved, see §1.3): `showroom-common` becomes a thin
re-export over `flock-protocol` (all existing pub item signatures preserved), with zero changes to
showroomctl/showroom source. That migration itself is showroom-side work; this repository only
guarantees the interface is swappable; it is not in this design's delivery scope (this repository
does not write showroom code).

### 1.3 API design: compatibility surface + upgrade tiers

Design principle (SKILL.md): **small interface, large implementation**. Each submodule's interface is
"everything callers need to know" — including security preconditions (such as the envelope tier's
one-time k), made explicit in type names or documented contracts.

#### 1.3.1 feature split

| feature | contents | default | served audience |
|---|---|---|---|
| (default) | sig / pake / kem-hybrid / envelope-v2 / session / mux / compress / trust | on | Flock VPN, full set |
| `legacy` | envelope v1 (RSA-OAEP) seal/open, old SR-SIG1 constants | off | showroom transition |
| `anchor` | OPAQUE server identity signature layer (the login anchor of P0-5) | off (on in Flock VPN builds) | Flock VPN; showroom to follow later |
| `pq-sign` | ML-DSA-65 parallel public-key tier (ml-dsa 0.1.1, crate self-describes as unaudited, crypto-2026 §5) | off | optional |
| `wasm` | getrandom custom backend bridge and other showroom wasm constraints (showroom-analysis §6.3) | off | showroom |

#### 1.3.2 Compatibility surface (interfaces preserved for showroom, signatures unchanged)

All of the following come from the pub-surface inventory in showroom-analysis §2 (spot-checked
against source, consistent), preserved as-is:

- `sig`: `build_canonical / sign / sign_prehashed / verify / verify_with_hash`; the canonical
  seven fields and the `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>` wire format unchanged byte for byte
  (showroom-common/src/lib.rs:222-261 verified in this session); `SIG_WINDOW_SECS=300` (lib.rs:48).
- `envelope` v1 (`legacy`): `seal/open` and the `[384B RSA-OAEP header]||segment{[12B nonce][ct+tag]}`
  layout unchanged (lib.rs:376-412 verified in this session); length-invariant tests preserved.
- `pake`: OPAQUE suite (ristretto255+TripleDH+Identity KSF, opaque.rs:32-39 verified in this
  session), all login/reg/server_* functions, `SERVER_ID` export, external argon2id for rwd
  (opaque.rs:53-70 verified in this session: m=19456KiB/t=2/p=1, salt prefix `showroom-opaque-v1`).
- Utilities: `sha256_hex(_stream)`, `nonce_hex` (16 random bytes → 32 hex, lib.rs:75-79 — P2-13 doc
  correction follows the implementation), `write_private` (0600), `names::*`, constants
  `KEY_LEN/NONCE_LEN/TAG_LEN/SEG/WRAP_LEN`.
- Dependency generations (P1-6): aes-gcm 0.11.1 / opaque-ke 4.0.1 / ed25519-dalek 3.0.0 / rand 0.9
  (new code; rationale: a non-wasm VPN carries no 0.8 compatibility burden; 0.8.x is still maintained
  but the API generation gap must be repaid sooner or later, crypto-2026 §5 rand row).
  **Compatibility gate**: opaque-ke 3→4 must pass the "showroom fixed-vector sample interop" test
  (hard M1 gate, see §7); the OPAQUE message format is fixed by RFC 9807, so the upgrade is an
  implementation-generation change, not a protocol change (crypto-2026 §4.1).
- Erratum applied (P2-11): in-library comments reference RFC **9807** (opaque.rs:1 mistakenly wrote
  9380; existence verified in this session).

#### 1.3.3 Upgrade tiers (added/replaced per the evaluation conclusions)

**(a) `kem` — hybrid KEM module (P0-1, P0-7 PQ)**

```rust
pub struct HybridKeypair { … }          // X25519 static + ML-KEM-768 keypair
pub struct HybridPubkey { … }           // wire 1216B = 32(X25519) + 1184(ML-KEM ek)
pub struct SealedShared([u8; 32]);
pub fn encapsulate(pk: &HybridPubkey, rng) -> (SealedShared, HybridCt); // ct 1120B = 32+1088
pub fn decapsulate(sk: &HybridKeypair, ct: &HybridCt) -> Option<SealedShared>;
pub fn fingerprint(pk: &HybridPubkey) -> Fingerprint;                  // for pinning/display
```

- Combination rule: `shared = HKDF-SHA256(x25519_ss || ml_kem_ss)` (TLS hybrid approach, RFC 10024;
  frp-compat not involved).
- Size and latency basis (verdict §3.3 re-run round): ek=1184B/ct=1088B, hybrid ciphertext 1120B,
  hybrid pubkey 1216B, encap+decap <0.1ms. Implementation uses ml-kem 0.3.3 (pure-Rust FIPS 203)
  + x25519-dalek 3.0.0; **liboqs is not used** (officially discouraged for production,
  crypto-2026 §5).
- RSA compatibility tier: the `legacy` feature preserves v1 read/open; the "transitional dual
  encapsulation" evaluation conclusion is **not to provide it** — a v1 reader parses the header by
  fixed 384B length and cannot parse any new layout containing hybrid ciphertext, so dual
  encapsulation cannot deliver "old and new readers both decode"; the real transition = during the
  migration window showroom keeps writing v1, and v1 stays forever readable (P0-1's "preservable"
  requirement is satisfied in this form; rationale consistent with the header layout in
  showroom-analysis §4.1).

**(b) `envelope` v2 — segment-sequence AAD (P0-3) + hybrid encapsulation**

```
header: [1B ver=2][16B envelope_id][32B eph_x25519][1088B ml_kem_ct]   = 1137B
segment: [12B nonce][AES-256-GCM ct‖tag], AAD = ver‖envelope_id‖seg_idx‖is_final
```

- The one-time k is derived from the hybrid KEM (a fresh ephemeral share per envelope ⇒ **one-time
  envelopes gain forward secrecy**, verdict §3.3).
- The envelope tier preserves the **documented precondition** of "one-time k + fresh random 96-bit
  nonce per segment" (messages per key = n/4MiB ≪ 2^32, within the SP 800-38D random-IV bound,
  verdict §3.4); AAD binds the segment sequence + envelope ID + final flag into the authentication,
  preventing segment reordering/splicing (missing in v1; verified in this session at lib.rs:396-411,
  the encrypt call takes only nonce+plaintext).
- `open_v1` read-only compatibility (`legacy`). The zstd-19 bulk tier (P1-7) remains a caller-side
  pipeline composition; the library only adds the `seal_v2_compress(policy)` convenience tier.

**(c) `session` — tunnel session (the core carrier of P0-2, P1-8, P1-10)**

Deep module: callers see only `Tunnel`; inside hides the full discipline of handshake / record
layer / anti-replay / rekey / keepalive / forgery limit and disconnect.

```rust
pub struct TunnelConfig {
    pub aead: AeadPreference,        // primary AES-256-GCM (aes-gcm 0.11.1); fallback XChaCha20-Poly1305 /
                                     // AES-256-GCM-SIV (P1-8, negotiated by intersection)
    pub keepalive: Duration,         // default 10s (WireGuard KeepaliveTimeout, crypto-2026 §6)
    pub rekey_after: (u64, Duration),// default (2^60, 120s) dual threshold
    pub reject_after: (u64, Duration),// default (2^64−2^13−1, 180s) hard reject
    pub forge_limit: u32,            // forgery-attempt limit that disconnects (default 100, P0-2)
}
pub enum LookupVerdict { NotFound, Revoked { since_epoch: u64 }, Active(DeviceRecord) }
pub trait DeviceDirectory: Send + Sync + 'static {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict>;  // must be async:
        // a linearizable read via the Raft leader is a network round trip (§4); both NotFound and
        // Revoked must reject the handshake with timing aligned (to prevent online device-enumeration
        // probing).
}
pub async fn initiate(io: TcpStream, device: &DeviceStaticKeys,
                      expect_server: &ServerPin, cfg: TunnelConfig) -> Result<Tunnel>;
pub async fn respond(io: TcpStream, server: &ServerIdentity,
                     dir: impl DeviceDirectory, cfg: TunnelConfig) -> Result<Tunnel>;
impl Tunnel {
    pub async fn open_stream(&self, prio: Prio) -> io::Result<Stream>;     // logical stream (runs inside yamux)
    pub async fn open_packet_channel(&self) -> io::Result<PacketChannel>;  // TUN framing (VPN-14 interface)
    pub fn stats(&self) -> SessionStats;                                    // epoch/counters/replay rejections
}
```

- **Implementation contract of the lookup seam** (prevents reconnect storms from amplifying into the
  Raft leader; details in §4 "Reads and caching"): the server-side implementation of the handshake-side
  `DeviceDirectory` uses two levels — "record cache + revocation epoch (revocation_epoch, advanced
  automatically as the Raft log applies)" — epoch unchanged and cache hit ⇒ answer locally; epoch
  changed or miss ⇒ linearizable read. After a relay link failure, an N-client reconnect storm hits
  the local cache entirely when there are no revocations, never touching the leader.
- **Handshake (P1-10), two forms** — whether the first connection has server static material decides
  the round-trip count (pinning model = the cluster root pubkey anchors the full set of server
  material, §1.3.3f):
  - **Pinned form (invite file or existing pin; the norm, 1-RTT, Noise IK structure)**:
    I1 = version + algorithm set + X25519 ephemeral + ML-KEM-768 ct (1088B, encapsulated to the
    **target server's** — i.e. the ServerEntry this endpoint maps to in the ClusterDirectory —
    **static ML-KEM pubkey**) + "device static X25519 pubkey + device Ed25519 pubkey + **device
    signature**" encrypted with a key derived from HKDF(x25519(e,s_srv)‖mlkem_ss); R1 = server
    ephemeral + **server identity key's signature over the transcript (P0-5, tunnel side)** +
    mutual key confirmation. The first frame after the handshake can already carry data.
    `initiate`'s `expect_server: &ServerPin` = (cluster_root_pub + the target endpoint's
    ServerEntry) — switching endpoints = swapping the ServerEntry, with material from the invite
    file or a root-signed directory refreshed via dir_pull, so **any endpoint is 1-RTT** (the
    implementation basis of A5/A15).
    - **Signature coverage contract (prevents UKS / unknown key share)**: the device Ed25519
      signature covers = **all fields sent in I1** (including both ephemeral shares and the
      algorithm set) + protocol context (cluster_id, expected server identity pubkey, session
      purpose label); the server identity signature covers = I1‖R1, the full transcript. M1 vectors
      must include "tamper with context / swap server identity → signature verification fails"
      cases.
  - **TOFU first-connect bootstrap form (no cluster material at all, once only, 2-RTT)**:
    I0 = version + algorithm set + client X25519 ephemeral (at this point there is no server static
    pubkey, so nothing can be encapsulated/encrypted; sent in the clear); R0 = that server's
    **enrollment credential public part** (server_id + identity_pub + static_hybrid_pub in full
    + access_endpoint) + **cluster root pubkey** + the server identity's signature over I0‖R0.
    Client verifies: the enrollment credential = the root pubkey's signature over the ServerEntry ⇒
    the material chain is trustworthy; it then displays the **cluster root fingerprint**, and after
    the user confirms, **pins only the root pubkey** (cluster_id → root_pub), and immediately sends
    I1/R1 per the 1-RTT form using that ServerEntry. Material for other endpoints / new servers is
    obtained via the control flow `dir_pull` (root-signed ClusterDirectory, dir_version
    monotonically increasing) — **from then on every endpoint is 1-RTT and I0 never appears again**.
    - **Residual risk made explicit**: TOFU does not defend against an online MITM on the first
      login — on first connection an attacker can self-sign a "root pubkey + credential chain" and
      the client pins the attacker's root (the same class of limitation as SSH known_hosts);
      organizational deployments must use the strong invite-file path (§1.3.3f).
  - Sessions are indexed by the peer's static pubkey ⇒ the endpoint (relay entry) can change while
    session semantics continue (roaming model, vpn-mesh §2 / crypto-2026 §6). Reconnect = **a
    brand-new handshake**; no PSK resumption (TLS resumption would bind the old session's security
    context and the binder is not dictionary-resistant, crypto-2026 §6).
- **Record layer (P0-2)**: `[u32 len ≤1MiB][type][AEAD(payload)]`, nonce = 32-bit zero ‖ 64-bit LE
  counter (WireGuard shape); independent counter and key per direction; **random 96-bit nonces are
  forbidden for long sessions** (the envelope-tier precondition does not apply to the tunnel tier —
  the two tiers are kept separate and each documented, verdict §3.4).
- **Anti-replay**: with TCP's in-order delivery the receiver checks the counter is strictly
  increasing; duplicate/regression is rejected and counted as forgery; the 2048 sliding-window
  structure is retained for a future UDP direct path (crypto-2026 §2.2 explicitly notes the window
  can shrink under TCP and cross-connection replay is backstopped by handshake freshness — recorded
  as-is, not overstated).
- **rekey**: REKEY_INIT/RESP runs on the control flow (fresh hybrid KEM, cost <0.1ms); after the
  epoch switch the counter resets with the new key; when `reject_after` triggers, keys are zeroed
  and the link dropped.
- **AEAD fallback negotiation (P1-8)**: XChaCha20-Poly1305 on hosts without AES hardware;
  AES-256-GCM-SIV for misuse-resistance / copy-sensitive scenarios (fastest on this machine at
  5.09–5.27 GB/s, verdict §0 re-run).

**(d) `mux` — multiplexing and EOF semantics (P1-9, VPN-16 protocol side)**

- Multiplexer: **rust-yamux 0.14.1** (the hashicorp-spec implementation, active 2026-09-21,
  vpn-mesh §4.1 table). yamux itself = length-prefixed frames + stream IDs + explicit FIN/EOF +
  ping keepalive + flow-control backpressure — exactly the full semantics P1-9 lists, **do not
  reinvent**. Link order: TCP → SecureStream (record-layer encryption) → yamux → logical streams.
  yamux runs inside the encryption ⇒ stream counts / stream metadata are invisible to the relay.
- **TCP half-close is forbidden as a dependency** (frp T3 finding: after SHUT_WR the return path is
  0/65536 and the whole chain tears down, frp-compat §1.5) — one-directional end is always a yamux
  FIN; keepalive uses yamux ping (default 10s; the P1-10/VPN-16 application-layer heartbeat, which
  doubles as relay liveness probing). Any first byte value is compliant (no TLS probing at the user
  port, proven by T2).
- The control flow (stream 0) is scheduled at high priority; `PacketChannel` = the TUN-packet
  framing (`[u16 len][ip packet]`, boundary-preserving), the library-side interface VPN-14 requires.

**(e) `compress` — compression tiers and hardening (P0-4, P1-7)**

```rust
pub struct CompressPolicy { pub mode: Mode /* Off (default) | Interactive | Bulk | Archive */,
                            pub padding: PadPolicy, pub dict: DictRef }
pub fn compress_frame(p: &Policy, bytes) -> Frame;   // frame header: compression flag + original length
```

- **Off by default**; enabled per-policy / per-stream (the VORACLE/CRIME/BREACH preconditions hold
  in Flock VPN — an FRP relay is exactly a length observation point, compression-2026 §3.2); when
  enabled, output padding is configured (starting at 16B multiples, tunable bucketing).
- Tiers (compression-2026 §0/§2 measured): `<128B` pass-through (40B anti-expansion 122.5%, 120B
  zero gain); `128B–1.5KB` zstd-1 + 4–16KB dictionary (synthetic-template training, dictID handshake
  negotiation, version strictly matched; 120B→28–30% and faster); `>1.5KB` zstd-1 in 16–64KB chunks
  + 5–10ms flush (64KB chunks lose only 0.2pp); level 19 kept only for the Archive tier; lz4_flex
  0.14 as the CPU-constrained fallback; context reuse (measured 3×).
- **Non-expansion fallback is a MUST** (RFC 3173 §2.2): if a trial compression does not shrink,
  emit plaintext, and after consecutive failures adaptively stop trying.
- Compress-then-encrypt order unchanged (RFC 3173 §1); compression happens inside the record-layer
  payload.

**(f) `trust` — first-login trust anchor (P0-5)**

Pinning model finalized (the ruling of the third review round's blocking item; conclusion first,
then structure): **the client anchors the "cluster root pubkey" and holds the root-signed access
material for the full set of servers (option ②)**. Of the three reconciliation options — ① the
cluster shares one set of server static keys: **rejected**, it conflicts with §4's admission model
of "each server has its own identity/static_hybrid keys" and makes VPN-15's "per-server independent
encapsulation / rewrap permission point" fake (with a shared HybridKeypair, one server's leak
decrypts all OPAQUE encapsulations); ③ switching endpoints falls back to the 2-RTT bootstrap:
**rejected**, reconnect/switch is a routine path and a 2-RTT + fresh manual confirmation every time
is unacceptable; ② the client holds the full set of material, vouched by a single root signature:
**adopted** — the "endpoint → server material" mapping itself is signed by the cluster root key
(the origin of MITM defense is exactly this signature); a single server rotating static keys only
needs a root-signed new entry and a client-side directory refresh, without touching other
endpoints' pins.

```rust
pub struct ServerIdentity { ed: VerifyingKey /* + optional ml_dsa */, … } // long-term signing identity (per server)
pub struct ServerEntry {                // = the "public part" of §4's enrollment credential; one credential,
                                        //   two uses: server mutual authentication (§4) / client access
                                        //   material (here)
    pub server_id: ServerId,
    pub access_endpoint: SocketAddr,    // that server's **access endpoint**: Direct form = direct
                                        //   address (public/internal host:port, zero frp), Frp form =
                                        //   the relay user port (frps host:port) — the two forms are
                                        //   indistinguishable to the client; both are dial targets
                                        //   (renamed from relay_endpoint in round four; semantics widened)
    pub endpoint_form: Direct | Frp,    // form annotation (client uses it for display/diagnostics only;
                                        //   routing logic unchanged)
    pub identity_pub: VerifyingKey,     // that server's identity Ed25519 pubkey
    pub static_hybrid_pub: HybridPubkey,// that server's static hybrid pubkey (1216B; I1's ML-KEM ct
                                        //   must be encapsulated to it)
}
pub struct ClusterDirectory {           // endpoint list and credentials signed together in one document,
                                        //   preventing "real list, fake entry" splices
    pub cluster_id: ClusterId,
    pub servers: Vec<ServerEntry>,
    pub dir_version: u64,               // increasing; single-server key rotation ⇒ root-signed new
                                        //   directory ⇒ client dir_pull refresh
}
pub struct InviteFile {                 // v3: cluster directory + one-time consumption credential,
                                        //   one root signature
    pub directory: ClusterDirectory,
    pub cluster_root_pub: VerifyingKey, // cluster root pubkey (the public half of §4's root key; the
                                        //   trust anchor proper)
    pub expiry: DateTime,               // default 7 days (configurable)
    pub invite_id: Uuid,                // goes into the Raft state machine for single consumption (below)
    pub root_sig: Signature,            // cluster root key signature covering all fields above
}
pub struct PinStore { … }               // pin granularity = (cluster_id → cluster_root_pub)
pub fn first_pin(cluster_id, root_pub) / verify_pinned(cluster_id, root_pub) -> Verdict;
                                        // change → explicit warning; server-level material gets no
                                        // separate TOFU (vouched by the root signature)
pub fn load_invite(path) -> Result<InviteFile>;
```

- **Two landing paths**: ① **invite-file strong path** (modeled on innernet's one-time invite,
  vpn-mesh §2/S15): v3 contains the **full set of server access material (ClusterDirectory) + the
  cluster root pubkey**, signed together once by the root — an invite-holding client reaches any
  endpoint (including A5's switch to server-b and A15's migration to server-a) directly at 1-RTT,
  fully bypassing TOFU; ② TOFU path (personal self-hosting): first connection is the 2-RTT bootstrap
  (§1.3.3c); the client **pins only the cluster root pubkey** (displays the root fingerprint,
  confirmed once), and server material is root-verified via the enrollment credential chain;
  thereafter every endpoint (including new servers, via dir_pull of the root-signed directory) is
  1-RTT. The server identity key additionally enters OPAQUE login-finish (`anchor` feature:
  signature covers SERVER_ID‖user‖ke2 transcript‖bind_token).
- **The life of an invite file (one-time semantics, modeled on innernet's "invite file (one-time)",
  vpn-mesh §2 table)**: generation (admin operation, root-key context) → distribution (0600 file,
  treated as a credential) → **redemption = Raft admin operation `redeem_invite(invite_id)`:
  duplicate check (used? reject) + revocation check + expiry check → mark used → create the
  user/device and assign a VIP**; a second redemption of the same invite_id must be rejected;
  `revoke_invite(invite_id)` (a root-key-signed admin operation) can revoke an unredeemed invite. A
  leaked redeemed file = useless (used); a leaked unredeemed file = can be redeemed once ahead of
  the owner within expiry (accepted boundary: invites are managed as one-time credentials, default
  7-day expiry, written into the deployment docs).
- **Account provisioning flow (where user accounts come from, completing the alignment with
  showroom semantics)**: a user account is created by the admin via `user-add` or on invite
  redemption; the password is then set via OPAQUE registration (pw-begin/pw-commit); device keys
  (X25519 + Ed25519) are generated client-side locally, with pubkeys registered through the
  logged-in state (a key-bind analogue, covered by the server identity signature); a device enters
  the registry = `(DeviceId, owner, VIP, static pubkey set, status)`. That is: **the invite file
  decides "who may join the network" (root-signed), OPAQUE decides "who is who" (account password),
  device keys decide "which machine"** — three separations.
- **Residual risk made explicit (never silent)**: TOFU does not defend against an online MITM on the
  first login (the first connection can be wholly impersonated, pinning the attacker's key; the
  subsequent bind_token hijack-and-takeover still applies — the same class of limitation as SSH
  known_hosts; verdict §3.9's attack is only partially closed); organization-facing deployment docs
  must mark the invite file as the recommended path.
- Basis: verdict §3.9 (the bind_token hijack takeover attack already declared at SPEC.md:285-287;
  `SERVER_ID` is a literal, not a key, opaque.rs:42 verified in this session); the RFC 9807 aPAKE
  model requires the client to hold an authenticated server identity.

**(g) `sig` tier (P2-12)**: the SR-SIG1 wire format is unchanged; adds `KeyProfile` (kid→algorithm
dispatch: Ed25519 primary + an ML-DSA-65 parallel public-key slot under `pq-sign`).

**(h) `pake` tier (P2-11)**: versioned argon2id parameter profiles
(`Profile::Owasp19MiB` (showroom-compatible default) / `Profile::Rfc9807High` (m=2GiB,t=1,p=4 high
tier)); the profile id goes into the registration record to prevent cross-tier drift; OPAQUE itself
unchanged (adopt, verdict §3.1).

### 1.4 Identical behavior under original FRP and ChmlFrp (argument)

The protocol library assumes only that the underlying thing is "a reliable, ordered, byte-transparent
TCP stream that may hard-drop as a whole":

1. **Byte transparency proven**: on original v0.71.1, a round trip of all 256 byte values + 1MiB
   random has matching sha256; first bytes 0x16/0x17 cause no interference; no framing injection
   (frp-compat §1.5 T1/T2); ChmlFrp's data plane is line-for-line identical to original v0.51.2
   (the fork diff touches neither `pkg/msg` nor the data path, frp-compat §2.3) ⇒ both relays carry
   the same ciphertext byte stream.
2. **No relay-specific behavior is relied on**: half-close forbidden (use yamux FIN, R3); no
   multi-tunnel reliance (a single frp tunnel carries all sessions, yamux multiplexes, R11 — a hard
   requirement under ChmlFrp's free tier's 4-tunnel limit); 10s application-layer heartbeat liveness
   (the data plane has no idle timeout but node restarts / NAT hard-drops exist, R5); link loss =
   reconnect with a brand-new handshake (R6).
3. **The differences between the two relays are isolated inside `flock-frpc`** (§5): the protocol
   library proper is unaware frp exists — its seam is `TcpStream`; direct / original relay / ChmlFrp
   relay are three adapters on the same seam, and the behavioral differences reduce to RTT and node
   rate limits (ChmlFrp's server-enforced 8–32Mbps, frp-compat §2.3).

---

## 2. Flock VPN overall architecture

### 2.1 Deployment form (modeled on Tailscale's "centralized control plane, distributed data plane",
vpn-mesh §2)

- **Access endpoint model (hard constraint landed, highest priority)**: every server exposes
  **one access endpoint**, in one of two forms, configured by `server.toml`'s `listener.mode`, with
  **`Direct` as the default**:
  - `Direct` (default): the server listens directly on a public/internal address and clients TCP
    dial it — **zero frp logic** (no frpc subprocess, no config generation, no flock-frpc assembly);
  - `Frp(RelaySpec)`: chosen only when "the server has no public IP or the client cannot reach the
    server IP directly" — `flock-frpc` supervises frpc (§3.9/§5), exposing the listen port through
    a relay node as a user port.
  The two forms are fully isomorphic to the protocol layer (both are "one TCP byte stream", §1.4);
  a single cluster may mix them per machine (server-a direct, server-b via relay, server-c direct).
  Server interconnects (Raft + gossip + cross-server forwarding) likewise go direct or via their own
  access paths, running the same E2E session protocol with the **server-server profile** (mutual
  enrollment-credential authentication, §4 admission).
- **Servers ×3 minimum** (Raft odd voter count, tolerating 1 failure): each exposes one access
  endpoint per the above; only machines without public IP / direct reachability attach to an FRP
  relay node (a ChmlFrp node or self-hosted original frps) and run `flock-frpc`.
- **Clients ×N** (Windows/macOS/Linux first; Android/iOS seam reserved): `flock-client` dials the
  access endpoints in the ClusterDirectory — **a direct address or a relay user port is
  indistinguishable to the client** (both are TCP dial targets; in the tcp proxy form the client
  never needs frpc anyway, frp-compat §1.1 proxy model), holding "the access endpoint list + liveness
  probing and switching"; any server gives the same access experience.
- Data plane: client ↔ server session tunnels (first version hub-and-spoke, peers routed via the
  server; no P2P direct connections, vpn-mesh §6 states the first-release strategy explicitly); in
  any link form a third party sees only this protocol's ciphertext.
- Virtual network: `100.64.0.0/10` (RFC 6598 CGNAT range; Tailscale/NetBird dual precedent,
  vpn-mesh §3.1), with several internal /24s reserved; allocation is decided by the Raft state
  machine (strongly consistent collision prevention); MTU 1280 (same as Tailscale, the IPv6 floor,
  vpn-mesh §3.2).
  **IP reuse policy (M7 revision, replacing the earlier blanket "disable without deleting, no IP
  reuse" wording)**:
  - **Revoked → the IP is never reused** (unchanged; innernet precedent, security first,
    vpn-mesh §3.1); Disabled likewise: the row is kept, the VIP is not reclaimed.
  - **Offline past the retention period → Expired + VIP returned to the allocation pool** (new,
    M7): a reaper moves devices that are "offline > retention period" to Expired via a Raft admin
    operation and releases their VIP back into the allocation pool — a new device may then be
    assigned that VIP; **the expired record itself stays on the roster** (auditable), while roster
    queries exclude Expired. Within the window, a reconnecting same device keeps the same IP (a
    non-expired row is untouched). Retention period = server.toml `peer_retention_days` (default 30
    days; **0 = never expire**, compatible with the old behavior). Expired ≠ Revoked: both block
    the handshake, but the states are distinguishable (different audit/roster semantics — Expired is
    time-based retirement, Revoked is security disposition).

### 2.2 Server (`app/flock-server`)

Responsibility chain: **access → authentication → registry → session → forwarding → sync**.

- Listener (TCP :9443): one E2E session per inbound connection (`session::respond`). Exposed form =
  `server.toml`'s `listener.mode` (§3.11 ListenerMode seam) — **`Direct` default** (direct listen,
  zero frp logic) / `Frp(RelaySpec)` (the flock-frpc Supervisor path); **the Direct-mode code path
  never touches flock-frpc** (no Supervisor instantiation, no config generation, no subprocesses
  started).
- Control flow (yamux stream 0, postcard-encoded messages): OPAQUE login (`anchor` on: identity
  signature + TOFU/invite pinning verification) → session ticket issuance (short-TTL local ticket;
  the ticket key root comes from Raft, delegated per VPN-15); device registration / config pull
  (network view: peer VIPs/pubkeys/routes).
  - **Mandatory ticket contract (the closure precondition for the SR-SIG1 cross-server replay
    surface; must be written as an interface contract)**: all **state-changing** requests protected
    by SR-SIG1 must carry a valid session ticket (bound to device + revocation_epoch), and the
    validation order = ticket validity (signature + TTL + epoch + revocation) **before** nonce
    accounting; the effective replay window = min(±300s, ticket TTL). Without this precondition,
    the same signed request replayed to another server that has not seen the nonce would succeed
    (the ticket key root is Raft-shared and any server can verify; the only things stopping it are
    "ticket TTL + epoch invalidation").
- Device management: device = `(DeviceId=Ed25519 fingerprint, owner, VIP, static pubkey set,
  status, hostname, expired_at)` (hostname/expired_at added by M7, §7-M7), all inside the
  `flock-sync` strongly consistent state machine.
  - **Revocation propagation bound (numbers fixed; A6 is verifiable against this)**: revocation = a
    Raft commit; each server, in **its own log apply callback**, (a) advances revocation_epoch and
    invalidates the record cache, (b) kills that device's local session, (c) rejects its tickets (a
    ticket whose epoch < current epoch is rejected). That is, "kicking sessions" needs no extra
    broadcast — Raft replication itself delivers the revocation to every server's state machine.
    Timing budget: healthy cluster (relay RTT ~100ms, heartbeat 500ms) commit→apply ≤2s + event
    margin ≤1s + slack 2s ⇒ **A6's ≤5s holds**; the 60s ticket TTL hard-caps cross-server replay.
    Online leases additionally have event push (≤1s) + 5s anti-entropy (§4).
- **Data plane (including cross-server forwarding — a necessary component of "any server gives the
  same access experience")**: the server itself is also a peer (has tun + VIP 100.64.0.1…).
  Forwarding decision order:
  0. **Source VIP binding check (step 0, ahead of all forwarding logic)**: every IP packet read
     from the PacketChannel must have a **source address equal to the registered VIP of that
     session's device** (session DeviceId ↔ src VIP binding); mismatch ⇒ drop + count + alert on
     excess / drop the session. Note: §2.3's `rp_filter=1` only acts on inbound kernel-network-
     interface traffic and **does not apply** to userspace IP packets arriving over yamux streams —
     this check is the application-layer "per-node ingress filtering enforcement policy"
     (Tailscale/innernet precedent, vpn-mesh §2 borrowing point 3). Without it, a malicious device
     holding a valid session could send packets with any peer's VIP as source (identity framing /
     reflection / future ACL total bypass). The ForwardEnvelope `src_dev` field is likewise
     cross-checked against the inner packet's source address (checked once at the receiver and once
     at the sender).
  1. Destination VIP → device ownership: look up the **local lease table** (gossip). **The single
     source of truth for a device's current location = the lease domain** (each server
     authoritatively publishes "the devices connected to me" + lease TTL 30s + event push ≤1s + 5s
     anti-entropy); **NetState (Raft) stores only static registration info** (device/VIP/pubkey/
     status/invite-consumption records), **not "which server a device is currently on"** — access/
     switching are high-frequency events; writing them to Raft in real time would turn reconnect
     storms into write storms (R18 only guards against read storms), while not writing in real time
     leaves the mapping stale and the fallback necessarily wrong again: two sources of truth are
     unacceptable; one source is fixed.
  2. Owned locally ⇒ deliver directly into that session's PacketChannel (same-server path).
  3. Owned by another server ⇒ **cross-server forwarding**:
     `ForwardEnvelope{ver, src_dev, dst_dev, origin_server, hop=1, payload=IP packet}` is sent on a
     dedicated FRWD stream of the server-interconnect E2E session (the outer layer has
     server-to-server encryption; the inner IP packet is plaintext at this point — threat model in
     §2.5). At the receiver: if dst is in a local session ⇒ deliver; otherwise reply `NOT_HERE` to
     the origin (**second-hop forwarding forbidden**, hop=1 prevents loops).
  4. **Fault-tolerance policy for lease miss / staleness** (vpn-mesh §5.2 explicitly calls this a
     policy decision; fixed here): when a device has just migrated to another server, packets within
     the old-lease window go to the old server → the old server replies NOT_HERE → the origin sends
     a **one-shot location query** (LocationQuery: ask the servers holding a lease for that device
     in their lease tables, or fan out to ≤3 interconnected servers, "who is hosting dst?") and
     redirects once; still failing ⇒ **drop the packet + best-effort ICMP unreachable** (no
     broadcast, no cached retries — VPN packet loss is recoverable by upper layers; this avoids
     state bloat in the forwarding plane). Device-online/migration event push (≤1s) usually makes
     this window shorter than the lease TTL.
  - Linux routing is configured via rtnetlink (VPN-14).
- `flock-frpc` supervision (§5): config generation + process supervision + health probing.
- **Web UI admin plane (§7-M8)**: in-process embedded HTTP (dual bind on `127.0.0.1:port` + the
  local tun VIP:port, default 9800, no LAN/public binding) — admin login account + Dashboard;
  authentication = OPAQUE (pake reuse) + admin role + HttpOnly session cookie; each server in the
  cluster embeds its own instance, and data is naturally consistent via Raft/leases/EWMA (reachable
  on any VIP).

### 2.3 Client (`app/flock-client`)

- Access: the access endpoint list (from the root-signed ClusterDirectory's `access_endpoint` —
  a direct address or a relay user port, indistinguishable) → TCP dial → `session::initiate`
  (with ServerPin); on disconnect, exponential backoff (starting at 5s + jitter, following
  wireguard-go's RekeyTimeout cadence, crypto-2026 §6) + endpoint round-robin switching.
- tun data plane: `tun-rs 2.8.16` (the fullest platform matrix, highest activity, built-in
  wintun/iOS fd/Android establish examples, vpn-mesh §1.2) creates the TUN (MTU 1280); IP packets ↔
  `PacketChannel`. **Seam**: the `TunDevice` trait (open/read/write/close); platform adapters =
  tun-rs native, Android `VpnService` fd injection + `protect()`, iOS `NEPacketTunnelProvider` fd
  injection (vpn-mesh §1.1: neither platform has a native equivalent API; the fd must be injected
  by the upper framework — this is a seam the library must leave).
- Routing: Linux rtnetlink 0.23.0 (/16 pool pointing to TUN + rp_filter=1 reverse-path filtering,
  innernet recommendation, vpn-mesh §3.3); Windows uses the wintun routing API; Android goes
  through `VpnService.Builder` routing parameters.
- TCP-over-TCP mitigation: per-inner-stream rate limiting and queue management (avoiding
  amplification contention across multiple inner streams; the weak-network collapse mechanism is in
  vpn-mesh §3.2); P2P direct connections go on the long-term roadmap (self-hosted node xtcp); not
  in the first version.

### 2.4 Keys and session lifecycle

| Stage | Keys / credentials | Lifecycle |
|---|---|---|
| Bootstrap | Invite file v3 (cluster root pubkey + root-signed ClusterDirectory with the full set of server material + one-time invite_id), or after TOFU first-connect 2-RTT bootstrap, the **pinned cluster root pubkey** | Root pubkey change = explicit warning + manual confirmation; single-server key rotation = root-signed new directory entry + dir_pull refresh (legitimate changes do not warn) |
| Login | OPAQUE (the password never goes on the wire) + server identity signature | Re-executed on every login; success → session ticket (short TTL, issued locally) |
| Device registration | Device static keys (X25519 for sessions + Ed25519 for identity, generated on the client and never leave the machine) | Registered into Raft; revocation invalidates it network-wide |
| Tunnel session | 1-RTT handshake derives bidirectional keys (hybrid KEM ⇒ forward secrecy + PQ) | rekey dual threshold 2^60 packets/120s; 180s/2^64−2^13−1 hard reject; reconnect after link loss = brand-new handshake |
| Server identity key | Ed25519 (optional parallel ML-DSA) | Long-term; rotation = new key + old-key parallel period + client re-pinning flow |
| OPRF key | OPAQUE server key (inside the Raft state machine, sealed by encryption to each server's hybrid pubkey) | Persistent (rotation invalidates all pass.opaque — same semantics as showroom, showroom-analysis §5) |
| Shared secret sealing | In-state-machine secrets sealed per server (envelope v2 to each server's HybridPubkey) | "Per-server independent keys / per-rotation re-wrapping" permission point: adding a server = re-wrap (VPN-15) |

Forward-secrecy chain: handshake one-time DH/KEM share → rekey every 120s (or 2^60 packets)
swaps in a fresh share → old keys erased.
Replay-state ownership by tier (verdict §3.6 multi-primary active-active constraints): **tunnel
data plane** = per-session counter (owned by the single server the session belongs to; no sharing
needed); **control-plane critical one-time operations** (bind_token/ticket reissuance) = Raft
linearizable duplicate check (low frequency; write amplification acceptable); **SR-SIG1 request
nonces** = local ±300s window + the **mandatory ticket contract** (§2.2: state-changing requests
must carry a valid ticket, ticket validation precedes nonce accounting, effective replay window =
min(±300s, ticket TTL 60s)) narrowing the cross-server replay surface (recorded as-is:
high-frequency per-request nonces are not strongly consistent; they are closed by ticket TTL — this
is an engineering trade-off).

### 2.5 Threat model boundaries (explicit statement, to prevent security claims from being misread as peer-level E2E)

1. **Cross-peer traffic is plaintext on the access server**: the first-version hub-and-spoke
   (§2.1/§2.2) means client↔client traffic is **decrypted and then forwarded** on the access server
   (the cross-server path has server-to-server encryption on the outer layer, but inside each
   server it is still plaintext). This is **fundamentally different** from Tailscale's "the
   coordination server cannot decrypt" property (vpn-mesh §2/S18): any enrolled server can observe/
   tamper with all cross-peer traffic it forwards. Mitigations: server host hardening + admission
   control (§4); **long term**: a peer-to-peer end-to-end overlay encryption layer (client-client
   inner session, the server degrading to a blind relay), on the roadmap but out of scope for this
   design.
2. **Any server can offline-dictionary all passwords**: the OPRF key is sealed per server (§2.4
   table) ⇒ compromising any enrolled server yields the OPRF key and enables offline dictionary
   attacks on all user passwords (within the OPAQUE aPAKE model, the OPRF key holder inherently has
   this ability — same semantics as showroom, showroom-analysis §5; the argon2id tier is the only
   speed bump). Mitigations: server keys 0600/memory-resident + admission red lines (§4: a fake
   node cannot obtain the key); **long term**: OPRF key thresholding (quorum unsealing). This is an
   accepted boundary, written into the deployment docs.
3. **TOFU does not defend against an online MITM on first login** (§1.3.3f residual risk):
   acceptable for personal self-hosting; organizational deployments must enforce the invite file.
4. **Relay and link**: FRP relay / link observers see only ciphertext and lengths (length
   side-channel countermeasures are in the compression tier P0-4); the ChmlFrp panel credential
   channel risk is in §5/R table (R20).

---

## 3. Module breakdown (ModuleSpec)

Each spec: **interface** (everything callers need to know) · **seam** (where the interface lands,
who can swap it) · **implementation points**. Deep-module checks: interface method count ≤5,
security preconditions in types/contracts, the deletion test (removing it would push the complexity
back onto N callers).

### 3.1 `flock-protocol::kem` (hybrid KEM primitive)
- **Interface**: the three types `HybridKeypair/HybridPubkey/HybridCt` + the three functions
  `encapsulate/decapsulate/fingerprint` (§1.3.3a).
- **Seam**: the KEM algorithm slot — an internal `trait KemGroup` seam (one implementation each for
  X25519 and ML-KEM-768); a future switch to ML-KEM-1024/pure-PQ touches no callers.
- **Implementation points**: ml-kem 0.3.3 + x25519-dalek 3.0.0; HKDF confluence; under `legacy`,
  RSA-OAEP is read-only.

### 3.2 `flock-protocol::envelope` (file envelope v1/v2)
- **Interface**: `seal_v2(recipient, plain_reader, out) -> SealInfo`, `open_v2(sk, in, out)`,
  `open_v1_legacy(rsa_sk, in, out)`; SealInfo carries envelope_id/segment count/total length.
- **Seam**: the encapsulation algorithm (the header's ver byte dispatches v1/v2); segment AAD
  construction is an internal implementation detail.
- **Implementation points**: v2 header 1137B (§1.3.3b); streaming with constant memory (reusing
  showroom's seal/open buffering model, showroom-analysis §4.1); AAD = ver‖id‖seg_idx‖is_final;
  length-invariant tests (v1's test idea carried over).

### 3.3 `flock-protocol::sig` (SR-SIG1 + key profiles)
- **Interface**: the five v1-compatible functions (§1.3.2) +
  `KeyProfile::verify_dispatch(kid)` (kid→Ed25519/ML-DSA).
- **Seam**: the kid algorithm dispatch table — extending `ProfileKey` with a new algorithm requires
  zero caller changes.
- **Implementation points**: ed25519-dalek 3.0.0; prehashed streaming signing preserved; `pq-sign`
  off by default (ml-dsa 0.1.1 unaudited, crypto-2026 §5 — labeled as-is).

### 3.4 `flock-protocol::pake` (OPAQUE + identity anchor)
- **Interface**: the showroom-compatible function family +
  `login_finish_anchored(...) -> (SessionSeed, ServerIdentity)` (the `anchor` feature);
  `rwd(pw, user, profile)`.
- **Seam**: argon2 profile parameterization (versioned upgrades do not break old records); the
  anchor signature layer is switchable (showroom keeps it off initially).
- **Implementation points**: opaque-ke 4.0.1; fixed-vector interop tests (3.0.0 recorded samples →
  4.0.1 can decode; the M1 gate); RFC reference 9807; the dummy fake-record anti-enumeration
  preserved.

### 3.5 `flock-protocol::session` (session/record layer/handshake)
- **Interface**: `initiate/respond(async)/Tunnel{async open_stream, async open_packet_channel,
  stats}` (§1.3.3c); handshake in two forms: pinned 1-RTT / TOFU first-connect 2-RTT bootstrap.
- **Seam**: `trait DeviceDirectory: fn lookup(&self, &DeviceId) -> BoxFuture<LookupVerdict>`
  (async + three states NotFound/Revoked/Active — the server injects the registry/revocation lookup
  into the protocol library; one of the multi-primary active-active permission points; a
  linearizable read is a network round trip, so a synchronous signature is unimplementable);
  `AeadPreference` (algorithm negotiation tier); `DeviceStaticKeys` (device key injection; on
  Android/iOS supplied by the upper-layer keystore).
- **Implementation points**: all P0-2 discipline built in (counter nonce/dual-threshold rekey/hard
  reject/forgery disconnect); the Noise IK structure is implemented in-house (snow not used — its
  CVE history and the inability to insert a KEM slot, crypto-2026 §5/§3.1); **the device signature
  covers all I1 fields + protocol context (cluster_id/expected identity fingerprint) — anti-UKS, M1
  has corresponding failure vectors**; transcript hash chain + test vectors (M1); strictly
  increasing counter checks + window structure reserved for a UDP path.

### 3.6 `flock-protocol::mux` (yamux carrier and packet channel)
- **Interface**: `Stream` (AsyncRead/Write + explicit `finish()`),
  `PacketChannel::send(pkt)/recv_stream()`, `Prio` scheduling tiers.
- **Seam**: the multiplexer implementation — an internal `trait Multiplexer` seam (the yamux adapter
  is the only first-release implementation; the trait is not exposed until a second adapter appears
  — "one adapter = an imaginary seam" discipline, SKILL.md principle).
- **Implementation points**: rust-yamux 0.14.1 runs inside SecureStream; control-flow stream 0 at
  high priority; keepalive = yamux ping 10s; FIN expresses one-directional end (half-close
  forbidden).

### 3.7 `flock-protocol::compress` (compression tiers)
- **Interface**: `CompressPolicy` + `compress_frame/decompress_frame` (§1.3.3e).
- **Seam**: policy tiers (Off/Interactive/Bulk/Archive) + dictionary version negotiation (dictID
  goes into handshake extensions).
- **Implementation points**: zstd 0.14.3 (Windows/MSVC proven compilable, compression-2026 §5) +
  lz4_flex 0.14; non-expansion fallback MUST; default Off + padding interlock.

### 3.8 `flock-protocol::trust` (TOFU/invite)
- **Interface**: `PinStore` (pin granularity = cluster_id → cluster root pubkey), `InviteFile`
  (v3: root-signed ClusterDirectory with the full set of server access material + one-time
  invite_id + expiry default 7 days, §1.3.3f), `ClusterDirectory/ServerEntry` (= the public part of
  §4's enrollment credential; `access_endpoint` = the access endpoint — a Direct direct address or
  an Frp relay user port, **indistinguishable to the client**; routing/liveness logic does not
  branch on the form), `fingerprint`, cluster root key / enrollment credential types (for §4
  admission).
- **Seam**: pin storage (file adapter first; a keystore adapter for mobile); the invite file
  version (v2 single-server material and v1 fingerprint-only are both no longer accepted — under a
  multi-server cluster they cannot support 1-RTT at any endpoint); directory refresh (dir_pull,
  root-verified + dir_version increasing).
- **Implementation points**: known_hosts semantics (at the cluster-root level); fingerprint display
  format (8 hex groups); root pubkey change warnings cannot be silently skipped; the invite_id
  single-consumption semantics are guaranteed by flock-sync's Raft state machine (the library only
  does structural validation); **the docs must embed the TOFU residual-risk statement** (no defense
  against an online first-login MITM; organizations use the strong invite path).

### 3.9 `crates/flock-frpc` (frpc subprocess supervision, VPN-16)
- **Interface**: `Supervisor::start(spec: RelaySpec) -> ManagedRelay`;
  `RelaySpec::ChmlFrp{mode: ChmlFrpMode} | Original{toml}`, where
  `ChmlFrpMode::ConfigFile(ini_path)` (**default**: the frpc.ini pasted and exported from the
  panel's "Tunnel Management → Config File", using `-c` mode) |
  `ChmlFrpMode::UserTokenAuto{usertoken, tunnel_id}` (legacy option: `-u/-p` cfg-API bootstrap);
  `health() -> RelayStatus`.
- **Seam**: frpc variants (ChmlFrp v0.51.2 pinned binary / original v0.71.1 pinned binary) + the
  config generator (golden-file tests, R8/R12: **do not modify the panel-generated proxy
  parameters** — CheckProxy would reject, frp-compat §2.3).
- **Implementation points**: process supervision (ChmlFrp frpc exits after three reconnect failures
  — modified behavior, frp-compat §2.3 — restart on exit + exponential backoff); health probing
  (local tunnel port + frpc admin); version matrix lock (R9: ChmlFrp node ⇔ ChmlFrp frpc,
  self-hosted node ⇔ same-generation original frpc, cross-combination forbidden — the two
  generations' control planes are mutually incompatible, frp-compat §1.3); **usertoken security
  tier**: the `-u/-p` bootstrapped cfg API is InsecureSkipVerify HTTPS (frp-compat §2.2,
  chml/pkg/api/api.go:30-46); the all-powerful panel credential can be intercepted by a MITM ⇒ the
  `-c` config-file mode is the default, UserTokenAuto retained but risk-documented (R20). Assembled
  only when the server's `listener.mode = Frp` (Direct mode has zero frp logic, §3.11); in the tcp
  proxy form the client dials the user port directly and never needs frpc itself.

### 3.10 `crates/flock-sync` (multi-primary active-active, VPN-15)
- **Interface**: `NetState::{register_device, revoke, allocate_ip, redeem_invite, revoke_invite,
  config_version, server_keys, rewrap, admin_op}` (writes, committed through Raft; admin_op =
  add_voter/rewrap/revoke_invite, must be signed by the cluster root key; **NetState does not store
  device current location — only static registration info and invite-consumption records**) +
  `read_linearizable(...)` + `LeaseTable::{publish, observe, location_query}` (gossip: event push
  ≤1s + 5s anti-entropy; lease TTL 30s; **the single source of truth for device current location**;
  location_query = a one-shot cross-server location inquiry, fan-out ≤3) + `TicketIssuer::
  issue/verify` (issued locally, TTL 60s, carries revocation_epoch) + `Enrollment` (enrollment
  credential verification/rotation, §4) + `Directory::serve(dir_pull)` (serves the root-signed
  ClusterDirectory to clients, §1.3.3f) + the cross-server forwarding carrier (ForwardEnvelope on
  the interconnect session's FRWD stream, §2.2).
- **Seam**: the state machine store (redb adapter first); the Raft network transport (direct TCP /
  relayed TCP — both run the E2E session with the **server-server profile**: mutual enrollment
  credentials + transcript signatures; no credential, no connection); the gossip transport (reuses
  the server interconnect sessions).
- **Implementation points**: openraft 0.9.25 stable line (0.10 still alpha, vpn-mesh §5.1); redb
  single-file embedded (pure Rust, fits the "no shared database" deployment form); the apply
  callback advances revocation_epoch + kills local sessions (§2.2 revocation propagation bound) +
  **apply-lag >2s circuit-breaks the local cache and degrades to linearizable reads** (§4 reads and
  caching); the learner→snapshot→add_voter→rewrap admission pipeline (§4); lease conflict = newest
  wins + the old end's session is kicked (vpn-mesh §5.2); invite_id single consumption is
  duplicate-checked inside Raft (§1.3.3f the life of an invite).
  M7 additions (§7-M7): lease entries carry per-device EWMA traffic and last_seen (the dynamic plane
  rides the leases, not Raft); the registry supports the Expired state and VIP return to the
  allocation pool (§2.1 IP reuse policy revision).

### 3.11 `app/flock-server` (server assembly)
- **Interface**: `flock-server --config server.toml` / `init-cluster` / `enroll` /
  `web-admin-add` (process entry points; web-admin-add = M8 Web UI first-admin bootstrap, §7-M8.3)
  + the control-flow message protocol (versioned; mandatory ticket contract in §2.2; includes
  dir_pull / the provisioning-redeem flow §1.3.3f) + the Web UI HTTP API (§7-M8.4 contract,
  verbatim).
- **Seam**: `ListenerMode` (access endpoint form, server.toml `listener.mode`, **Direct default**):
  ```rust
  enum ListenerMode {
      Direct { bind: SocketAddr },                 // listen directly on a public/internal address — zero frp logic;
                                                   // the code path never touches flock-frpc (no Supervisor
                                                   // instantiation / no config generation / no subprocesses)
      Frp { bind: SocketAddr, relay: RelaySpec },  // when there is no public IP / direct access is impossible:
                                                   // local listen + flock-frpc Supervisor-managed relay (§3.9/§5)
  }
  ```
  Downward it injects the `DeviceDirectory` for session::respond (= "NetState cache + epoch
  two-level read + lag circuit-break", §4 reads and caching); upward it hangs the tun adapter,
  flock-sync (including the FRWD forwarding plane) and flock-frpc **only in Frp mode** (dispatched
  by mode at assembly; the Direct branch has no flock-frpc type references).
- **Implementation points**: tokio runtime; one session task per inbound connection; the forwarding
  plane = **step-0 source VIP binding check** → lease-table location → local delivery or
  ForwardEnvelope cross-server forwarding (NOT_HERE → one-shot location_query redirect + hop=1 loop
  prevention + drop/ICMP on failure, §2.2); revocation executes locally inside the apply callback
  (no extra broadcast dependency); M8: the embedded Web UI admin plane (loopback + tun VIP dual
  bind :9800, OPAQUE login + session cookie, in-house minimal HTTP/1.1 — §7-M8).

### 3.12 `app/flock-client` (client assembly)
- **Interface**: `flock-client --config client.toml` / `flock-client invite <file>`.
- **Seam**: the `TunDevice` trait (tun-rs adapter first; the Android/iOS fd-injection adapter seam
  is reserved); the access endpoint list (source = the root-signed ClusterDirectory in the invite
  file/pinned directory, refreshable via dir_pull, switchable via liveness probing — every endpoint
  is 1-RTT, §1.3.3c/§1.3.3f).
- **Implementation points**: routing configuration (rtnetlink/wintun/VpnService parameters);
  access-side backoff reconnect; data plane IP packets ↔ PacketChannel; MTU 1280.

---

## 4. Multi-primary active-active sync scheme (selection: openraft strongly consistent state machine + gossip leases)

**Choice**: the first-phase form recommended by the research — "openraft replicated state machine
(device registry/credentials/config versions) + gossip leases (online state) + locally issued
session tickets" (vpn-mesh §5.3).

**Rationale** (point by point against the research evidence):
1. Three classes of data, three mechanisms (vpn-mesh §5.2): registry/IP allocation/revocation need
   **strong consistency** (an IP collision = a split-brain incident; revocation must be totally
   ordered and timely) — Raft's sweet spot, and openraft's `ensure_linearizable` exactly satisfies
   "any server gives the same access experience"; online state tolerates second-level staleness —
   gossip leases; network config is derived data — versioned in the state machine.
2. Explicitly not chosen: CRDT (revocation has no total-order guarantee), pure gossip (IP
   allocation can split-brain), a shared DB (pushes the multi-primary problem onto the database and
   requires the DB to be independently reachable, which does not fit the "one relay node per
   server, no shared internal network" form; NetBird's self-hosted HA is a commercial feature;
   among comparable projects multi-primary active-active is not a default capability, vpn-mesh
   §2/§5.3).
3. openraft is the Rust ecosystem's most mature Raft (in production at Databend, chaos tests in CI,
   the 0.9.25 stable line, vpn-mesh §5.1/S35); the server interconnect runs our own E2E session
   protocol ⇒ the sync link also has encryption/authentication/reconnect semantics; no new
   protocol is invented.

**Key points**: 3 voters minimum (tolerating 1 failure); writes forwarded to the leader (one extra
relay hop of latency, negligible for a low-write workload); the ticket key root lives in Raft, and
short-TTL tickets are issued locally (the login path does not depend on the leader; the vpn-mesh
§5.3 phase-two capability is absorbed directly into the first version); election/heartbeat timeouts
tuned to the relay RTT (default heartbeat 500ms/election timeout 1.5s, calibrated in M4 with an
injected 100ms RTT); replay-state ownership by tier is in §2.4.

**Reads and caching (preventing reconnect storms from punching through the leader)**: the
server-side implementation of `DeviceDirectory` (§1.3.3c) = two levels — "device record cache +
revocation_epoch (advanced automatically as the Raft log applies, **converging network-wide without
any extra broadcast**)" — epoch unchanged and cache hit ⇒ answer locally; epoch advanced ⇒
invalidate the cache; the next lookup is a linearizable read. After a relay link failure, an
N-client reconnect storm hits the local cache entirely when there are no revocations; the leader
only absorbs genuine global-order changes. `ensure_linearizable` is reserved for the few paths that
"must read the latest" (e.g. admin-side queries).
**Disclosure of the stale-read boundary and the circuit breaker (an honest statement of the health
precondition)**: when a follower lags (partition recovery / catching up), its local epoch is an old
value and "unchanged", and cached Active records still hit and pass — **a revocation the leader has
already committed cannot block a new handshake before it applies locally**; the window = how long
the follower's log lags (normally < heartbeat 500ms; after partition recovery it can reach seconds
or more). Countermeasure (circuit breaker): heartbeats/AppendEntries carry the leader's commit
index; followers self-monitor their apply lag; **lag > 2s (= the A6 timing budget) disables the
local-cache path and degrades to linearizable reads**, restored once caught up; the additional
backstop = session-ticket epoch checks (within a ticket's TTL 60s a local apply point necessarily
passes). M4's tests include "with a follower artificially lagged 5s, a revocation is still
blocked". A6's ≤5s therefore carries an explicit health precondition: it holds on a healthy cluster
or when the breaker has tripped; a partitioned node with lag>2s has already been broken and
degraded.

**Inter-server trust bootstrap and cluster admission (M4 start precondition, security-critical)**:

1. **Cluster bootstrap**: the operator runs `flock-server init-cluster --voters 3` to generate the
   **cluster root key** (Ed25519, kept offline, used only for signing, never for networking) and
   each initial voter's **enrollment credential** = the root key's signature over
   `{cluster_id, server_id, role, identity_pub, static_hybrid_pub, raft_addr, access_endpoint,
   expiry}`. Each server holds: its own identity/static-hybrid private keys + its own enrollment
   credential + the cluster root pubkey. **One trust root, two uses**: the public part of the
   enrollment credential (ServerEntry, §1.3.3f) is exactly the client access material — the root
   key both vouches for server mutual authentication (this section) and signs client invite files /
   the cluster directory (§1.3.3f); no second trust root is introduced.
2. **Interconnect authentication**: server interconnects (Raft/gossip/cross-server forwarding) run
   the E2E session protocol's **server-server profile** — each side must present an enrollment
   credential and sign the transcript with the credential's identity key; a peer without a valid
   credential is rejected at the handshake layer. The openraft network adapter hangs only above
   that authenticated session ⇒ **an attacker spinning up a fake node gets neither the snapshot nor
   entry into Raft** (with only Raft-layer weak authentication, a fake node could demand a snapshot
   and a re-wrap — a rewrap unseals the OPRF key, opening the network-wide offline-password-dictionary
   surface; this is this design's red line).
3. **New-node admission (the authorized path is fixed)**: the operator signs a new node's
   enrollment credential with the cluster root key → the new node joins as a **learner** (openraft
   dynamic membership, joint consensus) → snapshot sync → the operator initiates the Raft admin
   operation `add_voter` (the request body carries the cluster root key signature; the state
   machine verifies the signature before it takes effect) → promotion to voter; **secrets rewrap
   (extending the per-server sealing of the OPRF key etc. to the new server) is another independent
   admin operation** `rewrap(server_id)`, likewise requiring the cluster root key signature — a
   compromised single enrolled server does not hold the root key and can neither self-grant
   admission nor trigger a rewrap.
4. **Credential rotation**: enrollment credentials carry an expiry; rotation = a root-key-signed
   new credential + a Raft-committed activation window (the minimal window of old/new parallel
   validity); cluster root key leakage = full-network re-bootstrap (the docs state this explicitly
   as the disaster-recovery path).

---

## 5. FRP compatibility strategy (selection: option A subprocess supervision, pinned dual stack) — **an optional adapter, not a prerequisite**

> **Hard constraint (§0)**: frp serves only the "server has no public IP, or the client cannot
> reach the server IP directly" scenario; when `listener.mode = Direct` (the default), **no
> frp-related logic is executed**. Everything in this chapter applies only to servers that
> explicitly choose the `Frp` form.

**Choice**: **option A** of frp-compat §3 — supervising two pinned frpc builds as subprocesses:
ChmlFrp nodes use `ChmlFrp-0.51.2_251023` (the Linux package already exists:
`.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/`, existence verified in this session);
self-hosted/original nodes use original frp v0.71.1 (the Linux official package was downloaded in
this session and executed inside a container to verify: `frps --version` → `0.71.1`,
FRPS_LINUX_OK).

**Rationale** (frp-compat §0.4/§3):
1. ChmlFrp is based on v0.51.2 (no control-plane encryption) and original ≥v0.53.0 (mandatory
   AES-128-CFB); **the two generations are mutually incompatible** (§1.3, confirmed at source
   level) ⇒ A is the only path that "supports both simultaneously at zero protocol-maintenance
   cost".
2. B (a native Rust implementation) hits the v1→v2 wire-protocol transition (v1 is planned for
   removal in v0.78.0) + must align with ChmlFrp's modified auth/CheckProxy naming — the worst
   cost/benefit moment; listed as a long-term evolution.
3. C (visitor/xtcp) is unavailable on ChmlFrp (the panel cannot create stcp/xtcp + CheckProxy
   rejects, §2.4); only self-hosted nodes could use it as a long-term P2P acceleration layer; not
   on the main path.
4. Every known shortcoming has an engineering fix: ChmlFrp frpc exiting after three reconnects →
   supervised restart (§3.9); proxy parameters cannot be hand-crafted (CheckProxy) → golden-file
   config generation (R12); multiple sessions over one tunnel → yamux multiplexing (R11).
5. Protocol-layer consistency assertion set: R1–R12 (frp-compat §4) as the source of §6 Docker
   assertions and M2/M5 acceptance cases.

---

## 6. Docker multi-machine interconnect test topology (Windows host + Docker Desktop Linux containers)

### 6.1 Feasibility verification (all actually executed in this session; commands and outputs in Appendix B)

| Item | Result | Command (summary) |
|---|---|---|
| Docker backend | Docker Desktop 29.8.2 / Engine 29.8.2, **WSL2** (kernel 6.18.54.1-microsoft-standard-WSL2) | `docker version` / `docker info` |
| `/dev/net/tun` passthrough | **Works**: with `--cap-add NET_ADMIN --device /dev/net/tun`, `ip tuntap add` + `ip addr add 100.64.0.1/32` succeeded (TUN_CREATE_OK) | see Appendix B-2 |
| `mknod` fallback | **Works**: without `--device`, inside the container `mknod /dev/net/tun c 10 200` + device creation succeeded (MKNOD_PATH_OK) | Appendix B-3 |
| Original frps Linux binary | **Works**: official v0.71.1 linux_amd64 download (14,140,587B) + in-container `frps --version`→`0.71.1` | Appendix B-4 |
| ChmlFrp Linux package | already at `.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/` (frpc+frps+ini, verified by ls in this session) | Appendix B-5 |
| Windows host toolchain | Rust 1.98.1 (msvc + linux-gnu + wasm32 targets installed) | Appendix B-6 |
| Not verified (stated as-is) | in-container Rust image builds not run (the repo has no code yet; nothing to build); Hyper-V/Docker VMM backend CONFIG_TUN not checked (vpn-mesh §1.3 limitation — **the deployment constraint pins the WSL2 backend**) | — |

### 6.2 Topology (deploy/e2e.yml, three isolated networks — a single subnet would make
"simulating an untrusted public network" a misnomer)

```
Network split (key point: the Frp-form server-a/b are not directly reachable on flockpub,
ruling out an implementation cheating the assertions via a direct-connection fallback;
server-c deliberately hangs directly on flockpub in Direct form — both listener modes coexist
in one topology, verifying the hard constraint):
  flockpub  172.28.0.0/24  bridge, simulates the untrusted public network — hosts frps, the frpc
                          sidecars, clients, and Direct-form server-c; ciphertext flows over it
  srvmesh   172.29.0.0/24  internal — hosts only the three servers (Raft/gossip/FRWD interconnect,
                          never on the public network)
  link-a/b  one /30 internal network each — frpc sidecar ↔ its server (the sidecar exposes
                          server:9443 through the relay)

frps-a   [flockpub]  original frps 0.71.1  :7000(frpc control) :23000(user port A)
frps-b   [flockpub]  original frps 0.71.1  :7000              :23001(user port B)
frpc-a   [flockpub+link-a] frpc 0.71.1 → registers to frps-a, forwards to server-a:9443
frpc-b   [flockpub+link-b] frpc 0.71.1 → registers to frps-b, forwards to server-b:9443
server-a [link-a+srvmesh]  flock-server listener.mode=Frp   tun0 VIP 100.64.0.1
server-b [link-b+srvmesh]  flock-server listener.mode=Frp   tun0 VIP 100.64.0.2
server-c [flockpub+srvmesh] flock-server listener.mode=Direct (default) :9443 directly on the
                                                                  public network
                                                                  tun0 VIP 100.64.0.3
         (C is a Raft quorum voter: a 2-node Raft has zero fault tolerance; the failover
           assertion needs 3 voters — a necessary extension of the brief's "×2 servers each
           behind a relay"; rationale in §4; from round four on, C doubles as the Direct-form
           template: no frpc sidecar, no frp process, access endpoint = 172.28.0.22:9443)
client-1 [flockpub] flock-client  tun0 VIP 100.64.0.11  — config pinned to access via frps-a:23000
client-2 [flockpub] flock-client  tun0 VIP 100.64.0.12  — config pinned to access via frps-b:23001
client-3 [flockpub] flock-client  tun0 VIP 100.64.0.13  — config pinned to direct 172.28.0.22:9443
         (the pinned mapping is an assertion-semantics requirement: A2's client-1↔client-2 mutual
           ping must cross servers (the server-a↔server-b ForwardEnvelope path); the two clients
           must not be allowed to defeat the cross-server forwarding plane by connecting to the
           same server)
(client-N can be replicated; all flock containers get --cap-add NET_ADMIN --device /dev/net/tun,
 MTU 1280)
```

Inside the server containers: `flock-server` listens on :9443 — server-a/b are reachable only on
their link networks (exposed via the frpc sidecars as frps user ports 23000/23001); server-c, in
Direct form, listens directly on its flockpub address (**no frpc sidecar, no frp process of any
kind in the container**). Clients dial the access endpoint (direct address or relay user port;
logic isomorphic, §2.1). In Frp-form production deployments frpc is a subprocess inside the server
process (§3.9); the separate sidecar containers in the test topology are purely a networking need
— the same Supervisor code, two deployments.
Build: code is written and host unit tests run on the Windows host; Linux binaries are built inside
containers — the build image's C toolchain question **was closed by an actual test in this session**
(revision round, Appendix B-9): `rust:1-slim-bookworm` was measured to ship `/usr/bin/cc`,
`/usr/bin/gcc` (Debian gcc 12.2.0), and inside that image `cargo add zstd@0.14 && cargo build
--release` compiled zstd-sys 2.1.2 (vendored C source) **successfully** (7.67s,
ZSTD_BUILD_CHECK_DONE) — a default-feature build that includes the compression module will not
die at zstd-sys. The image tag is pinned by digest (or `rust:1` + a CI check of `rustc --version`
≥1.98); for extra stability, use the full `rust:1-bookworm`.
The automation baseline uses original frp ×2 (a real ChmlFrp node needs a real-name account,
frp-compat gaps#1 — left as a manual checklist item; protocol byte-stream consistency is argued in
§1.4 + R8/R12 golden files covering the config side).

### 6.3 Assertion checklist (deploy/e2e_assert.sh, M5 acceptance = all PASS)

| # | Assertion | Pass criteria |
|---|---|---|
| A1 | Byte pass-through | reuse the frp-compat T1/T2 harness: echo 1MiB random + all 256 byte values back through each of the two relays; sha256 matches (R1/R2) |
| A2 | Tunnel connectivity (incl. cross-server) | client-1 `ping -c 3 100.64.0.1` 0 loss (same-server path); client-1↔client-2 mutual ping works — the access mapping pins client-1→frps-a, client-2→frps-b, so this mutual ping **must traverse cross-server forwarding** (the §2.2 ForwardEnvelope path) |
| A3 | MTU | `ip link show tun0` contains `mtu 1280`; `ping -c 2 -s 1252 -M do 100.64.0.1` works (1252+28=1280) |
| A4 | Throughput baseline | iperf3 over the tunnel ≥ 100 Mbps (local relay without the 8Mbps cap; the number is recorded for regression comparison, R7) |
| A5 | Relay failover | `docker stop frps-a` → client-1 switches within ≤30s to `frps-b:23001` (= server-b's endpoint, using server-b's ServerEntry from the ClusterDirectory) and completes a brand-new handshake — **1-RTT pinned form; I0 must not appear** (a direct verification of the pinning model §1.3.3f), VIP unchanged, ping recovers; assertion basis: the client config contains only the endpoint list from the root-signed directory (R6) |
| A6 | Multi-primary revocation takes effect (parameterized) | revoke client-2 via server-b → each server kills local sessions inside its Raft apply callback + revocation_epoch advances → the session on server-a is kicked + new handshakes rejected + ticket epoch checks fail; ≤5s (budget: commit→apply ≤2s + event margin ≤1s + slack 2s, §2.2; ticket TTL 60s backstop) |
| A7 | Raft fault tolerance | `docker stop server-a` (including its frpc) → B/C still have quorum; A2/A6 rerun in full and pass; re-election ≤15s |
| A8 | Many sessions over one tunnel | 100 concurrent yamux streams for 60s without errors (R11) |
| A9 | keepalive link-failure detection | `docker network disconnect` simulates a silent dead link → both sides detect within ≤3×10s and enter reconnect (R5) |
| A10 | Seamless rekey | iperf3 sustained load ≥5min; epoch increases ≥2 times; throughput shows no >1s plateau (P0-2) |
| A11 | Compression off by default | with default config, captured record lengths = original + constant overhead; after enabling a compression tier, non-expansion fallback works (P0-4) |
| A12 | Anti-replay (unit-level injection) | duplicate/regressed counter records injected at the session layer are rejected and counted toward the forgery limit (M1 unit tests re-run as the M5 entry) |
| A13 | No direct-connection fallback (topology validity, Frp-form servers) | from the client-1 container, `timeout 2 bash -c '</dev/tcp/172.28.0.20/9443'` and `…/172.28.0.21/9443` against server-a/b's flockpub addresses fail (neither is on flockpub ⇒ must fail; otherwise the "via relay" semantics of A1/A5 has been bypassed; server-c excepted — it is the Direct form and is meant to be directly reachable, asserted positively by A16) |
| A16 | Direct form (hard-constraint gate) | client-3 directly dials `172.28.0.22:9443`, completes the 1-RTT handshake (same ServerEntry material system) and pings 100.64.0.3 successfully; client-1/2 ↔ client-3 mutual ping works (Direct↔Frp cross-server forwarding isomorphic); inside the server-c container `pgrep -f frp` finds no process, and there is no frpc sidecar container (the runtime proof of zero frp logic in Direct mode) |
| A14 | Cross-server forwarding plane + source VIP check | packet-capture counters for client-1 (on server-a) ↔ client-2 (on server-b) mutual ping: ForwardEnvelope appears on server-a's FRWD stream (non-zero count), and after killing the srvmesh connection the mutual ping breaks while the local ping to server-a still works (isolating a cross-server-plane failure); also, from client-1, `hping3/scapy` forges packets with src=100.64.0.12 (client-2's VIP) ⇒ server-a's drop counter increases and client-2 receives nothing (§2.2 step-0 source VIP binding check) |
| A15 | Stale-lease fault tolerance | migrate client-2's config from frps-b to frps-a and restart (the new endpoint's handshake is likewise 1-RTT); within the old-lease window client-1→client-2 packet loss recovers after ≤ lease TTL(30s)+anti-entropy(5s) (§2.2 fault-tolerance policy: the NOT_HERE→location_query redirect path is exercised, FRWD counters show redirect frames) |

---

## 7. Milestone breakdown (each with verifiable completion criteria)

### M1 Protocol library (crates/flock-protocol)
Scope: all tiers of §1.3 + the compatibility surface + the feature matrix; upgradeList placement
P0-1/2/3/4/5, P1-6/7/8/9/10, P2-11/12/13 (protocol-library parts).
Completion criteria (all runnable):
- `cargo test -p flock-protocol --all-features` fully green, and it must include:
  - OPAQUE vectors: registration records/login samples generated by showroom 3.0.0 interop under
    4.0.1 (P2-11 gate);
  - envelope v1 read-only compatibility: showroom `seal` output is opened by `open_v1_legacy` and
    the length-invariant assertions pass (P0-1 compatibility tier);
  - envelope v2 AAD: segment-reorder/splice/tail-truncation cases must fail (P0-3);
  - session discipline: duplicate counter rejected, a 120s injected clock triggers rekey, 180s hard
    reject, N forgeries disconnect (P0-2);
  - **handshake in two forms**: pinned 1-RTT full vectors; TOFU first-connect 2-RTT
    (I0→R0→I1→R1) state-machine vectors; invite file v3 (containing the cluster root pubkey + the
    full set of server material) → any endpoint's first connection is already 1-RTT;
  - **UKS/binding failure vectors (against unknown key share)**: tampering with the protocol
    context (cluster_id/expected identity fingerprint) or swapping the server identity → the device
    signature/server signature verification must fail (§1.3.3c signature coverage contract);
  - **DeviceDirectory fake-implementation three states**: handshake behavior for each of
    NotFound/Revoked/Active (the first two reject, with timing aligned) + async interface
    (BoxFuture) compile-time assertion;
  - hybrid KEM round trip + ml-kem official KAT re-run (P0-1);
  - compression: <128B pass-through, trial-compression-no-shrink fallback to plaintext, dictID
    negotiation (P0-4/P1-7);
  - trust: the pin-change-triggers-warning path; invite file v3 structure vectors — root signature
    mismatch / directory entry tampered / dir_version regression → refuse to load; under the same
    root pubkey, **each of multiple endpoint ServerEntries can complete its own 1-RTT
    encapsulation** (the gating case of the multi-server pinning model §1.3.3f) (P0-5).
- `cargo bench -p flock-protocol --bench aead`: aes-gcm 0.11.1 @4MiB ≥ 4 GB/s
  (this machine's old-kernel baseline 2.2; the 2.3× expected floor of P1-6).
- `cargo clippy -p flock-protocol --all-features -- -D warnings` passes.

### M2 Server (app/flock-server + flock-frpc, single-server form)
Scope: the listener (ListenerMode: Direct default / Frp) / control flow / OPAQUE login + anchor /
device registration (local NetState adapter: redb single-node edition, interface identical to
flock-sync) / frpc supervision dual stack (assembled only in Frp mode) / config generation
golden-file.
Completion criteria:
- `docker compose -f deploy/m2.yml up -d --build` (1 frps + 1 server (Frp mode) + 1 client
  skeleton) comes up and stays up;
- **direct-connection smoke variant (hard-constraint gate, added in round four)**:
  `docker compose -f deploy/m2-direct.yml up -d --build` comes up — **no frps container**; the
  server listens with `listener.mode = Direct` and is mapped to a host port; the client dials that
  port directly and runs exactly the same smoke assertion set as m2.yml (`cargo test -p
  flock-server --test smoke -- --ignored --direct` or an equivalent env switch for the endpoint);
  and it is asserted that inside the Direct-form server container `pgrep -f frp` finds no process
  and the Supervisor was never instantiated (the runtime proof of zero frp logic on the Direct code
  path);
- `cargo test -p flock-server --test smoke -- --ignored` (actually run against containers)
  asserts: invite file (containing static hybrid pubkeys) → 1-RTT first connection → OPAQUE login
  → key-bind (signature-verification path) → the device appears in the registry → SR-SIG1 request
  signatures verify → after revocation the handshake is rejected;
  **mandatory ticket contract tests**: state-changing requests with no ticket / an expired ticket /
  a low-epoch ticket (post-revocation) must be rejected, and ticket validation precedes nonce
  accounting (order assertion: bad ticket + brand-new nonce → reject; bad ticket + already-used
  nonce → reject and the nonce is not recorded); effective replay window = min(±300s, 60s)
  verified;
  **TOFU first-connection path tests**: without an invite, I0→R0 bootstrap (R0 carries the
  enrollment credential chain) + root-fingerprint confirmation callback → the pinned cluster root
  pubkey is written to disk → the second connection is 1-RTT and **switching endpoints (another
  server) is still 1-RTT** (directory pull takes effect);
  **provisioning / invite one-time-use tests**: redeem invite_id → user/device created + VIP
  assigned; a second redemption of the same invite_id rejected; rejected after revoke_invite;
  rejected when expired.
- frpc generated-config golden-file tests (ChmlFrp INI sample + original TOML sample field-for-
  field identical, R8/R12); the ChmlFrp frpc "exit and be restarted" supervision unit test (fake
  process exits 3 times → restarted 3 times); the ChmlFrp default `-c` mode assertion (UserTokenAuto
  enabled only by explicit opt-in).

### M3 Client (app/flock-client, data plane working)
Scope: tun adaptation (tun-rs) / routing (rtnetlink/wintun) / access-side backoff / PacketChannel
data plane.
Completion criteria:
- `docker compose -f deploy/m3.yml up -d --build`;
- `deploy/m3_assert.sh` all PASS: assertions A2/A3/A4/A9 (single-server edition); on the Windows
  host `cargo test -p flock-client` (tun unit tests use a mock TunDevice — the host has no
  container NET_ADMIN environment);
- **Windows real-machine manual checklist (the lead platform must have real-machine records)**:
  on the dev machine, with a local test relay, wintun creation + route injection + `--smoke` pass
  (wintun.dll permissions / first-time driver-install behavior recorded); macOS has no device ⇒
  marked not verified (utun per the tun-rs platform-matrix design).

### M4 Multi-primary sync (crates/flock-sync)
Scope: the openraft state machine (registry/credentials/config versions/ticket key root) + gossip
leases + the rewrap permission point + **cluster admission (enrollment credentials/server-server
profile, §4)** + the cross-server forwarding carrier (ForwardEnvelope).
Completion criteria:
- `cargo test -p flock-sync --test cluster` (3-node in-memory cluster) asserts:
  a write on any node → a linearizable read on any node sees it within ≤2s (including revocation
  records);
  kill the leader → re-election ≤15s with no lost commits (an injected relay RTT of 100ms
  simulated);
  the same device holding leases on two servers conflicts → newest wins, the old side's
  kick callback fires;
  `register→revoke→register` (the no-IP-reuse semantics) and the `server_keys→rewrap` round trip;
  **revocation propagation bound**: after a revoke commits, each node's apply callback advances
  revocation_epoch + the kill-local-session hook fires within ≤2s (RTT 100ms injected).
- `cargo test -p flock-sync --test admission` asserts:
  **a node without an enrollment credential or with a forged credential is rejected at the
  server-server handshake layer** (it gets neither the snapshot nor entry into Raft);
  learner joins → snapshot sync → `add_voter` (root-key signature) → promotion; `rewrap` without a
  root-key signature → the state machine rejects it; with the signature → the new server's hybrid
  pubkey enters the sealing set (OPRF key replica count +1 observable).
- `cargo test -p flock-sync --test forward` asserts: **source VIP binding check** (a session's
  device sending with someone else's VIP as src ⇒ drop + count; a ForwardEnvelope whose src_dev
  mismatches the inner source address ⇒ the receiver rejects it); local delivery / NOT_HERE →
  one-shot location_query redirect / hop=1 loop prevention (construct a second-hop forward → drop
  counter); on still failing, send ICMP unreachable.
- `cargo test -p flock-sync --test cluster` additionally: **apply-lag circuit breaker** —
  artificially lag a follower by 5s and inject a revocation during that time ⇒ that follower
  refuses to use the cache (degrades to linearizable reads) and new handshakes are rejected (§4
  stale-read boundary).

### M5 Docker multi-machine test (deploy/e2e.yml + e2e_assert.sh)
Scope: the full §6.2 topology (three isolated networks + pinned access mapping + Direct/Frp mix) +
§6.3 assertions A1–A16.
Completion criteria: `docker compose -f deploy/e2e.yml up -d --build && deploy/e2e_assert.sh` all
PASS; the script outputs a per-item PASS/FAIL summary (A5/A6/A7/A15 may pass within an explicit
retry window).
**Desktop real-machine manual checklist (a mandatory M5 acceptance item, run on the host, not in
containers)**:
- Windows (the dev machine is the real machine): `cargo run -p flock-client -- --smoke` — wintun
  device creation, `route print` asserting the 100.64.0.0/10 route exists, tun0 MTU 1280, ping to
  the server VIP through a local test relay; the admin-permission behavior of wintun.dll's
  first-time driver install goes into the checklist.
- macOS: no device; listed as **not verified** (the utun path designed per the tun-rs platform
  matrix, to be filled in when a device is available; the utun facts in vpn-mesh §1.1 are the
  design basis).
- The Linux container path is covered by A2–A15; no manual step needed.
Omissions stated as-is: ChmlFrp real-node end-to-end (needs an account; manual checklist: after M5,
when an account exists, re-run R1/R6/R7 against a ChmlFrp node); mobile (Android/iOS) real machines
(separately scheduled after M3; the seam is already reserved in §3.12).

### M6 System service + client control plane (phase one: daemon side; tray in a parallel phase two)

Requirements (user's words): Windows/Linux/macOS auto-start as a system service at boot; if the
machine has a GUI, show a system tray icon (no GUI window for now); the tray's right-click menu has
three items: connection status, VPN IP, quit. Phase one delivers the daemon side (service/IPC/
installer); the tray UI is developed in phase two — **the IPC contract is frozen in this phase as a
module compilable and consumable standalone** (`flock_client::ipc`, directly depended on by the
tray project).

#### M6.1 Two-process model (architecture finalized)

- `flock-client service`: **the system service process** — no GUI dependencies of any kind;
  auto-starts at boot (Windows SCM / systemd / launchd); owns all the existing supervise/data-plane
  logic (§3.12 unchanged) and additionally runs a local control-IPC server.
- `flock-client tray`: **the user-session process** — tray UI only (implemented in phase two);
  queries status / triggers quit over the control IPC; never touches keys/tun/the data plane.
- **Rationale**: a Windows service runs in session 0 and cannot create a tray (blocked by the
  shell; a factual constraint); a single process cannot satisfy both "auto-start without a session"
  and "a tray inside the session". Linux/macOS services likewise run in the system context (a
  systemd system unit / a LaunchDaemon), separate from the user-session GUI — the three platforms
  are isomorphic, avoiding platform forks (Linux's user-service form is not adopted: it cannot
  align with the Windows service form and does not start before login).
- **Quit semantics** (the "Quit" tray menu): stop the VPN + the tray process exits; **the service
  stays installed** (auto-starts next boot). The daemon-side Shutdown = graceful stop: drop the
  session (tunnel GoAway/FIN) → stop the data plane → tear down tun → process exit; the service
  manager **does not revive it** (the systemd unit `Restart=on-failure` — a normal exit is not a
  failure; the launchd plist sets no KeepAlive; the Windows service recovery policy acts only on
  failed exits).

#### M6.2 Control IPC (v1 contract)

**Transport** (postcard over a local transport; framing isomorphic to §3.11's admin plane:
`[u32 LE len][postcard]`, single connection, single request-response):

| Platform | Endpoint | Permissions |
|---|---|---|
| Windows | named pipe `\\.\pipe\flock-client-control` | explicit DACL (SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)`): SYSTEM + Administrators + interactive-users group (IU) read/write |
| Linux/macOS | Unix socket `/run/flock/client.sock` | 0660, directory `/run/flock` 0755 root |

**Authentication**: the daemon generates a 32B random token on every start (`rand::random`) and
writes it to a token file — Windows `%ProgramData%\flock\control-token` (explicit ACL: Users
read); Linux/macOS `/var/lib/flock/client/control-token` (0640 root; if `client.toml`'s
`control_group` field names a group, the daemon chgrps the token and socket to that group when
writing them out — the single source of truth for the group name is the config, not install
parameters; installing never rewrites the user's config; only local /etc/group names or numeric
gids are resolved; on failure warn but do not block, and the default root:root means "root-only
control", documented as works-out-of-the-box). **Every request carries the token** (Status and
Shutdown share the same envelope field); validation precedes dispatch; a wrong token ⇒ `Denied` —
tighter than "only Shutdown carries the token": Status leaks endpoints/VIP and is not opened to
everyone who can connect at the transport layer.

**Messages** (`flock_client::ipc`, postcard/serde, `#[derive(Clone, PartialEq)]`):

```rust
pub enum CtrlReq {
    Status   { token: [u8; 32] },
    Shutdown { token: [u8; 32] },
}
pub enum CtrlResp {
    Status {
        state: ConnState,              // Connected | Connecting | Disconnected
        vip: Option<String>,           // local VIP (resolved at startup ⇒ Some; copy-tolerance slot)
        endpoint: Option<String>,      // current/most recent dialed endpoint
        epoch: u64,                    // current session key epoch (advanced by rekey; 0 when down)
        uptime_secs: u64,              // seconds since daemon start
    },
    Ok,        // Shutdown accepted
    Denied,    // wrong token
}
```

**Semantics**: `Status` is side-effect-free and idempotent; `Shutdown` = the §M6.1 graceful stop;
after replying `Ok` the daemon finishes teardown and exits (the process exit races with writing the
response; the promise is response-first — in the extreme case the client seeing a connection reset
still counts as accepted). v1 has no version-negotiation field — adding enum variants is backward
compatible (postcard varint variant ordinals); cross-version policy is left to v2.

#### M6.3 Service installation (`flock-client install` / `uninstall`)

`--user` installs only the tray autostart; `--service` only the service; the default is both. The
install action records the **install-time** `--config` path into the service definition
(unit/plist/service command line carries it); uninstall reverses the cleanup.

- **Windows** (windows-service crate): `SERVICE_AUTO_START` + a failure-recovery policy (restart,
  5s delay each, capped at 3); service name `flock-client`, binary path = the current exe, command
  line `service --config <path>`; event-log source `flock-client` (reports Start/Stop/failures).
  **Service installation needs an administrator**: a non-elevated session gets a clear error
  message (docs/manual/windows-smoke.md precedent — the real-machine install goes on the manual
  checklist `docs/manual/service-install.md`).
- **Linux**: renders `/etc/systemd/flock-client.service` (`WantedBy=multi-user.target`,
  `Restart=on-failure`, `After=network-online.target` + `Wants=network-online.target`,
  `ExecStart=<exe> service --config <path>`) → `systemctl daemon-reload` → `systemctl enable --now
  flock-client`. **Needs root** (sudo hint). Uninstall: `disable --now` → delete the unit →
  `daemon-reload`. Installing inside a container requires systemd to be running (in the test phase
  only unit rendering and the command sequence are verified; the enable execution surface is left
  to the real-machine checklist).
- **macOS**: writes `/Library/LaunchDaemons/com.flockvpn.client.plist` (`RunAtLoad=true`,
  **no KeepAlive** — no revival after Shutdown) → `launchctl load -w`. Needs root. **No device on
  this machine ⇒ marked not verified** (the file and commands are written out anyway; a slot is
  reserved on the M6 manual checklist).
- **Tray autostart**: Windows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value
  `flock-client-tray` = `<exe> tray` (HKCU needs no elevation); Linux
  `~/.config/autostart/flock-client-tray.desktop`; macOS
  `~/Library/LaunchAgents/com.flockvpn.client-tray.plist` (`RunAtLoad`, no KeepAlive).

#### M6.4 CLI surface

The existing default run (`--config`, bare) is kept as the **foreground debug mode** (no IPC; logs
straight to stderr); new subcommands: `service` (the daemon assembly: supervise + IPC server +
graceful stop, running in the foreground under the service manager), `tray` (**implemented in
phase two**: §M6.7 — tray menu/polling/quit, feature-gated), `install`/`uninstall` (§M6.3), and
`status` (sends one `Status` request and prints — a probe for tray-less environments and tests;
the token is read from the token file, and failure to read reports "daemon not running / no
permission").

#### M6.5 Feature gating

`tray` feature: included in Windows/macOS dev defaults; a Linux headless server image must not
drag in tray GUI dependencies by default. **Cargo limitation stated as-is**: cargo cannot express
per-target default features — in this phase `default = ["tray"]` is identical across the three
platforms, but the tray gating surface is only subcommand registration (zero dependency delta);
in phase two all tray GUI dependencies hang under `[target.'cfg(windows/macos)'.dependencies]` +
`optional = true` inside the `tray` feature; the Linux default build (including default features)
pulls in no GUI dependency surface, and release builds drop the tray explicitly with
`--no-default-features` (CI gating includes that build).

#### M6.6 Completion criteria (phase one)

1. `cargo test -p flock-client --all-features` fully green (IPC contract round trips / token
   rejection / Denied / supervision assembly and service-semantics unit tests; one set each of
   transport-layer mocks and real platform loopback).
2. `cargo check -p flock-client --no-default-features` (no-tray build) and
   `cargo check --target x86_64-unknown-linux-gnu -p flock-client` (the Linux compile surface)
   pass.
3. `cargo clippy -p flock-client -- -D warnings` passes.
4. Windows service install/start/real-machine tray autostart, the full macOS chain: needs
   administrator/real machines; listed on the `docs/manual/service-install.md` manual checklist
   (the Windows real-machine item marked "to be executed in an administrator session"; macOS
   marked not verified).
5. The tray project can directly `use flock_client::ipc::{CtrlReq, CtrlResp, ...}` to consume the
   contract (lib-surface export + the contract unit tests double as consumption samples).

#### M6.7 Tray process (implemented in phase two, 2026-11-06)

- **Entry point**: `flock-client tray` (gated by the `tray` feature; opens no GUI window of any
  kind). Tray/daemon interact per the §M6.2 contract, with the token read from the token file; the
  core logic (copy projection / token source / polling cadence / quit adjudication / icon / GUI
  detection) lives in the platform-neutral `flock_client::tray` layer — **zero GUI dependencies,
  fully unit-testable on the host**.
- **Menu (three items)**: "Connection status" and "VPN IP" are dynamic read-only menu items
  (disabled items — the platform-idiomatic greyed-out read-only form), refreshing text by polling
  `Status` every 2s ("Connection status: connected · frps-a:23000", "VPN IP: 100.64.0.11"; when
  disconnected/`vip: None`, VPN IP shows "—"; daemon not running / IPC failure / `Denied` ⇒
  "service not running" with continued retrying); "Quit" is the action item: sends `Shutdown` with
  the token ⇒ the daemon stops gracefully (§M6.1: the service stays installed and auto-starts next
  boot) ⇒ the tray process exits; if the daemon is absent (token missing / IPC failure) ⇒ **quit
  the tray only**; `Denied` ⇒ do not quit and show a hint — the token-stale reload path (the
  recovery path when the daemon restarted with a fresh token); the user clicks "Quit" again to
  retry. The tooltip mirrors the status summary.
- **Icon**: a 32×32 programmatic RGBA (rounded-square base + a goose-formation forward arrow,
  SDF-subpixel anti-aliased) — no image crate / no PNG asset:
  `tray_icon::Icon::from_rgba` and ksni ARGB32 both eat raw pixels; PNG would be a pure relay; no
  binary-asset diffs, pixel-level assertions possible (corner transparency / center opacity /
  foreground pixel count / determinism).
- **Platform libraries and minimal pump** (no winit/tauri/egui full GUI stack):
  - Windows/macOS: `tray-icon` (built-in muda menus, consumed via the `tray_icon::menu`
    re-export). Windows uses a minimal Win32 message pump (a dedicated thread `GetMessageW`; the
    main thread wakes refresh via `PostThreadMessageW` and stops the pump with `WM_QUIT` — the
    official minimal-example shape; tray-icon's event dispatch requires a thread that pumps
    messages, a hard constraint); macOS uses a main-thread NSApp event-drain loop
    (`nextEvent/sendEvent/updateWindows` + a 50ms cadence consuming the shared refresh; AppKit's
    tray/NSMenu main-thread constraint).
  - Linux: `ksni` (pure-Rust DBus StatusNotifierItem; the zbus tokio feature shares the existing
    runtime domain) — **zero GTK/libappindicator system dependencies**, consistent with the
    headless discipline; the menu is rebuilt to the latest state every time it opens (ksni
    semantics naturally satisfy the 2s refresh); the tooltip refreshes actively via
    `Handle::update`.
- **GUI detection and fallback**: on Linux, first check that at least one of `DISPLAY`/
  `WAYLAND_DISPLAY` is set + a session DBus (`DBUS_SESSION_BUS_ADDRESS` or
  `$XDG_RUNTIME_DIR/bus`); any missing ⇒ log "no GUI session detected, tray not started" and exit
  code 0; Windows/macOS do not pre-check — a tray-creation failure likewise exits gracefully (no
  panic, exit code 0). An SNI host that becomes ready later than autostart is not treated as fatal
  (`assume_sni_available` + `watcher_offline` keeps waiting — login-race tolerance).
- **feature/dependency gating (M6.5 delivered)**: the `tray` feature filled with real dependencies
  from its `[]` placeholder — tray-icon (win/macos target-gated optional),
  objc2/objc2-app-kit/objc2-foundation (the macos pump), ksni (linux, default-features=false +
  tokio feature); `dep:` references are no-ops on non-matching targets ⇒ the Linux default build
  shows no tray-icon/objc2 surface, Windows shows no ksni surface, and `--no-default-features`
  has a zero-GUI-dependency compile surface on all three platforms (gates verified by testing).
- **Verification boundary (as-is)**: core unit tests (all projection branches / token-stale
  reload / polling recovery / quit-ordering with a real-transport IPC mock) + a real Windows
  process test on the host (mock daemon on a real endpoint / token in place: tray stays alive
  ≥10s without panic, menu-refresh logs, state consistent with `status` in two processes, and
  after a token `Shutdown` stops the daemon the tray shows "service not running" and keeps
  retrying); **icon/menu visual checks and the "Quit" click** cannot be automated ⇒ the tray
  real-machine checklist in `docs/manual/service-install.md`; a real-daemon joint test needs
  invite bootstrap + wintun administrator (windows-smoke.md precedent), listed on the same
  checklist; the full macOS chain unverified (no device; and the aarch64-apple-darwin toolchain
  downloaded too slowly in this session for compile-level verification — the API surface checked
  against crate sources, listed for later); the Linux desktop real machine unverified (the
  container build covers the compile surface).

### M7 Member roster and observability (server side)

Requirements (condensed from the user's words): the CLI must be able to list each VPN IP's
hostname, account, online status, and average traffic; a host going offline must not disappear
immediately — retain it for 1 month by default; within the window, a reconnecting same device
keeps the same IP (after expiry the device expires and the IP returns to the pool); response
latency is measured by the client (out of scope for this milestone).

#### M7.1 Registry extension (Raft static plane)

`DeviceRow` gains two fields (`crates/flock-sync/src/proto.rs`; the registry row = the Raft state
machine's snapshot wire format):

```rust
pub struct DeviceRow {
    pub owner: String,
    pub device_x25519: [u8; 32],
    pub device_ed25519: [u8; 32],
    pub vip: [u8; 4],
    pub status: DeviceStatus,      // Active | Disabled | Revoked | Expired (new)
    pub since_epoch: u64,
    pub hostname: String,          // new (M7): reported by the client when joining; empty ⇒ "(unknown)";
                                   //   re-register (the same device key-binding again) can update it
    pub expired_at: Option<u64>,   // new (M7): unix seconds when set to Expired (for audit); always
                                   //   None when not Expired
}
```

- `hostname` origin: the enroll/key-bind path (`DevicePubs` gains a `hostname: String` field,
  included in the key-bind device-signature coverage); the server wires the field and its default
  through first — client reporting is filled in during the M8 client phase, with an empty string
  landing as `"(unknown)"` (length cap 64 bytes, truncated beyond).
- **Snapshot/wire-format compatibility (stated as-is)**: postcard has no field tags, so after
  `DeviceRow`/`SyncRequest` gain fields, **old snapshots and old log entries cannot be decoded** —
  acceptable in the pre-release window (the same discipline as the existing `L_SERVER_KEYS` rename
  in proto.rs); upgrades with leftover old databases require a rebuild (re-running init-cluster);
  no migration is provided.

#### M7.2 IP reuse policy revision (§2.1 revised in sync)

- **Revoked → the IP is never reused** (unchanged); **offline past the retention period → Expired
  + VIP returned to the allocation pool** (a new device may get it); **the expired record stays on
  the roster** (audit), excluded from roster queries.
- Implementation: `SyncRequest::Expire { device, now_unix }` (a Raft write; `now_unix` is injected
  by the submitter, and the state machine deterministically sets `expired_at`). Apply semantics:
  only Active/Disabled → Expired (idempotent: replaying an already-Expired entry passes without
  touching the epoch); advances revocation_epoch and triggers the revocation-propagation hooks
  (kill residual sessions / void tickets — the same path as Revoked, only the state semantics
  differ); releases the VIP into the allocation pool (`NetStateData.vip_pool: BTreeSet<[u8; 4]>`,
  **takes priority over high-water-mark allocation** — take the minimum from the pool; when the
  pool is empty fall back to the monotonically increasing watermark `vip_next`); the
  VIP-reverse-lookup index drops the old entry (Expired rows do not enter the index — the
  injectivity of released VIPs is maintained by "VIPs in the pool are not in the index").
- **Expired is terminal** (like Revoked): cannot be Enabled (the old VIP may already belong to
  another device; revival would break injectivity); the same device identity with the same keys
  cannot be revived (DeviceId = hash(ed25519) ⇒ re-registering yields DeviceExists; only the
  re-register hostname-update path is available) — **a new device identity (new keys) registers a
  new row with a new VIP**. The single-server form (netstate.rs StateStore) has the same
  semantics: `expire()` + a VIP pool table.
- Retention period = server.toml `peer_retention_days` (default 30; **0 = never expire**,
  compatible with the old behavior; u64 is naturally ≥0, parsing validates it).

#### M7.3 The dynamic plane rides the leases (EWMA traffic + last_seen, not into Raft)

- Lease entries (`flock-sync/src/lease.rs`) gain: `tx_ewma/rx_ewma: u64` (bytes/s, **device
  perspective** — tx = sent by the device, rx = received by the device; the server's own entry
  likewise) and `last_seen_unix: u64`. Gossip `Publish`/`Anti` messages carry them along (the
  holder's authoritative values).
- EWMA: α = 0.2 (`EWMA_ALPHA_NUM/DEN = 1/5`), a **1s update window** — per-device byte
  accumulators in `LeaseTable` (`note_tx/note_rx`); `tick_ewma(now_ms)` folds once per second:
  `ewma = ewma·(1−α) + (Δbytes/Δt)·α` (fold only the rows this machine holds — remote rows' values
  come from the holder's publish/anti-entropy and are never overwritten locally).
- **Counting points (single-point principle, no double counting)**: count "at the
  successful-delivery point" —
  - **src device tx**: counted once by the **access server** (the src lease holder) after the step-0
    source VIP binding check passes at ingest (entering the mesh = success; the dst side never
    counts src);
  - **dst device rx**: counted once by the **server that delivers successfully** (local sink
    delivery success / ForwardEnvelope receive-side local delivery success — i.e. the dst's actual
    holder); the origin of a cross-server FRWD does not count dst; Not_HERE/drops are not counted;
  - **the server's own entry**: dst = the local VIP injected into the kernel successfully ⇒ local
    rx; the kernel return path `route_outbound` ⇒ local tx.
  - Rows whose TTL has expired are **retained** (no longer deleted): `observe` semantics are
    unchanged (expired ⇒ None), but the row's `last_seen_unix`/ewma remain for the roster's
    offline-device display (memory trade-off: ~60B per row);
    **offline decay (revision)**: rows past TTL with no accumulation this window decay their ewma
    by ×4/5 per window, set to 0 below 8B/s (the decay branch of `tick_ewma` — rows with
    accumulators get the same mathematical decay via zero-rate folding) — the roster no longer
    shows non-zero traffic for offline devices.
- `last_seen_unix` update points: publish/renewal (holder), local traffic counted for that device
  (holder), receiving a peer's publish/anti-entropy event (remote entries take the value carried
  in the message).
- Sync channel: rides the **existing** lease publish/events (≤1s semantics; the renewal loop
  re-publishes every 10s carrying the latest ewma) and anti-entropy (5s) — no new gossip message
  types. The roster assembly takes from the **local lease view**.
- Single-server form: no lease table — `flock-sync` provides the same-math `TrafficMeter` (any key
  + EWMA + last_seen, no gossip); `PeerRouter::serve_stream` counts both directions (inbound =
  that device's tx, outbound = that device's rx; inbound packets with dst = the server VIP count
  the server's rx; the kernel return path counts the server's tx).

#### M7.4 Roster contract (new on the control flow; consumed in the client phase, frozen verbatim)

`CtrlRequest` gains a variant + response + row type (postcard, `flock-server/src/control.rs`):

```rust
CtrlRequest::PeerListPull { ticket: Option<TicketWire> }
CtrlResponse::PeerList { peers: Vec<PeerInfo> }

pub struct PeerInfo {
    vip: [u8; 4],
    hostname: String,
    owner: String,
    kind: PeerKind,            // pub enum PeerKind { Device, Server }
    online: bool,
    last_seen_unix: u64,
    tx_bps: u64,               // device-perspective EWMA (bytes/s)
    rx_bps: u64,
}
```

- **Ticket protection**: the login ticket is mandatory (`ticket: None` ⇒ `TicketMissing`);
  **ticket validation (signature + TTL + epoch + device state) precedes roster data assembly** —
  following the §2.2 mandatory-ticket-contract discipline (this operation is read-only with no
  nonce-accounting surface; the order has a test assertion: a bad ticket ⇒ `TicketBad` and the
  assembly counter does not move).
- **Assembly** = a registry snapshot (the **locally applied view** — the two-level read-cache tier
  suffices; a linearizable read is not required: the roster is a display surface, tolerating
  second-level staleness of a follower view) ⋈ the local lease view (including ewma):
  - Device entries: rows with `status == Active` (Disabled/Revoked/Expired excluded — the roster =
    current members; audits go through DeviceList); `online` = valid TTL in the local lease view;
    `last_seen_unix`/`tx_bps`/`rx_bps` taken from the lease row (no lease history ⇒ 0).
  - **The servers themselves are also on the roster** (kind=Server): the multi-primary form takes
    the Raft `server_keys` local view (`ServerKeyEntry` gains `vip: [u8; 4]` — signed at root-signed
    registration together with the identity/hybrid pubkeys, with the canonical bytes extended
    accordingly; the vip value is **deterministically derived** from the node number: node 1..=10 →
    `100.64.0.<node_id>` (the §6.2 server segment .1–.10); out-of-range registration is rejected —
    the same derivation network-wide, no second source of truth); `owner` = that server's node_id
    in decimal string form (the carrier form of server_id); `hostname` = that server's
    `relay_endpoint` in the root-signed ClusterDirectory (the client-visible endpoint, familiar
    and unique); traffic = the server's self-published entry in the local lease view (the
    `server_self_device_id(node_id)` synthetic device key — node_id big-endian in the first 8B +
    a fixed marker suffix; collision probability with a real device id (sha256(ed25519)) is
    negligible; each server self-publishes in its lease renewal loop and counts the kernel path).
    Single-server form: one local Server entry (vip = `cfg.vip`, hostname =
    `advertise_endpoint`, traffic = the local TrafficMeter).
  - Output sorted **ascending by VIP**.

#### M7.5 The reaper (a low-frequency task)

A low-frequency task inside server (60s period): scan the locally applied registry snapshot and,
via a Raft write, move devices that are "Active and `last_seen_unix` older than
`peer_retention_days`" to Expired + release their VIP (the M7.2 path). `peer_retention_days = 0`
⇒ the reaper is not assembled. Concurrent reaping across servers is idempotent (Expire replay
passes); `last_seen_unix` = the local lease view (multi-primary) / TrafficMeter (single-server);
**with no observation (0), the anchor is `DeviceRow.registered_at`** (landing "counting starts at
registration" — counting from epoch 0 would make `0 <= cutoff` always true, and online devices
not yet observed after a restart would be bulk-terminated on the first tick — a review
correction). There is also a **restart / view-not-ready gate** (defense in depth, minimal reliable
form): single-server = TrafficMeter has had zero observations since creation (empty and the
registry non-empty ⇒ just restarted) skips this round; multi-primary = the local lease table is
empty **or** no remote lease event has been received since startup (the race window between
anti-entropy backfill ≤1 period 5s and the reaper's first tick; a single-node raft cluster has no
peers ⇒ the gate stays closed and the retention period never applies — not a deployment-facing
form, noted as-is) skips this round. `registered_at` is injected by the submitter (apply has no
clock — determinism); the Raft row and the single-server row both persist it (postcard/manual
codec gains a field; old snapshots cannot be decoded — acceptable in the pre-release window,
§7-M7.1 discipline). The window-decision function takes the injected clock (`reap_once(..,
now_unix)` is testable).

#### M7.7 Client side (M7 second batch: login/ticket keeping/roster consumption/peers CLI)

**Contract hoisting (repaying an architecture debt)**: `PeerInfo`/`PeerKind`, the ticket wire
formats `TicketWire`/`SignedTicket`, the control-plane messages `CtrlRequest`/`CtrlResponse` and
their value types, the key-bind device-signature canonical, hostname normalization — hoisted into
**`flock-protocol::roster`** (the same types on both ends, no second source of truth;
`flock-server::{control,ticket}` and `flock-sync::proto` re-export them via `pub use`, existing
reference paths unchanged; the authoritative ticket logic TicketAuthority/NonceLedger does not
move — a server-internal surface). flock-protocol gating includes a wasm32 check (roster is pure
data with no platform surface).

**Credentials and login (the client half)**:

- `client.toml` gains `[auth] username` (+ optional `credentials_file`, defaulting to the state
  directory's `credentials`); the password is stored as a **single plaintext line** in a 0600
  file (Windows explicit DACL: SYSTEM+administrators+owner, no Users). **At-rest risk stated
  as-is**: OPAQUE (RFC 9807) guarantees the password never goes on the wire; at rest locally =
  the local trust domain (owner-side plaintext readable — the same class of trade-off as "root
  can read /etc/shadow", no keystore dependency).
- `flock-client login` (one-time bootstrap): read the password from stdin (a tty echoes — a local
  trust-domain trade-off) → write the 0600 credential → direct-tunnel control flow:
  `PwBegin/PwCommit` sets the server-side password (authorization = the session device's owner;
  the admin plane has no account-password-creation operation; password setting has always gone
  through the control flow) → login verification + key-bind carrying the hostname onto the
  roster. The ticket is not kept (a one-shot command).
- The daemon (`service` form) login-keep task: session in place ⇒ OPAQUE login (anchor verified
  with **the identity pubkey of that server from the pinned directory** — the anchor stays correct
  after endpoint rotation switches servers) → key-bind (the hostname re-register update path;
  `add_user_sig_key` dedup ⇒ periodic re-login does not bloat the registry) → the ticket
  **lives in memory only**; re-login cadence = TTL·2/3 (a **relative quantity** — immune to clock
  skew between the two ends; stays fresh within the ticket TTL). The credentials file is **read
  fresh at every login** (changing the password via `login` needs no daemon restart). Control-flow
  request timeout ⇒ poison the stream + actively kill the session and reconnect (a yamux stream
  after a timeout may be misaligned — better to reconnect than continue misaligned).

**Hostname reporting**: `client.toml hostname` overrides; the default is the OS hostname (the
hostname crate); unified `normalize_hostname` (trim/64B truncate/empty string "(unknown)" — the
same semantics as the server-side persist).

**PeerListPull consumption + IPC/CLI**:

- The daemon caches the most recent roster (`RosterCache`, fetch time + ≤5s freshness window);
  IPC gains `CtrlReq::Peers{token}` → the daemon: cache fresh, or fetch holding the current ticket
  → for entries that are **online and not self**, concurrently ping-probe (ICMP echo over tun — a
  raw socket to the VIP goes out via the routing table through tun0; 3 probes, 2s timeout per
  probe, take the upper median; implementation = a thin socket2 raw-ICMP layer: the daemon's
  privileged context has raw permission in place, the same API surface on all three platforms,
  checksum/reply matching fully controlled; raw unavailable ⇒ the latency column degrades to "—")
  → `Peers{rows}`, `PeerRow = PeerInfo + latency_ms + self_flag`; not logged in / tunnel down /
  not configured ⇒ `PeersUnavailable{reason}` (the CLI turns it into guidance copy).
- `flock-client peers`: an aligned table `VIP | hostname | account | type | status | latency (ms)
  | ↓ traffic (B/s) | ↑ traffic (B/s)`; status has three states = online / offline (Device) /
  **service not running** (Server-type offline — distinguishable from device offline); offline
  latency column `—`; own row annotated `(self)`; `--json` machine-readable build (an array;
  latency null = offline/not probed). Daemon absent / not logged in ⇒ a clear error and guidance.
- Live test: `deploy/m7.yml` + `m7_assert.sh` (two clients + server: roster entries/latency/
  iperf3 traffic columns/JSON parsing); Windows/macOS raw ICMP real machines → item 9 of §7 of
  the `docs/manual/service-install.md` checklist.

#### M7.6 Completion criteria

1. `cargo test -p flock-sync --all-features`: includes DeviceRow round trips (new fields), a new
   device receiving a released Expired VIP, EWMA convergence, lease-gossip traffic-field round
   trips, and the snapshot-compatibility statement (old formats cannot be decoded ⇒ clean
   failure).
2. `cargo test -p flock-server --all-features`: roster assembly (online/offline/expired three
   states + Server entries), the ticket-first order assertion, reaper window logic (injected
   clock), hostname defaults / re-register updates.
3. `tests/multi_primary.rs` additionally: with two clients cross-server, the roster assembles
   identically on either server (structural fields strictly equal; ewma/last_seen compared with
   tolerance — the two servers' local views come from anti-entropy snapshots at different times;
   byte-for-byte equality is neither possible nor necessary), with a fake traffic pump making ewma
   non-zero.
4. Gates: both crates clippy `-D warnings`, workspace check, fmt; the container linux-tier check
   (anything involving cfg is only on the data-plane counting path; no new platform branches).

### M8 Server Web UI (admin login + a modern dashboard)

Requirements (the user's words): the server needs a Web UI with an admin login account and a
complete, modern dashboard; by default only the server's own machine can access it, and authorized
accounts access it via the VPN server's internal IP; in a multi-server cluster, any server's VPN
internal IP works.

#### M8.1 Form and selection finalized (in-process embedding / HTTP framework / three frontend
options / asset embedding / i18n)

- **Form: an HTTP service embedded in the flock-server process** (the webui module, file placement
  in §M8.8), a third listening surface alongside the existing access endpoint (:9443) and the admin
  loopback (:9444). A cluster = every server embeds the same UI and API; the data plane
  (registry/Raft, leases/EWMA, epoch) is naturally consistent via existing mechanisms ⇒ "any
  server's VPN internal IP works" needs no new sync logic. **The session table is per-server
  process memory** (not in Raft): a cookie obtained by logging in at server-a's VIP is invalid at
  server-b (cookies are host-scoped anyway) — just log in again on b; the behavior goes into the
  docs.
- **HTTP framework: an in-house minimal HTTP/1.1 (`webui::http`), not axum**. Ruling:
  1. Dependency-tree status: Cargo.lock (364 packages) contains no hyper/tower/http artifacts
     whatsoever; a minimal axum assembly would pull in ~40–60 new crates (hyper 1.x + tower +
     http-body + matchit + mime…); paying for the whole tower stack for an admin plane reachable
     only on loopback+VIP with ~20 JSON endpoints contradicts the repository's existing discipline
     (§3.6 "one adapter = an imaginary seam"; admin.rs/session are precedents of in-house frame
     protocols).
  2. The exposure surface is tiny ⇒ the HTTP subset is tiny: HTTP/1.1, GET/POST, keep-alive,
     single-cookie parsing, fixed-length bodies via `Content-Length` — **reject
     Transfer-Encoding/chunked and duplicate Content-Length** (the fundamental way to prevent
     request smuggling is to not implement ambiguous features); request line ≤2KiB, headers ≤8KiB,
     body ≤64KiB, over-limit 400/413 and close the connection; the concurrency cap = an
     independent semaphore (default 64).
  3. The parser carries malformed-request test vectors (§M8.9); every rejection path is asserted.
  Cost (stated as-is): no HTTP/2, no chunked uploads, no Range — the admin plane does not need
  them; if needed later, `webui::http` has a single caller and can be replaced wholesale (the seam
  is the handler dispatch function).
- **Frontend selection (three options evaluated; A chosen)**:
  - **A (chosen)**: hand-written fetch + Alpine.js 3.14 (vendored, ~15KB gz) + a hand-written
    modern CSS design system (dark theme) + **uPlot 1.6.9** (vendored ~48KB min) for traffic
    curves;
  - B (rejected): htmx server-rendered fragments — charts and polling still need JS (uPlot does
    not disappear because of htmx), yet HTML assembly moves into the Rust template surface, and
    the wasm OPAQUE client still needs browser JS — savings nowhere;
  - C (rejected): Vue ESM vendored — without a node toolchain there is no SFC compilation, leaving
    components written as template strings (poor maintainability), and a ~34KB gz runtime is
    overkill for form/list interactions across 6 pages.
  Chart library uPlot vs Chart.js: traffic time series are uPlot's sweet spot (canvas, 120 points
  redrawn per minute imperceptibly, ~12KB gz vs Chart.js ~65KB gz); **uPlot it is**.
- **Asset embedding: `include_dir`** (fixed). vs rust-embed: include_dir has zero runtime
  dependencies and deterministic behavior; rust-embed's debug-profile fs read-back adds no value
  for this asset set (<15 files). Asset `Cache-Control`: API `no-store`, assets `no-cache` (a
  single-binary upgrade refreshes everything; no fingerprinted filenames needed).
- **i18n: Chinese first** (fixed). v1 is zh-CN only; all copy is centralized in a single
  dictionary object in `assets/i18n.js` (adding English later only adds a file; the API does not
  vary by language).
- **wasm: flock-protocol compiles the OPAQUE client functions for the wasm32 target** — no
  wasm-bindgen (same-origin constraint as showroom §8.3), reusing showroom `wasm_shim.rs`'s
  **C-ABI shim** approach + this repo's already-in-place getrandom custom backend in
  `wasm_bridge.rs` (`getrandom_backend="custom"` in `.cargo/config.toml`). The new shim
  `crates/flock-protocol/src/webauth_shim.rs` (contract in §M8.6). Build profile: `cargo build -p
  flock-protocol --target wasm32-unknown-unknown --no-default-features --features wasm,anchor`
  (no zstd ⇒ zero C dependencies); the artifact + hand-written JS glue (~120 lines) are both
  embedded into the server binary via include_dir.

#### M8.2 Listening, binding, and the access matrix (assertion table)

- **Dual binding (retry logic fixed)**: `[webui] port` (default **9800**) derives two listen
  addresses — `127.0.0.1:9800` and `cfg.vip:9800`. **The config exposes no bind field at all** (a
  0.0.0.0 misconfiguration is structurally impossible, not caught by validation). The loopback
  listener binds at startup; **the VIP binding is added by a retry task** (5s period: tun not
  ready / address unconfigured ⇒ bind fails and retries; failure logged once, re-logged on state
  change, never crashes — the loopback surface is unaffected). Data path: peer → access-server E2E
  session → (cross-server: ForwardEnvelope, the receiver injects into the kernel
  `fwd_delivered_kernel` path) → the target server's tun0 → the kernel TCP stack → the VIP:9800
  listener — the same path as "peer pings the server VIP"; no new forwarding plane.
- **server.toml new section (§3.11 ServerConfig extension)**:
  ```toml
  [webui]
  enabled = true            # default; false = do not assemble webui
  port = 9800               # validated 1..=65535 and no conflict with bind/admin_bind/admin_bind+1/raft_bind (server start refused)
  session_ttl_secs = 28800  # default 8h; validated 60..=86400
  series_points = 120       # traffic ring-buffer point count (§M8.5)
  series_interval_secs = 60 # sampling interval
  ```
- **Access matrix (adjudicated per request by the origin middleware; tests anchored to W-A1–W-A4)**:

| # | Origin (RemoteAddr) | Result | Mechanism |
|---|---|---|---|
| W-A1 | 127.0.0.0/8 (incl. ::1) | **Reachable**: static pages + login; post-login authorization by role | loopback binding + origin middleware allow |
| W-A2 | 100.64.0.0/10 (arriving via the tun VIP) | **Reachable**: same as above (any VPN peer can open the login page; accounts without a role get read-only/403 after login) | VIP binding + origin middleware allow |
| W-A3 | anything else (LAN/public interfaces) | **Unreachable** (at the connection layer) | Root mechanism: no LAN/public address is bound; defense in depth: the origin middleware returns 403 `forbidden_origin` for out-of-range RemoteAddrs |
| W-A4 | behind a reverse proxy / LB | **Not promised** | `X-Forwarded-For` is always ignored (client-forgeable); a proxy IP not in the allowed ranges gets 403 — reverse-proxy deployments are unsupported, stated in the docs |

- **The established path for remote administration**: an SSH tunnel (`ssh -L 9800:127.0.0.1:9800
  …`, the same recommendation as the admin endpoint, §3.11 validation copy); putting the webui
  behind a TLS reverse proxy is undefined behavior (the RemoteAddr would be the proxy's address,
  triggering the W-A4 rejection).

#### M8.3 Authentication and authorization (OPAQUE reuse form + sessions + the ruling against the
existing authorization surfaces)

**The login flow = same-semantics new HTTP endpoints (control-flow messages are not reused; the
pake primitives are)** — an explicit ruling:
- The control flow's `LoginBegin/Finish` presumes "session device owner == user" (authenticated
  inside the tunnel; the current control.rs implementation); a Web login has no tunnel session ⇒
  **define same-semantics endpoints for HTTP**: `/api/login-begin|finish`, with the server calling
  the same `pake::{server_login_start, server_login_finish}` + the same OPRF (single-server =
  local / multi-primary = the shared key unsealed from Raft sealing) + the same registry password
  records. The ke1/ke2/ke3 wire form = the same b64 strings (protocol-isomorphic).
- **anchor kept**: the login-begin response carries `{server_id, bind_token, anchor_sig}` (the
  same canonical as the control flow: `anchor_canonical_bytes`); the page startup fetches
  `GET /api/bootstrap` for this server's `identity_pub`, and wasm verifies with
  `login_finish_anchored`. Semantic boundary (as-is): the browser has no pinned cluster root
  pubkey; this verification binds "login transcript ↔ this server's identity" (preventing
  wrong-cluster/wrong-server response mixups) and **provides no MITM protection** — transport
  integrity is borne by the trust domain (loopback / per-hop VPN E2E, §M8.7).
- **Profile constraint**: the Web login client always uses `Profile::Owasp19MiB` (=default); if
  the record-side profile ≠ 0 ⇒ login-finish errors locally on the client ⇒ 401 `login_failed`
  (same presentation as a wrong password; no reason leaked). All password records in the system
  are created at the default tier (the control flow PwBegin/CLI web-admin-add use the same tier),
  so this is no practical restriction.
- **Anti-enumeration**: unknown users go down the pake dummy path (ke2 same shape);
  login-finish is uniformly 401.

**Sessions (server-side in-memory table + HttpOnly cookie)**:
- SessionId = 32B random (`flock_protocol::rand`) as 64 hex chars; table =
  `HashMap<sid, Session{user, admin, origin: Loopback|Vpn, iat_unix, exp_unix}>`; TTL =
  `session_ttl_secs` (default 28800); **cap of 256 entries**, oldest-by-iat evicted beyond the cap
  (asserted); lazy expiry (exp checked on hit) + a 60s periodic sweep. origin is set at
  login-finish by the RemoteAddr (loopback / VPN segment); **both classes are legal and both are
  recorded** (cross-segment cookie reuse is not rejected — per the requirement's original
  semantics; /api/me and audit rows echo origin).
- Cookie (verbatim):
  `Set-Cookie: flock_session=<64hex>; HttpOnly; SameSite=Strict; Path=/; Max-Age=<session_ttl_secs>`;
  logout returns the same name with `Max-Age=0` to delete. **No Secure** (no TLS, §M8.7). Cookies
  are host-scoped ⇒ 127.0.0.1 vs the VIP, and VIP-a vs VIP-b, are each independent logins
  (documented).
- **Role model**: `UserRow.admin: bool` (below) decides the role. **Not logged in: everything
  except the public endpoints (login-begin/finish, pw-begin/commit, bootstrap, static assets) is
  401 `not_logged_in`**; non-admin: read-only endpoints available (peers/dashboard/config — this
  data is already visible to any member via the M7 roster), admin endpoints 403 `forbidden`. The
  per-endpoint role matrix is fixed in §M8.4.
- **Demotion/disable takes effect = immediate session recycling (review revision)**: dispatch, on
  the session-tier lookup, **re-reads `UserRow`** (the Raft form uses the locally applied view; a
  linearizable read is not required — a local commit is visible on re-read immediately, another
  server's commit takes effect within sub-second-to-seconds after local apply, the same view tier
  as the roster/peers): after `set_admin=false`, an old session **gets 403 on its next request**
  (the admin snapshot inside the session row does not count; `/api/me` echoes the sync); a
  `disabled` user gets **401 `user_disabled` on the next request at any login-tier endpoint** —
  neither waits for the TTL (the old behavior's 8h lingering privilege window is eliminated).

**Web sessions ↔ the existing authorization surfaces: an explicit ruling (three items, closing
the ambiguity)**:
1. Web sessions **neither reuse nor map to** the control flow's 60s tickets: tickets bind devices
   and are short-term in-tunnel credentials; web sessions bind users and are 8h credentials on
   the HTTP surface — two credential systems, two lifecycles; no bridging, mutually unusable.
2. Web mutating writes **go through the existing ordinary Raft write path** (the same shape as
   the control flow's DeviceOp): authorization is adjudicated at the handler layer (the session
   user must be admin), then committed by this server via `NetBackend`. **They neither go through
   nor loosen `admin_op` root-signed operations**: `add_voter/rewrap/revoke_invite` and
   `cluster-bootstrap/cluster-invite` (root-key context) **are not exposed in the Web UI**; they
   stay CLI + root.seed (the §4-3 red line unchanged).
3. Coexistence and division of labor with the admin loopback (:9444, unauthenticated, single
   local writer): the CLI ops surface keeps using 9444; `web-admin-add` is a 9444 extension
   variant (first-admin bootstrap, below). Neither endpoint promises remote access.

**Registry extension (Raft static plane)**: `UserRow` (flock-sync/src/proto.rs; re-exported by the
single-server netstate from the same source) gains three fields — **postcard has no field tags ⇒
old snapshots/old logs cannot be decoded; acceptable in the pre-release window** (the same
discipline as §7-M7.1; upgrades with leftover old databases rebuild. The single-server redb row
encoding is the netstate module's own layout: the three fields append at the tail, and pre-M8
old rows are **leniently decoded** to default values — existing single-server deployments upgrade
without breaking the database; this is a different encoding surface from flock-sync's postcard
snapshot "clean failure"):

```rust
pub struct UserRow {
    pub opaque_record: Option<String>,  // existing
    pub opaque_profile: u16,            // existing
    pub sr_sig_pubs: Vec<[u8; 32]>,     // existing
    pub admin: bool,                    // new (M8): Web admin role
    pub disabled: bool,                 // new (M8): disabled ⇒ blocks Web and control-flow login
                                        //   (a Web session gets 401 user_disabled on the next
                                        //   request — review revision; established data-plane/
                                        //   control-flow sessions are not retroactively dropped;
                                        //   device-level severance goes through disable/revoke)
    pub pw_bootstrap: Option<[u8; 16]>, // new (M8): initial/reset-password one-time bootstrap token
                                        //   (set to None once consumed)
}
```

`SyncRequest` **appends at the tail** five ordinary writes (no root-signature requirement —
authorization is at the submitter's handler/CLI layer, the same shape as SetPassword/
AddUserSigKey) + `StateError` tail-appends `BadBootstrapToken`:

```rust
CreateUser { username: String, pw_bootstrap: [u8; 16] }      // UserExists rejects
SetPasswordBootstrap { user: String, token: [u8; 16],
                       record_b64: String, profile: u16 }    // atomic: token matches and the record
                                                            // is empty ⇒ persist the record + clear
                                                            // the token
ResetPassword { user: String, new_token: [u8; 16] }          // clear the record + set a new token
                                                            // (admin-initiated; the old password is
                                                            // invalidated immediately)
SetUserAdmin { user: String, admin: bool }
SetUserDisabled { user: String, disabled: bool }
```

- **Disabled semantics**: a disabled user's Web login-finish gets 401 `user_disabled` (login-begin
  goes down the dummy same-shape path for unknown users / users without a password, for
  anti-enumeration; for disabled users **the real record is still used** — the ke2 is the same
  shape as a normal user's, leaking no disabled state; an honest client can therefore complete
  ke3 and receives `user_disabled` at finish; the disabled determination happens after the
  password proof is established, leaking nothing extra), and the control flow's `LoginBegin` gains
  the same determination (**the only touch to the existing control-flow dispatch**, test-covered);
  established data-plane/control-flow sessions are not retroactively dropped (device-level
  disposition goes through the existing disable/revoke) — documented. **Stated as-is (review
  revision): a disabled account has a password-correctness oracle** — at finish, a correct
  password ⇒ `user_disabled`, a wrong one ⇒ `login_failed` (distinguishable); that oracle is
  usable only when online password verification is possible and is throttled by the §M8.3 login
  backoff (15min sliding window, exponential lockout from the 5th failure, capped at 900s) and a
  per-IP token bucket (10/min) — not in conflict with the "ke2 same-shape anti-enumeration" goal
  (not leaking account existence / disabled state at the begin stage); the price buys honest
  clients a clear error semantics (otherwise a disabled user and a wrong password would be
  indistinguishable and ops could not tell them apart). **Web session surface**: a disabled
  user's existing Web session gets 401 `user_disabled` on the next request (dispatch re-reads
  UserRow; see "demotion/disable takes effect = immediate session recycling" above).
- **Password-setting flow (shared by create/reset)**: admin `POST /api/users` (or
  reset-password) ⇒ the response returns a one-time `pw_bootstrap_token` (32hex, exactly once,
  delivered to the user out of band) ⇒ the user's browser `POST /api/pw-begin {user, token,
  m1_b64}` (token pre-check is read-only, no consumption) ⇒ `POST /api/pw-commit {user, token,
  record_b64, profile}` (atomic Raft consumption + record persist). The token = a 16B random
  one-time credential, at the same trust level as an invite_id (readable inside Raft state,
  single consumption).

**First-admin bootstrap (a CLI subcommand reusing the credentials/OPAQUE registration path)**:
`flock-server web-admin-add <username>` — reads the password twice interactively from stdin (a
tty echoes; a local trust-domain trade-off, the same semantics as `flock-client login`); runs the
native OPAQUE registration in-process (`reg_start` → the admin endpoint m1→m2 → `reg_finish` →
submit). The admin endpoint (:9444) **tail-appends** two variants: `AdminRequest::WebPwBegin {
user, m1_b64 }` → m2 (loopback binding = the authentication boundary, the same trust level as the
existing invite/revoke); `AdminRequest::WebPwCommit { user, token, record_b64, profile, admin:
bool }` — if the service is running ⇒ submit through the endpoint (multi-primary: CreateUser
(UserExists idempotently ignored) + SetPasswordBootstrap + SetUserAdmin; the token is generated by
the CLI and carried in the message); if the service is not running ⇒ the single-server form may
write the state store directly (the Cmd::Invite fallback precedent); **multi-primary must submit
through a running service (Raft)**, otherwise a clear error. If the target user already exists
and already has a password ⇒ refuse and point to the Web reset flow.

**Login-failure backoff + rate limiting (process memory, testable with an injected clock)**:
failures counted per username (15min sliding window): from the 5th failure, lockout 30s, doubling
per further failure, capped at 900s; success or an empty window clears it. Additionally a
per-RemoteAddr token bucket rate-limits login-begin/pw-begin (10/min, burst 10) — against
enumeration grinding. 429 responses carry `retry_after_secs`.

#### M8.4 API contract (fixed verbatim)

**Common conventions**:
- Base = `http://127.0.0.1:9800` or `http://<VIP>:9800`; API prefix `/api/`; assets at the root
  and under `/static/`. Request/response bodies are always `application/json; charset=utf-8`
  (except assets/wasm).
- **CSRF double gate (mutating = all POSTs)**: the request must carry the header `X-Flock-Web: 1`
  **and** `Content-Type: application/json` — a cross-site form / top-level navigation / fetch in
  a browser cannot satisfy both simultaneously (without a CORS surface, a custom header always
  triggers a preflight that fails with no response) ⇒ stacked with SameSite=Strict, CSRF is
  closed. Missing header ⇒ 400 `bad_request` (does not leak that it was a CSRF block).
- **Unified error envelope (verbatim)**:
  ```json
  {"error": {"code": "<code>", "message": "<whitelisted copy, no paths/internal error strings>"}}
  ```
  code → HTTP mapping (fixed): `bad_request` 400 / `not_logged_in` 401 / `login_failed` 401 /
  `user_disabled` 401 / `bad_token` 401 / `forbidden` 403 / `forbidden_origin` 403 / `not_found`
  404 / `method_not_allowed` 405 / `user_exists` 409 / `password_exists` 409 / `invalid_state`
  409 / `cannot_demote_self` 409 / `payload_too_large` 413 / `rate_limited` 429 (also carrying a
  `retry_after_secs` field) / `internal` 500.
- Limits and smuggling rejection: request line 2KiB, headers 8KiB, body 64KiB; a
  `Transfer-Encoding` or a duplicate `Content-Length` ⇒ 400 with connection close. **Slowloris
  dual-layer read timeouts (review revision)**: 15s per read (half-open) + **a 30s total budget
  per request** (head+body as a whole — byte-dripping that stays under each per-read timeout
  still cannot pass the total budget; on expiry the connection closes and a counter increments;
  keep-alive resets per request) — otherwise the 64 concurrency permits can be held open
  indefinitely, exhausting the admin plane.

**Endpoint contract** (request body → 200 response body verbatim; the role column = session
requirement; the error-code column lists business items only):

| Endpoint | Method | Role | Request → 200 response | Business errors |
|---|---|---|---|---|
| `/api/bootstrap` | GET | public | → `{"cluster_id":"<hex32>","server_id":"<hex32>","identity_pub":"<b64-32B>","lang":"zh-CN"}` | — |
| `/api/login-begin` | POST | public | `{"user":"alice","ke1_b64":"…"}` → `{"ke2_b64":"…","bind_token":"<hex16B>","anchor_sig":"<hex64B>","server_id":"<hex32>"}` (unknown users dummy same shape) | 400; 429 |
| `/api/login-finish` | POST | public | `{"user":"alice","ke3_b64":"…"}` → `{"user":"alice","admin":true}` + Set-Cookie | 401 login_failed; 401 user_disabled; 429 |
| `/api/logout` | POST | logged in | `{}` → `{"ok":true}` + clears cookie | 401 |
| `/api/me` | GET | logged in | → `{"user":"alice","admin":true,"origin":"vpn"‖"loopback","expires_unix":1760000000}` | 401 |
| `/api/users` | GET | **admin** | → `{"users":[{"username":"bob","admin":false,"disabled":false,"has_password":true,"devices":2}]}` (username ascending) | 403 |
| `/api/users` | POST | **admin** | `{"username":"bob"}` → `{"username":"bob","pw_bootstrap_token":"<hex32B>"}` (username constrained 1..=32B, `[A-Za-z0-9_.-]`) | 409 user_exists; 400 |
| `/api/users/{u}/disable` | POST | **admin** | `{}` → `{"ok":true}` | 404 |
| `/api/users/{u}/enable` | POST | **admin** | `{}` → `{"ok":true}` | 404 |
| `/api/users/{u}/reset-password` | POST | **admin** | `{}` → `{"pw_bootstrap_token":"<hex32B>"}` (the old password is invalidated immediately) | 404 |
| `/api/users/{u}/admin` | POST | **admin** | `{"admin":false}` → `{"ok":true}` | 409 cannot_demote_self (target == the session user and admin=false) |
| `/api/pw-begin` | POST | public (token) | `{"user":"bob","token":"<hex32B>","m1_b64":"…"}` → `{"m2_b64":"…"}` | 401 bad_token; 409 password_exists; 429 |
| `/api/pw-commit` | POST | public (token) | `{"user":"bob","token":"<hex32B>","record_b64":"…","profile":0}` → `{"ok":true}` | 401 bad_token; 409 password_exists |
| `/api/peers` | GET | logged in (read-only) | → `{"peers":[{"device_id":"<hex64B>","vip":"100.64.0.11","hostname":"box","owner":"alice","kind":"device"‖"server","online":true,"status":"active"‖"disabled"‖"revoked"‖"expired","last_seen_unix":1760000000,"tx_bps":120,"rx_bps":80}]}` (VIP ascending) | 401 |
| `/api/peers/{device_id}/revoke` | POST | **admin** | `{}` → `{"ok":true,"epoch":43}` (Raft Revoke + the apply hook kills sessions, §2.2 revocation propagation bound) | 404 |
| `/api/peers/{device_id}/disable` | POST | **admin** | `{}` → `{"ok":true,"epoch":44}` | 404 |
| `/api/peers/{device_id}/enable` | POST | **admin** | `{}` → `{"ok":true}` | 404; 409 invalid_state (Revoked/Expired terminal) |
| `/api/peers/{device_id}/kick` | POST | **admin** | `{}` → `{"ok":true}` (semantics: **best-effort local** — kill the local session + detach the local lease; under multi-primary, other servers' sessions are not retroactively touched (the peer's online flag flips to false after its 30s lease TTL expires; an auto-reconnecting device comes back online — kick ≠ ban; for a definitive severance use disable/revoke); the UI confirmation-modal copy says the same) | 404 |
| `/api/dashboard/summary` | GET | logged in (read-only) | → `{"cluster":{"cluster_id":"<hex32>","epoch":42,"sync_mode":"single"‖"raft"},"servers":[{"node_id":1,"vip":"100.64.0.1","endpoint":"ep:9443","leader":true,"epoch":42,"online":true}],"totals":{"devices":7,"devices_active":5,"devices_online":3,"users":4,"tx_bps_sum":0,"rx_bps_sum":0},"self":{"server_id":"<hex32>","uptime_secs":3600}}` | 401 |
| `/api/dashboard/series?vip=100.64.0.11` | GET | logged in (read-only) | → `{"vip":"100.64.0.11","interval_secs":60,"points":[{"t":1760000000,"tx_bps":100,"rx_bps":50},…≤120 items, old→new]}` | 401; 404 (VIP has neither a series nor a registry entry) |
| `/api/config` | GET | logged in (read-only) | → `{"listen_mode":"direct"‖"frp","advertise_endpoint":"…","sync_mode":"single"‖"raft","ticket_ttl_secs":60,"peer_retention_days":30,"max_sessions":1024,"webui":{"port":9800,"session_ttl_secs":28800}}` (**field whitelist: no keys / no srvmesh peer table / no root material**) | 401 |
| `/api/audit` | GET | **admin** | → `{"entries":[{"ts":1760000000,"user":"alice","action":"user.create","target":"bob","origin":"vpn","result":"ok"},…≤200 items, new→old]}` | 403 |

- **Action vocabulary (fixed)**: `session.login / session.logout / user.create / user.disable /
  user.enable / user.reset_password / user.set_admin / peer.revoke / peer.disable / peer.enable /
  peer.kick`; result ∈ `ok|denied|error` (denied is also recorded — including 403 attempts;
  password/token/ticket bytes are never recorded).
- **Assembly semantics**: `/api/peers` = all registry rows (incl. status/device_id) ⋈ the local
  lease view (online/last_seen/EWMA) — the same assembly source as the §7-M7.4 roster, a
  different projection (the roster shows only Active and no device_id; the web surface shows all
  states + device_id for operational addressing). `/api/dashboard/summary`: multi-primary = the
  server_keys local view (node/vip) + the root-signed directory endpoint + the self-published
  lease online + `current_leader`; single-server = one local entry (leader=true, online=true);
  totals.users = the UserRow count (locally applied view — display-tier, same as the roster
  §7-M7.4).
- **Static assets**: `GET /` (index.html), `GET /static/*`; content-type: `.html`=text/html,
  `.js`=text/javascript, `.css`=text/css, `.wasm`=application/wasm; unknown `/api/*` → 404 JSON,
  everything else → **SPA fallback** (index.html 200, landed in M8b — the hash-route
  direct-hit/refresh surface; the 404-JSON face for API clients does not swallow HTML).

#### M8.5 Dashboard data plane: traffic time series (in-memory ring buffer)

- A per-server in-memory ring buffer (**not into Raft, not into gossip** — a local display
  surface): per-VIP `VecDeque<(unix_minute, tx_bps, rx_bps)>` with capacity `series_points`
  (default 120) × `series_interval_secs` (default 60) ⇒ **a 2-hour window**. The sampling task is
  assembled with webui: every interval it takes the current EWMA snapshot of the local traffic
  sources — single-server = `TrafficMeter::stats(vip)` (the server itself via SERVER_TRAFFIC_KEY);
  multi-primary = `LeaseTable::peer_stats(device)` (the server itself via
  `server_self_device_id`; rows without a local lease participate with the latest gossip value —
  the same view as the roster). The VIP↔Device mapping comes from the local registry snapshot;
  after a row disappears (revoked/expired) the series is retained until it naturally rings out.
- **Restart clears it (written down, accepted)** — the ring buffer is pure memory; after a process
  restart the curves start from zero; a VIP on the roster but with no samples returns an empty
  points array (not 404).
- Memory budget: ~3KB per peer (120×24B) × 1k devices ≈ 3MB — accepted.

#### M8.6 Frontend (pages / wasm C-ABI contract / asset inventory)

**Pages** (SPA, hand-written hash routing, no router library):
1. `#/login`: the login page (username/password; failure copy and a lockout countdown).
2. `#/set-password`: the initial/reset password page (bootstrap token + the new password twice;
   via pw-begin/commit).
3. `#/dashboard`: Server cards (node/VIP/endpoint/leader/epoch/online) + summary cards + a
   per-device traffic curve (uPlot, tx/rx dual series; 60s polling of series+summary).
4. `#/peers`: the device table (all fields + status badges + an online dot) + row actions: revoke
   (**a confirmation modal**, Esc/cancel backs out) / disable / enable / force disconnect (kick
   semantics copy consistent with §M8.4).
5. `#/users`: the account table (admin badge/disabled state/device count) + create (the bootstrap
   token **shown exactly once in a modal** + a copy button) / disable / reset password (the same
   token semantics) / set admin.
6. `#/settings`: the read-only config summary + the audit log table (admin).
A non-admin login: dashboard/peers visible; users/settings hidden and direct API hits 403 → the
frontend shows a "no permission" page. Design system: hand-written dark theme (CSS custom
properties: background/surface/border/primary/semantic colors), **system font stack (zero
webfonts)**, components = cards/tables/buttons/badges/modals/form validation states.

**wasm C-ABI contract** (`webauth_shim.rs`, `#[cfg(all(feature = "wasm",
target_arch = "wasm32"))]`; all `#[no_mangle] pub extern "C"`; return 0 = ok, negative = error
code):

```text
sr_wasm_inject_entropy(ptr: *const u8, len: usize)              // called by JS at startup (crypto.getRandomValues ≥32B)
sr_wasm_alloc(len: usize) -> *mut u8 / sr_wasm_free(ptr, len)   // buffer allocation for JS writing args / reading returns
sr_web_login_begin(user_ptr, user_len, pw_ptr, pw_len, out_ptr, out_cap) -> i32
    // WasmRng (GLOBAL_RNG adapter) drives pake::login_start; the ClientLogin state lives in a
    // module-level single slot (Mutex<Option<..>>; a later begin overwrites the previous one);
    // out receives ke1_b64 (NUL-terminated)
sr_web_login_finish(ke2_ptr, ke2_len, server_id_ptr(16B), identity_pub_ptr(32B),
                    bind_token_ptr(16B), anchor_sig_ptr(64B), out_ptr, out_cap) -> i32
    // pake::login_finish_anchored (anchor verification) → out receives ke3_b64
sr_web_pw_begin(user_ptr, user_len, pw_ptr, pw_len, out_ptr, out_cap) -> i32   // reg_start → m1_b64 (state single-slot as above)
sr_web_pw_finish(m2_ptr, m2_len, out_ptr, out_cap) -> i32                      // reg_finish → record_b64
error codes: -1 entropy not injected; -2 pake failure (wrong password/bad message share the code);
-3 anchor verification rejected; -4 out capacity insufficient
```

JS glue `assets/flock_pake.js` (hand-written ~120 lines): `WebAssembly.instantiate` → inject
entropy → expose a Promise API `loginBegin(user,pw)` / `loginFinish(ke2,anchor)→ke3` /
`pwBegin/pwFinish` (internally sr_wasm_alloc to copy args/read returns/sr_wasm_free). argon2
(m=19MiB t=2) is on the order of ~100ms on the main thread — the button spinner state absorbs
it; no worker (v1, stated as-is).

**Asset inventory** (`app/flock-server/src/webui/assets/`, all embedded via include_dir with the
vendored LICENSE files in the same library):

```text
index.html  app.js  i18n.js  style.css  flock_pake.js  flock_pake.wasm  vendor/{alpine.min.js, uplot.min.js, uplot.css}
```

Build: the wasm artifact is produced by `deploy/build-wasm.sh` and copied into assets/ (the
**artifact is committed** — CI can produce the full binary without a wasm toolchain; the gates
additionally run a wasm check + artifact-consistency check against source/artifact drift).

#### M8.7 Security checklist (fixed)

1. **Cookie/transport**: HttpOnly + SameSite=Strict + Path=/ + Max-Age=TTL; **no Secure, no TLS**
   — trust-domain statement (as-is): on loopback, **other local users/processes can sniff the
   plaintext and the cookie** (holding local packet capture is already equivalent to a half
   compromise; loopback administration on a multi-user machine is an informed trade-off); on the
   VPN segment, transport = per-hop E2E (peer↔access server + inter-server FRWD, §2.2/§2.5) —
   invisible to other peers; **the server endpoint itself is visible (the same §2.5-1 boundary;
   no new security claim)**.
2. **CSRF**: SameSite=Strict + the double gate on mutating POSTs (`X-Flock-Web: 1` + JSON
   content-type, §M8.4).
3. **Rate limiting**: the §M8.3 login backoff + per-IP token bucket; 429 carries
   retry_after_secs. Both tables are capacity-capped at 4096 + a 60s periodic sweep (review
   revision — arbitrary user/IP names injected on the unauthenticated surface no longer cause
   unbounded memory growth).
4. **Audit**: mutations and login failures leave records — stderr (journald-managed, the same
   channel as the existing `flock-server:` logs) + the most recent **200** entries in memory
   (`/api/audit`, admin); fields ts/user/action/target/origin/result, **never recording
   password/token/ticket bytes**; user/target have control characters stripped before output
   (review revision — the single-line stderr format cannot be line-injected into forged audit
   rows; at the input layer the four public auth endpoints reject control characters / oversized
   user values).
5. **No leaks**: error messages are whitelisted copy (§M8.4 envelope); `/api/config` has a field
   whitelist; logs never print full ke1/ke2/ke3/record (only lengths and the first 8 characters as
   a diagnostic hint).
6. **Session surface**: sid is 256-bit random, in-memory table, deleted on logout; authorization
   re-reads UserRow — demotion/disable takes effect on an old session's next request (§M8.3,
   review revision); known v1 residual (as-is): a password reset does not forcibly kick other
   in-flight sessions (an old sid stays usable until TTL; the 8h TTL caps the exposure — a reset
   does not set disabled and so does not trigger item 6's immediate-recycling path) — "rotate the
   sid after sensitive operations" is listed for a later batch.

#### M8.8 File placement (fixed)

```text
app/flock-server/src/webui/mod.rs        assembly: loopback first + the VIP-bind retry task (5s); hung into server::run / sync::run_raft
app/flock-server/src/webui/http.rs       minimal HTTP/1.1 (parsing/response/keep-alive/limits/smuggling rejection)
app/flock-server/src/webui/session.rs    session table (issue/lookup/logout/256-cap eviction/sweep)
app/flock-server/src/webui/access.rs     origin matrix + CSRF double gate + role matrix + login backoff + token bucket + audit ring
app/flock-server/src/webui/api.rs        route dispatch + all handlers (calling NetBackend / pake / roster assembly)
app/flock-server/src/webui/series.rs     traffic ring buffer + the sampling task
app/flock-server/src/webui/assets.rs     include_dir embedding + content-type + Cache-Control
app/flock-server/src/webui/assets/…      frontend assets (the §M8.6 inventory)
app/flock-server/tests/webui.rs          HTTP e2e (login driven by a native-Rust OPAQUE client — bypassing wasm; protocol-isomorphic)
app/flock-server/examples/webui_login.rs the HTTP-OPAQUE driver (the CLI vehicle of webui_assert.sh: login/CRUD probes)
crates/flock-protocol/src/webauth_shim.rs the wasm C-ABI shim (feature wasm+anchor gated)
deploy/build-wasm.sh                     wasm build + artifact copy into assets/ + consistency check
deploy/webui.yml / webui_assert.sh       container integration assertions (§M8.9 W1–W7)
docs/manual/webui-checklist.md           browser real-machine checklist (M8c)
```

Dependency changes: flock-server gains `serde_json` (already in the workspace lockfile) and
`include_dir` (new, a small proc-macro-level crate); flock-protocol gains no new dependencies
(feature composition only). Code touch points: the config.rs `[webui]` section + the port-conflict
validation; the main.rs `web-admin-add` subcommand; admin.rs tail-appends `WebPwBegin/
WebPwCommit`; control.rs `LoginBegin` gains the disabled determination (§M8.3).

#### M8.9 Test plan (verifiable assertions)

**Unit tests** (`cargo test -p flock-server` / `-p flock-sync`):
- session.rs: issue/hit/expiry-reject/logout-delete / **256-cap oldest eviction** / lazy +
  periodic sweep;
- access.rs: the origin matrix (127.0.0.1, 127.3.2.1, [::1] allowed; 100.64.0.11 allowed;
  192.168.x.x, 8.8.8.8 ⇒ 403 forbidden_origin); CSRF (a POST missing the custom header 400; with
  the header but missing the JSON content-type 400); **the role matrix per endpoint, three states
  enumerated** (not logged in 401 / non-admin 403 / admin 200, including the order of 401 vs 403
  — session first, then role); login backoff (injected clock: 5th locks 30s, doubling, 900 cap,
  success clears);
- http.rs: request vectors (a legal GET/POST round trip; a bad request line / oversized headers /
  oversized body 413 / Transfer-Encoding 400 / duplicate Content-Length 400 / half-packet timeout
  closes the connection);
- series.rs: an injected clock sampling at fixed points → ring-out caps at 120 → a new instance
  starts empty (restart semantics) → the series is retained after the row disappears;
- flock-sync: UserRow round trips (new fields), the five new write variants' semantics (UserExists
  / a wrong token BadBootstrapToken / token replay rejected / the old password record invalidated
  after ResetPassword / enabling a terminal-state device rejected), and old snapshots failing
  cleanly as undecodable.

**Integration** (tests/webui.rs, real HTTP in-process + a native pake client — protocol-isomorphic,
bypassing wasm): not logged in, everything except the public endpoints is 401 (all endpoints
enumerated); first-admin bootstrap (the web-admin-add path function) → reg/login (anchor
verification passes) → cookie session → the me/peers/dashboard/series/config/audit read-write
full chain; the non-admin 403 matrix; cannot_demote_self; user_exists/password_exists/bad_token/
token replay; the audit ring shows entries (including denied rows); after logout the original sid
gets 401. wasm gate: `cargo check -p flock-protocol --target wasm32-unknown-unknown
--no-default-features --features wasm,anchor`.

**Container integration** (deploy/webui.yml: reusing the multinode two-server + client topology;
webui_assert.sh assertions):

| # | Assertion |
|---|---|
| W1 | Not logged in: all admin APIs 401 (curl 127.0.0.1:9800 inside the server-a container) |
| W2 | loopback login → the full CRUD chain: `web-admin-add` (password fed via a pipe) bootstraps the first admin → examples/webui_login drives the HTTP-OPAQUE login → users create/disable/reset/set-admin → peers list/revoke → dashboard/series → audit contains the corresponding rows |
| W3 | A non-admin account: read-only endpoints 200, users*/revoke/kick/audit 403 |
| W4 | Inside the client-1 container (the flockpub network, flock-client's network namespace), `curl http://100.64.0.1:9800` (server-a's VIP) is reachable and the login chain works (the VPN-segment path proven live) |
| W5 | From client-1, curl to server-a's flockpub/LAN address :9800 is **unreachable** (timeout/refused — the connection-layer proof of the unbound surface) |
| W6 | Both server VIPs (100.64.0.1 / 100.64.0.2) are reachable and **the data agrees**: after logging in to each, the (device_id, vip, owner, status) sets from /api/peers are strictly identical (ewma/last_seen compared with tolerance — the same tier as §7-M7.6); the /api/users lists agree (after Raft convergence) |
| W7 | Config validation: `[webui] port=9443` (conflicts with bind) refuses server start; the config surface has no bind key (structural misconfiguration-proofing — unknown toml keys are ignored, so the webui section uses an explicit whitelist key set) |

**Browser visual checks = the real-machine checklist** (docs/manual/webui-checklist.md, M8c):
login/account creation (the token shown once)/Dashboard curve refresh/the revoke confirmation
modal/the dark theme across Chrome/Edge/Firefox; an optional headless smoke (asset content-types +
wasm downloadable) goes into CI.

#### M8.10 Milestone split and completion criteria

- **M8a server + API + an embedded shell page**: the whole webui module (http/session/access/
  api/series/assets with a skeleton shell page), the UserRow/Raft extensions and the five write
  variants, the CLI web-admin-add, tests/webui.rs. The browser surface is a shell page only (no
  wasm — login unavailable for now; all behavior verified by the Rust client). Completion
  criteria: unit + integration all green; clippy/fmt/gates; containers W1–W3, W5, W7 all PASS.
- **M8b frontend + wasm**: webauth_shim + build-wasm + all pages + vendored assets embedded.
  Completion criteria: the wasm check gate green; the browser real-machine checklist
  (login/account creation/dashboard/revoke) all passing; W4, W6 PASS (W4's login chain can be
  executed on the client's behalf by webui_login inside the client container).
- **M8c review + live testing**: the security checklist re-checked item by item (§M8.7), the
  three-machine W6 extension for multi-primary (including the follower stale-view tier), CPU/
  memory sampling under 120-point polling, and the deployment-doc section (ports/access methods/
  trust boundaries/no reverse-proxy promise).

---

## 8. Risks and countermeasures

| # | Risk | Basis | Countermeasure | Residual |
|---|---|---|---|---|
| R1 | tun unavailable under Windows Docker Desktop | vpn-mesh §1.3 | **Eliminated by live testing**: on the WSL2 backend, both paths — `--cap-add NET_ADMIN` + `--device /dev/net/tun`, and mknod — successfully created devices (Appendix B-2/3) | Hyper-V/VMM backend unchecked → the deployment constraint pins WSL2 and it goes into the deploy/README |
| R2 | ChmlFrp's real node untested (needs a real-name account) | frp-compat gaps#1 | automation uses original frp ×2; protocol consistency rests on the byte-transparency argument (§1.4) + golden files (config side) + the ChmlFrp source-diff evidence; re-test R1/R6/R7 once an account exists | relay-side residuals (node rate limits / long-connection policies) can only be verified on a real node |
| R3 | TCP-over-TCP weak-network performance collapse | vpn-mesh §3.2 (Titz 2001) | per-stream rate limiting / queue management; MTU 1280 controls the inner MSS; long-term a UDP direct path (self-hosted node xtcp / in-house) | accepted in the first version (that is the form); documented |
| R4 | The in-house handshake has no formal verification | this design §3.5 (the reasons for not using snow) | structurally replicates Noise IK / WireGuard constants; transcript test vectors gate M1; labeled "experimental" until an external audit; libcrux watched as an alternative | implementation-defect risk exists until M1 vector coverage |
| R5 | opaque-ke 3→4 / dalek 2→3 API-generation migration breaks compatibility | P1-6 | fixed-vector interop tests = the hard M1 gate; if they fail, pin the old versions and open a migration branch | — |
| R6 | ChmlFrp free tier 8Mbps + 4-tunnel cap | frp-compat §2.1 | the single-tunnel multi-session multiplexing (yamux) design is final; production throughput expectations managed in the docs | the bandwidth hard cap is unsolvable (paid tier or a self-hosted node) |
| R7 | The official frp Windows exe gets blocked by local security policy | frp-compat gaps#4 (proven during this research) | server-side frpc all runs in Linux containers (FRPS_LINUX_OK verified); Windows clients need no frpc (they dial the user port directly) | an frpc distributed to third-party Windows users needs signing/allowlisting assessment |
| R8 | zstd C toolchain cross-platform / cross-compilation | compression-2026 §5 | Windows/MSVC proven compilable; **the container path was tested live**: rust:1-slim-bookworm ships cc/gcc and zstd-sys vendored compiled successfully (Appendix B-9, 7.67s) — the slim image suffices; lz4_flex pure-Rust fallback | the musl static-linking path to be verified within M1 |
| R9 | Multi-primary Raft over a relay with high RTT → election jitter | vpn-mesh §5.3 constraint recap | heartbeat/election timeouts tuned to the relay RTT (M4 calibrates with an injected 100ms RTT); 3 voters minimum | transnational relays with RTT>500ms need measured tuning |
| R10 | VORACLE/CRIME length side channel | compression-2026 §3.2 (all preconditions hold) | compression off by default + policy-enabled + padding + non-expansion fallback (P0-4 all landed) | sessions with compression enabled retain a residual channel — stated for admins |
| R11 | yamux/TCP head-of-line blocking | vpn-mesh §4.2 (RFC 9113 states TCP HOL is irremovable) | control flow at high priority + flow-control backpressure; accepted as a property of the form | a UDP path is the only cure; long-term |
| R12 | The ML-DSA crate is unaudited | crypto-2026 §5 | `pq-sign` off by default; enabling requires explicit opt-in plus reading the risk note | — |
| R13 | wintun.dll distribution (Windows client) | vpn-mesh §1.1 (the driver is GPL; the officially signed DLL has a distribution exception) | tun-rs has built-in wintun integration; ship the official signed 0.14.1 DLL with the program | antivirus false positives follow the R7 policy |
| R14 | The in-memory SR-SIG1 nonce table's multi-primary restart replay surface | verdict §3.6 | replay-state ownership by tier (§2.4): short-TTL tickets + Raft duplicate checks for critical operations + session counters | high-frequency per-request nonces are not strongly consistent — an engineering trade-off, documented |
| R15 | The multi-primary sealing surface for session tickets / shared secrets widens | VPN-15 | per-server independent hybrid pubkeys + the rewrap permission point (§3.10); the ticket key root rotates through Raft | — |
| R16 | TOFU first-login online-MITM takeover (the same class of limitation as SSH known_hosts) | this design §1.3.3f/§2.5-3 (verdict §3.9 only partially closed) | organizational deployments enforce the strong invite-file path (with static hybrid pubkeys + signature binding); the TOFU first-connect fingerprint-confirmation UI must not be silent | a residual accepted for personal self-hosting, documented |
| R17 | Cross-peer traffic plaintext on the access server + any server can offline-dictionary all passwords | §2.5-1/2 (fundamentally different from Tailscale's peer-E2E property) | the boundaries are written explicitly into the deployment docs; server host hardening + admission red lines (§4); long term: a peer inner-E2E overlay, OPRF key thresholding | accepted in the first version; guards against "misreading it as peer-level E2E" |
| R18 | A reconnect storm drives all linearizable reads into the Raft leader | the §1.3.3c lookup seam | the DeviceDirectory two-level read: an epoch-cache hit answers locally; only an epoch change/miss goes linearizable (§4 reads and caching) | when a revocation coincides with the storm, short-term leader pressure (tolerable for a low-write workload) |
| R19 | Cluster admission infiltrated by a fake node (a snapshot/rewrap is an OPRF key leak surface) | §4 admission red line | the cluster root key kept offline; the server-server profile with mutual enrollment credentials; add_voter/rewrap are Raft admin operations requiring root-key signatures | root key leakage = full-network re-bootstrap (the disaster-recovery path documented) |
| R20 | The ChmlFrp `-u/-p` bootstrapped usertoken travels over InsecureSkipVerify HTTPS | frp-compat §2.2 (api.go:30-46) | the `-c` config-file mode by default (pasted from the panel export); UserTokenAuto explicit opt-in + risk labeling | if a user insists on -u/-p mode, a panel-account takeover surface exists |
| R21 | A cross-server routing black hole inside the stale-lease window (device migration period) | the §2.2 fault-tolerance policy (vpn-mesh §5.2 explicitly a policy decision) | NOT_HERE → a one-shot location_query redirect + drop/ICMP on failure (no cached retries); assertion A15 gives a ≤35s recovery bound | migration-window packet loss is recovered by upper layers |
| R22 | A malicious device holding a valid session forges another's source VIP (identity framing/reflection/future ACL bypass; rp_filter does not cover userspace streams) | §2.2 step 0 (vpn-mesh §2 borrowing point 3, "per-node ingress filtering") | the session DeviceId ↔ src VIP binding check (mismatch drop + count + disconnect on excess), the ForwardEnvelope src_dev cross-check; the A14 forged-source assertion | — |
| R23 | An unredeemed invite file leaking = being redeemed once ahead of the owner within expiry, joining the network | the §1.3.3f life of an invite | invite_id goes into Raft for single consumption (second time rejected) + revoke_invite revocation + expiry default 7 days + the file managed as a one-time credential (0600) | the front-run redemption window exists (the same boundary as innernet), stated in the deployment docs |
| R24 | A lagging follower (partition recovery / catching up) lets the local cache pass an already-revoked device | the §4 stale-read boundary disclosure in reads and caching | apply-lag >2s circuit-breaks the local cache and degrades to linearizable reads + the ticket epoch/TTL 60s backstop; the M4 5s-lag case | the ≤2s pass window inside the breaker threshold matches the A6 budget (the health precondition made explicit) |
| R25 | The traps of the three-way choice for the multi-server pinning model (shared keys destroy per-server sealing / per-server TOFU doesn't scale / switching degrades to 2-RTT) | the §1.3.3f finalization rationale (third-round review blocking) | option ②: the client anchors the cluster root pubkey + the root-signed ClusterDirectory with the full material set (the endpoint↔material mapping signed together against splices); key rotation = a root-signed new entry + dir_pull; every endpoint 1-RTT | root key leakage = full-network re-bootstrap (the same disaster path as R19) |
| R26 | The architecture tightly binding frp causing superfluous processes/failure surfaces in the direct scenario (servers that could be reached directly forced to run frpc: a superfluous subprocess, config generation, the ChmlFrp 3-exit supervision, relay bandwidth bottleneck and failure point) | the user's hard constraint (round four, §0) — **eliminated**: ListenerMode `Direct` default, the Direct code path never touches flock-frpc; frp demoted to an optional adapter for the "no public IP / unreachable" scenario (§2.1/§2.2/§3.11/§5) | gating assertions: the M2 `m2-direct.yml` direct-connection smoke (no frps, no frp process in the container) + M5 A16 (Direct/Frp mixed in one topology) | — |
| R27 | The M8 web admin plane widens the attack surface: no TLS (sniffable on loopback / plaintext on the VPN segment at the endpoint), password brute force, CSRF, in-house HTTP parser defects | §7-M8.2/M8.7 (the access matrix and security checklist) | the dual binding structurally excludes LAN/public (the config has no bind field); OPAQUE (password never on the wire) + login backoff + a per-IP token bucket; SameSite=Strict + the custom-header double gate; HTTP subsetting (rejecting chunked/duplicate Content-Length — not implementing ambiguous features means no smuggling surface) + malformed-request test vectors; auditing + whitelisted error copy; no reverse-proxy promise | loopback sniffing on multi-user machines (an informed trade-off, documented); the endpoint is visible inside the VPN segment (the same §2.5-1 server boundary) |

---

## Appendix A: the 16 upgradeList items → design placement cross-reference (none omitted)

| # | Upgrade item (verdict §4) | Placement | Milestone |
|---|---|---|---|
| P0-1 | Encapsulation replaced with the X25519+ML-KEM-768 hybrid KEM (RSA compatibility tier) | §1.3.3a `kem`, §1.3.3b `envelope` v2 (compatibility strategy = a migration window rather than dual encapsulation; rationale in §1.3.3a) | M1 |
| P0-2 | Session/tunnel-tier AEAD discipline (counter nonce/rekey/hard reject/forgery disconnect) | the §1.3.3c `session` record layer; the envelope-tier precondition documented | M1 |
| P0-3 | Envelope v2 segment AAD (v1 read-only) | §1.3.3b | M1 |
| P0-4 | Compression hardening (off by default/policy-enabled/padding/non-expansion fallback) | the §1.3.3e `compress` | M1 |
| P0-5 | First-login trust anchor/TOFU/invite system/bind_token coverage | the §1.3.3f `trust` (invite v2 contains the static hybrid pubkey + signature binding) + the §1.3.3c handshake R0/R1 signatures and the TOFU 2-RTT first connection + the §1.3.3d `anchor` + residual risk §2.5-3 | M1/M2 |
| P1-6 | crate generation upgrades (aes-gcm 0.11.1/opaque-ke 4.0.1/dalek 3.0.0/rand 0.9) | the §1.3.2 dependency generations; bench threshold | M1 |
| P1-7 | Compression tier rework (pass-through/dictionary/chunked/lz4/context reuse/level19 archive tier) | §1.3.3e | M1 |
| P1-8 | AEAD fallback tier (XChaCha20-Poly1305/AES-256-GCM-SIV) | the §1.3.3c `AeadPreference` | M1 |
| P1-9 | Transport framing and multiplexing (yamux/EOF/keepalive/free first byte) | the §1.3.3d `mux` (yamux 0.14.1 running inside the encryption) | M1 |
| P1-10 | Handshake 1-RTT Noise-IK + hybrid KEM/roaming/reconnect = new handshake/10s keepalive | §1.3.3c (two forms: pinned 1-RTT / TOFU first-connect 2-RTT; the UKS signature coverage contract) | M1 |
| P2-11 | OPAQUE maintenance (4.0.1/argon2 profile/RFC 9807 erratum) | §1.3.2/§1.3.3h | M1 |
| P2-12 | Signature maintenance (dalek 3.0/ML-DSA-65 kid dispatch reserved) | §1.3.3g | M1 |
| P2-13 | nonce-length doc correction (implementation rules: 16B/32hex) | §1.3.2 (library docs + the showroom-side migration note) | M1 |
| ★VPN-14 | tun data-plane interface (framing/tun-rs/rtnetlink/MTU 1280/mobile fd seam) | the §3.6 `PacketChannel` + the §3.12 `TunDevice` seam + §2.3 | M3 |
| ★VPN-15 | Multi-primary active-active sync interface (strongly consistent state machine/gossip leases/ticket delegation/re-sealing permission point) | the §3.10 `flock-sync` + §4 (incl. cluster admission/rewrap authorization) + §2.4 + §2.2 (the ticket contract/revocation propagation bound/cross-server forwarding plane) | M4 |
| ★VPN-16 | frp relay adaptation interface (heartbeat/link-loss reconnect/no half-close reliance/single-tunnel multi-session/frpc dual-stack supervision) — **an optional adapter, not a prerequisite: Direct defaults to zero frp logic (the §0 hard constraint/§3.11)** | §1.4 (protocol-side constraint; direct and relayed isomorphic) + the §3.9 `flock-frpc` (assembled only in Frp mode) + §5 + the §2.1 access endpoint model; gates = M2 m2-direct + M5 A16 | M2/M5 |

## Appendix B: verifications performed in this session (commands and key outputs)

1. `docker version` / `docker info` → Client 29.8.2 (windows/amd64, context desktop-linux);
   Server "Docker Desktop 4.95.0" Engine 29.8.2 linux/amd64,
   Kernel `6.18.54.1-microsoft-standard-WSL2` ⇒ the WSL2 backend.
2. `docker run --rm --cap-add NET_ADMIN --device /dev/net/tun debian:bookworm-slim sh -c '… ip
   tuntap add mode tun dev flocktest0 && ip link set … up && ip addr add 100.64.0.1/32 …'`
   → `3: flocktest0: <…,UP> …` + `TUN_CREATE_OK` (under Git Bash, `MSYS_NO_PATHCONV=1` is needed
   to stop `/dev/net/tun` being rewritten into a Windows path — without it on the first try it
   reported `adding custom device "C"`; located and worked around).
3. `docker run --rm --cap-add NET_ADMIN debian:bookworm-slim sh -c 'mknod /dev/net/tun c 10 200 …
   && ip tuntap add …'`
   → `MKNOD_PATH_OK` (the fallback path without the --device argument also works).
4. `curl -sL -o frp_linux_test.tar.gz …/frp_0.71.1_linux_amd64.tar.gz` (14,140,587B) +
   `docker run … -v …/frp_0.71.1_linux_amd64:/frp:ro debian … /frp/frps --version` →
   `0.71.1` + `FRPS_LINUX_OK`.
5. `ls .tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/` → `frpc frps frpc.ini frps.ini …`
   (the pinned ChmlFrp Linux binaries in place); `ls .tmp/frp-src .tmp/frp-test .tmp/cryptobench`
   → the upstream source / pass-through experiments / the benchmark project all in place (the
   assets described in the frp-compat appendix are real).
6. `cargo --version` → 1.98.1; `rustup target list --installed` →
   `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `wasm32-unknown-unknown`.
7. showroom source spot checks (read-only): `opaque.rs:1` (the RFC 9380 misreference),
   `opaque.rs:32-39` (the Suite), `opaque.rs:42` (the SERVER_ID literal), `opaque.rs:53-70`
   (argon2id parameters and salt), `lib.rs:48-55` (constants), `lib.rs:376-412` (the seal
   layout/random nonce/no AAD), the Cargo.lock versions (aes-gcm 0.10.3/argon2 0.5.3/
   ed25519-dalek 2.2.0/opaque-ke 3.0.0/rand 0.8.8/rsa 0.9.10/zstd 0.13.3), `Cargo.toml:3`
   (workspace members) — consistent with the verdict §0 spot-check table.
8. Not executed: cargo build of the Rust project in a container (the repo has no code yet); a
   cryptobench re-run (the verdict re-check round already re-ran it; this session takes its output
   on trust); ChmlFrp real-node connectivity (needs an account).
9. The rust slim image cc check + zstd vendored in-container compilation (revision round,
   triggered by a non-blocking review item, **tested live**):
   `docker pull rust:1-slim-bookworm` succeeded; `docker run --rm rust:1-slim-bookworm sh -c
   'which cc gcc clang; cc --version'` → `/usr/bin/cc`, `/usr/bin/gcc` (no clang),
   `cc (Debian 12.2.0-14+deb12u1) 12.2.0` — **the slim image ships cc/gcc** (the rust image's
   rustc needs a linker, and the official slim variant also installs gcc; the review's assumption
   "per official image convention, no gcc" contradicts the measurement; the measurement rules).
   Further, `cargo new + cargo add zstd@0.14 + cargo build --release`
   → `Compiling zstd-sys v2.1.2+zstd.1.5.7 … Finished release in 7.67s`,
   `ZSTD_BUILD_CHECK_DONE` — the zstd vendored C compilation path works end to end inside the
   container. Note: the full workspace's in-container build still awaits M1 (the repo has no code
   to build yet).

---

## Appendix C: revision history

- 2026-10-31 round two (review: 4 blocking + 9 non-blocking, all absorbed):
  1. **B1**: the handshake's two forms finalized — the invite file v2 must contain the server's
     static hybrid pubkey (1216B) bound to the identity signature (a fingerprint is a hash and
     cannot be encapsulated to); the TOFU first connection is 2-RTT (I0→R0 presents the static
     pubkeys → I1/R1); the norm is 1-RTT (§1.3.3c/§1.3.3f); the UKS signature coverage contract +
     the M1 failure vectors added.
  2. **B2**: the `lookup` seam becomes an async `trait DeviceDirectory` (BoxFuture) with the three
     states `LookupVerdict{NotFound,Revoked,Active}`; `Tunnel::open_stream/open_packet_channel`
     made async; the two-level "reads and caching" policy added to keep reconnect storms from
     punching through the leader (§1.3.3c/§3.5/§4).
  3. **B3**: the cross-server data plane completed — ForwardEnvelope/hop=1 loop prevention/
     NOT_HERE fallback/lease-miss fault tolerance (drop + ICMP, no cached retries) (§2.2); A2 pins
     the cross-server access mapping, and the A14 cross-server-plane assertion added.
  4. **B4**: the cluster admission design — the cluster root key (offline) + enrollment
     credentials + the server-server profile with mutual authentication;
     learner→snapshot→add_voter→rewrap all require root-key-signed admin operations (§4/§3.10);
     M4 gains the admission test group.
  5. Non-blocking: the four §2.5 threat-model boundary items (cross-peer plaintext / the OPRF
     offline-dictionary surface / the TOFU residual / the relay); the mandatory ticket contract
     (state changes must carry a ticket; validation precedes nonce accounting; the replay window =
     min(300s,TTL)); the revocation propagation bound parameterized (apply ≤2s + event ≤1s +
     slack; ticket TTL 60s; lease TTL 30s/anti-entropy 5s); the ChmlFrp supervision default `-c`
     mode (the usertoken InsecureSkipVerify risk goes into R20); the Windows real-machine manual
     checklist into M3/M5, macOS marked not verified; the contradiction between the build image
     and R8's "slim has no cc" resolved **by measurement**: rust:1-slim-bookworm ships cc/gcc and
     zstd-sys vendored compiles in-container (Appendix B-9); §6.2 split into the
     chmlpub/srvmesh/link three networks + frpc sidecars + the A13 direct-unreachable assertion +
     the A15 lease fault-tolerance assertion.

- 2026-10-31 round three (review: 1 blocking + 4 non-blocking, all absorbed):
  1. **blocking · the multi-server pinning model finalized (option ②)**: the client anchors the
     **cluster root pubkey** and holds the root-signed **ClusterDirectory** (the full
     ServerEntry set = the enrollment credentials' public part; the endpoint list and credentials
     signed in one document against splices); every endpoint 1-RTT (I1 encapsulates to the target
     server's own static KEM pubkey); the TOFU first connection pins only the root (R0 carries the
     enrollment credential chain); key rotation = a root-signed new directory entry + dir_pull;
     the shared-server-keys option explicitly rejected (destroys per-server sealing / the rewrap
     permission point) as was switching degrading to 2-RTT (§1.3.3c/§1.3.3f/§3.8/R25). The A5/A15
     wording aligned to "every endpoint 1-RTT; I0 must not appear".
  2. Non-blocking: §4 reads and caching gains the **stale-read boundary disclosure + the
     apply-lag>2s circuit breaker** (R24, the M4 5s-lag case); the §2.2 forwarding decision order
     gains the **step-0 source VIP binding check** (R22, the A14 forged-source assertion —
     rp_filter does not cover userspace streams); **the single source of truth for device location
     = the lease domain** (NetState does not store current location; the NOT_HERE fallback becomes
     a one-shot location_query, eliminating Raft write storms and dual-source inconsistency); the
     **invite lifecycle + the provisioning flow** fixed (invite_id into Raft single consumption,
     revoke_invite, expiry default 7 days, the user/device/password three-way separation, R23;
     the M2 provisioning tests).

- 2026-11-01 round four (**the user's hard constraint: ChmlVPN must not be tightly bound to
  frp/chmlfrp**, highest priority):
  1. §0 gains the hard-constraint statement and the layering diagram changes (access endpoint =
     Direct default / Frp optional; frp serves only the "no server public IP or the client cannot
     dial directly" scenario; when directly reachable, no frp logic is executed).
  2. the §2.1/§2.2 access endpoint model: one access endpoint per server; `server.toml`
     `listener.mode`, one of two, **Direct default**; mixing allowed within one cluster; the two
     forms isomorphic to the protocol layer.
  3. the §3.11 `ListenerMode` seam (Direct direct listen, zero frp logic / Frp(RelaySpec) via the
     Supervisor); the Direct branch instantiates no Supervisor, generates no config, has no
     chml-frpc type references; §3.9/§5 labeled "assembled only in Frp mode; an optional adapter,
     not a prerequisite".
  4. §1.3.3f/§3.8: `ServerEntry.relay_endpoint` renamed `access_endpoint` (+ the endpoint_form
     annotation); the semantics = the access endpoint (a direct address or a relay user port,
     indistinguishable to the client); client routing/liveness probing unchanged.
  5. §6/§7: M2 gains the direct-connection smoke variant `deploy/m2-direct.yml` (no frps; host
     mapping, direct dial; `pgrep frp` empty in the container); §6.2 server-c switches to the
     Direct form directly on chmlpub (the frpc-c sidecar removed) + the new client-3 direct dial;
     A13 narrowed to the Frp-form server-a/b only; the new A16 (Direct session connectivity + no
     frp process in the container + Direct↔Frp cross-server forwarding isomorphic); the M5
     assertion range A1–A16; the R table gains R26 (the risk this constraint eliminates). The
     A2/A5/A15 semantics are unaffected (client-1/2's access mapping and cross-server paths
     unchanged).

- 2026-11-01 naming adjustment: chml-protocol → flock-protocol (the protocol layer independent of
  the chml/frp brands; flock = a flock of geese, the image of a small distributed network; zero
  behavior change).
- 2026-11-02 project rename: ChmlVPN → Flock VPN (chmlvpn-server/client→flock-server/client,
  chml-sync/frpc→flock-sync/frpc, the network chmlpub→flockpub, the placeholder git URL switched
  to the flock domain; flock-protocol's wire behavior unchanged). The repository directory renamed
  to FlockVPN in sync — while the session held it, transitioned via a junction (the two host paths
  equivalent; inside Docker mounts only the real path visible; container commands temporarily used
  the ChmlVPN path); the closing steps are in docs/manual/dir-rename-final.md.
- 2026-11-06 M6 phase one (system service + the daemon-side control plane): added §7-M6 — the
  two-process model (`flock-client service`, the system service holding all supervise/data-plane
  logic + `flock-client tray`, the user-session tray via local IPC; the Windows session-0 tray
  constraint settled); the control IPC v1 contract (postcard over a named pipe/Unix socket + a
  32B token envelope authentication, **every request carries the token** — tighter than "only
  Shutdown carries a token"; Status is never left bare); service installation on the three
  platforms (Windows AUTO_START + a recovery policy / systemd Restart=on-failure / launchd without
  KeepAlive) + tray autostart + the `install/uninstall/status` subcommands + the `tray` feature
  gate (cargo's lack of per-platform default features stated as-is; the GUI dependencies left
  target-gated for phase two); the quit semantics finalized (Shutdown = graceful stop without
  revival; the service stays installed). The IPC contract frozen as the `flock_client::ipc` module
  for the tray project to consume standalone.
- 2026-11-06 M7 (member roster and observability, server side): added §7-M7; **the §2.1 IP reuse
  policy revision** (revoked → never reused, unchanged; offline past retention → Expired + VIP
  back to the pool, the record kept for audit, excluded from the roster; `peer_retention_days`
  default 30, 0 = never expire, compatible with the old behavior); the registry's DeviceRow gains
  `hostname/expired_at` + `DeviceStatus::Expired` (terminal) + the VIP release pool (the
  snapshot/wire-format compatibility stated as-is: postcard has no field tags; old snapshots
  cannot be decoded — acceptable in the pre-release window); the dynamic plane rides the leases
  (lease entries + gossip carrying per-device EWMA traffic and last_seen, α=0.2/1s window; the
  "count at the successful-delivery point" single-point principle against double counting); the
  roster contract `CtrlRequest::PeerListPull` (ticket first) → `Vec<PeerInfo>` (VIP ascending,
  including Server entries); the 60s reaper setting Expired.
- 2026-11-07 M7 second batch (member roster, client side): added §7-M7.7 — the contract types
  hoisted to `flock-protocol::roster` (PeerInfo/PeerKind/the TicketWire wire formats + the
  control-plane messages + the key-bind canonical + hostname normalization; the same types on
  both ends with no second source of truth; server/sync re-export via `pub use`); the client-side
  control-flow half (credentials as a 0600 single line + `[auth] username`; `login` as a one-time
  bootstrap = set password → login verification → hostname onto the roster; the daemon's
  login-keep = anchor verification + key-bind re-register + the ticket in memory only + the
  TTL·2/3 relative-quantity re-login + timeout-poisoning kill-and-reconnect); the IPC gains
  `Peers{token}` (a ≤5s roster cache + concurrent raw-ICMP probing of online non-self entries: a
  thin socket2 layer, 3 probes, 2s timeout, upper median; raw without permission degrades to "—";
  MAX_CTRL_FRAME 4KiB→256KiB); `flock-client peers` (an aligned table: the status three-state
  online/offline/service not running + the `--json` machine-readable build); container live test
  `deploy/m7.yml` + `m7_assert.sh` (two clients + server: entries/latency/the iperf3 traffic
  column/JSON); Windows/macOS raw ICMP real machines listed on the service-install.md §7
  checklist.
- 2026-11-06 M6 phase two (the tray process): added §7-M6.7 (the §7-M6.4 tray row synced) —
  `flock-client tray` landed: the three-item menu (connection status / VPN IP as dynamic
  read-only + quit as the action), 2s polling refresh, Denied/IPC failure ⇒ "service not running"
  with continued retrying; quit = token Shutdown ⇒ the tray exits (the service stays installed) /
  daemon absent ⇒ quit the tray only / Denied ⇒ no exit + the token-stale reload; the
  programmatic 32×32 RGBA icon (zero asset files); the platform libraries tray-icon (Windows
  minimal Win32 message pump / macOS main-thread NSApp drain loop) + ksni (Linux DBus SNI, zero
  GTK system dependencies); no winit/tauri/egui; GUI detection (Linux DISPLAY/WAYLAND + session
  DBus pre-checked; win/mac fall back on creation failure); no GUI always exits gracefully with
  code 0; the M6.5 feature gates delivered (all GUI dependencies target-gated optional; `dep:`
  references are no-ops on non-matching targets; --no-default-features gives a zero-GUI-dependency
  compile surface on all three platforms — gates verified by testing). Verification boundaries
  as-is: core unit tests + a real Windows process against a mock daemon (alive/refresh logs/state
  consistency/after a token Shutdown stops the daemon, the tray shows "service not running");
  icon visuals / the quit click / a real-daemon joint test (needs invite + administrator) are on
  the service-install.md tray real-machine checklist; macOS unverified (no device; the apple
  target toolchain downloaded too slowly for compile-level verification; the API checked against
  crate sources); the Linux desktop real machine unverified (the container compile surface
  passed).
- 2026-11-07 M6/M7 server/sync-layer review fixes (6 items in this batch): ① the reaper's
  last_seen=0 semantic flaw (fixed in §7-M7.5) — DeviceRow gains `registered_at` (injected by the
  submitter at registration/redemption and persisted; without observation it anchors the retention
  clock) + the restart/view-not-ready gate (single-server = skip when the traffic meter has zero
  observations; multi-primary = skip when the lease table is empty / no remote events;
  `LeaseTable::remote_events` signal + the anti-entropy loop self-filtering); ② the server_vip_of
  consistency assertion in both forms (multi-primary open_sync asserts cfg.vip == the derived
  value, giving the expected value on error; single-server rejects startup when the VIP collides
  with the device allocation segment); ③ NetError::DeviceExists as its own variant (eliminating
  the "already registered" string contract) + the KeyBind re-register owner check (a cross-owner
  hostname change ⇒ NotAuthorized); ④ the systemd unit path corrected (/etc/systemd →
  /etc/systemd/system, sample + docs; the install.rs constant synced from the client-side
  same-named item) + the launchd plist gains StandardErrorPath and a newsyslog rotation
  suggestion; ⑤ the CtrlResponse variant-position discipline frozen (the frozen zone before Err,
  new variants append at the tail; PeerList moved after Err) + the lease EWMA offline decay
  (expired without accumulation decays ×4/5 per window until <8B/s, then 0 — the roster shows no
  non-zero traffic for offline devices) + a §7-M7.2 wording fix ("the same device identity
  revived" → "a new device identity (new keys) registers a new row with a new VIP"; the same keys
  re-registering goes through re-register's hostname update).
- 2026-11-07 M8 (server Web UI, design supplement): added §7-M8 — the in-process embedded HTTP
  admin plane (**an in-house minimal HTTP/1.1, not axum**: Cargo.lock has no tower-family
  artifacts; the exposure surface is loopback+VIP only; the subset rejects chunked/duplicate
  Content-Length); **dual binding 127.0.0.1:9800 + cfg.vip:9800** (the config exposes no bind
  field — a 0.0.0.0 misconfiguration is structurally impossible; loopback first while tun is
  unready, the VIP re-bound by a 5s retry); the access matrix W-A1–A4 (loopback/100.64.0.0/10
  allowed, everything else 403 as depth; no reverse-proxy promise); authentication = **OPAQUE
  reuse (new same-semantics HTTP endpoints, not reusing control-flow messages)** + the anchor
  kept (bootstrap self-attestation; no MITM protection claimed) + the three `UserRow.admin/
  disabled/pw_bootstrap` fields (Raft row extension, the pre-release-window discipline) +
  HttpOnly/SameSite=Strict sessions (32B sid, TTL 8h, cap 256, the loopback/vpn origin recorded);
  **the authorization ruling**: web sessions do not map to control-flow tickets; writes go through
  the ordinary Raft path (admin adjudicated at the handler layer); the `admin_op` root-signed
  operations and cluster-* never enter the UI; the API contract §M8.4 fixed verbatim (22
  endpoints / the unified error envelope / the CSRF double gate X-Flock-Web + JSON); password
  create/reset = a one-time `pw_bootstrap` token (atomic Raft consumption); the first admin =
  `flock-server web-admin-add` (two tail variants on the admin endpoint; multi-primary must go
  through a running service); the traffic time series = an in-memory ring buffer 120×60s (the
  restart-clears behavior stated as-is); the frontend = Alpine.js 3.14 + uPlot 1.6.9 + a
  hand-written dark design system, include_dir-embedded, Chinese first; wasm = the C-ABI shim
  `webauth_shim.rs` (the showroom wasm_shim approach + the existing getrandom custom backend; no
  wasm-bindgen); the tests W1–W7 container assertions + an e2e driven by a native-Rust OPAQUE
  client; the R table gains R27.
- 2026-11-07 M8a landed (server in full, this batch): the flock-sync five writes +
  BadBootstrapToken (token adjudication precedes the record — a wrong token does not leak whether
  a password already exists; replay yields the same error) + users_snapshot; the webui module's
  seven files (http/session/access/api/series/assets/mod — the §M8.8 file placement verbatim);
  netstate/backend user operations with dual arms (the redb rows tail-append the three fields;
  pre-M8 old rows leniently decoded — a different encoding surface from the postcard snapshot's
  clean failure); the admin tail WebPwBegin/WebPwCommit (web_pw_commit as the single semantic
  source, shared with the CLI direct-write fallback); the control-flow LoginBegin gains the
  disabled determination; the CLI web-admin-add; the [webui] config section
  (deny_unknown_fields whitelist key set + port conflicts on four surfaces refuse startup);
  tests/webui.rs with 4 items + the examples/webui_login vehicle (cookie-cache reuse — logging in
  per subcommand would exhaust the per-IP bucket); deploy/webui.yml + webui_assert.sh +
  Dockerfile.webui (**W1/W2/W3/W5/W7 container-tested all PASS**; W4/W6 left for M8b).
  Implementation wording clarified: a disabled user's login-begin uses the real record (the ke2
  same-shape, leaking no disabled state; user_disabled returns at finish after the password proof
  is established — otherwise that error code is unreachable for an honest client). Also repaid
  the standing clippy debt along the way (dataplane test locks / unreachable arms / needless
  returns under the new toolchain's -D warnings).
- 2026-11-07 M8b landed (frontend + wasm, this batch): the webauth_shim C-ABI shim (the §M8.6
  contract verbatim — entropy injection/alloc/free/login_begin/login_finish/pw_begin/pw_finish,
  error codes -1..-4; the compile gate on the literal wasm+wasm32 extended with the anchor
  feature + a native test — a unit test calls the shim directly and runs OPAQUE end to end, with
  a fixed injected entropy asserting a deterministic ke1); deploy/build-wasm.sh (the wasm32 build
  + the artifact committed + an idempotent sha256 re-check; the flock-protocol [lib] gains a
  cdylib profile); the JS glue vendor/flock_pake.js (the wasm-bindgen placeholder imports from
  the yamux→web-time transitive dependency get lazily-stubbed dynamically per Module.imports —
  unreachable on the pake path); the full SPA (Alpine 3.14.9 + uPlot 1.6.9 vendored with their
  LICENSEs, the hand-written dark design system, the Chinese i18n single dictionary, hash routing
  with 7 segments — audit split into its own page for M8b, the responsive three-tier layout fully
  functional + 44px touch + no horizontal scrolling); the SPA fallback (unknown non-/api paths
  return index.html; the §M8.4 static-asset row revised in sync); webui_assert.sh W4 (the client
  VIP:9800 login page reachable + webui_login's VIP-endpoint login chain + origin=vpn) and W6
  (--profile dual, a two-voter Raft: each VIP logs in separately + the peers/users/summary sets
  agree); the webui.yml dual profile (dual-a/b + operator init-cluster + dual-client, the
  standalone project name flock-webui-dual parallel to the single-server topology); the
  docs/manual/webui-checklist.md skeleton (filled in M8c). Live tests: the local embedded-browser
  wasm login full chain (account creation → token → password set → both roles) + the three-tier
  layout checks; containers W1–W7 all PASS (see the batch report). The W6 live test exposed and
  fixed two standing forwarding-plane gaps (flock-sync forward.rs): ① the server-segment VIPs
  (§6.2 .1–.10) are not in the device registry ⇒ packets to a remote server's VIP fell into
  drop_with_icmp — ingest/route_outbound gained the server_vip_node fallback mapping (a
  ForwardEnvelope to the receiver's server-self synthetic key), and receive gained the "dst = this
  server's server-self ⇒ inject into the kernel" branch (the fwd_delivered_kernel path promised
  in §7-M8.2 was previously unimplemented); ② route_outbound's src_dev=[0;32] placeholder made
  the server's kernel return path always fail the receiver's source binding — switched to the
  server-self synthetic key + receive validating that surface against the origin's deterministic
  VIP (no loss of anti-forgery semantics). 8 unit tests added in forward.rs.
- 2026-11-07 M8 review-fix batch (security hardening, 8 items, all with new unit tests; all cargo
  gates green):
  ① 🔴 slowloris — http.rs gains the **per-request total deadline REQUEST_TOTAL=30s** (the
  head+body read loop extracted into read_request under a total budget; on expiry the connection
  closes + the SLOW_KILLS counter; keep-alive resets per request; tests use
  serve_conn_with_budget injecting a 300ms budget to drive the byte-dripping vectors) — the old
  READ_TIMEOUT was per-read, and byte-dripping could hold the 64 concurrency permits indefinitely
  (a VIP-surface DoS on the admin plane);
  ② 🟡 loopback accept error classification — transient errors (WouldBlock/Interrupted/
  ConnAborted/ConnReset/EMFILE/ENFILE) logged + a 250ms backoff and keep running; only fatal ones
  exit (aligned with the VIP surface's 5s re-bind semantics);
  ③ 🟡 the pending-login full-load eviction now oldest-by (exp_unix, insertion order) + put/take
  lazily clearing expired rows (the old keys().min() lexicographic minimum ≠ the oldest —
  login-finish for admin-like lexicographically-small names failed for no reason);
  ④ 🟡 audit stderr line injection — the four public auth endpoints' user input uniformly 1..=64B
  + ASCII control characters rejected (sane_user_param; valid_username's full set is not reused —
  the control-flow device-owner names are not subject to that charset), and AuditLog::record
  strips control characters from user/target before output (stderr and the in-memory ring get the
  same stripping);
  ⑤ 🟡 LoginBackoff/IpBuckets capacity-capped at 4096 + a 60s periodic sweep (SWEEP_PERIOD reused
  at the same tier; the write path first clears lazy/idle rows, still evicting the oldest when
  full — arbitrary user/IP names injected on the unauthenticated surface no longer grow rows
  unboundedly);
  ⑥ 🟡 demotion/disable session recycling made immediate — dispatch's session tier re-reads UserRow
  (the locally applied view; linearizable not required; the trade-off noted in a comment): after
  set_admin=false an old session gets 403 on the next request; a disabled user gets 401
  user_disabled on the next request (the old behavior kept the admin snapshot for the 8h TTL);
  §M8.3/§M8.7 wording synced (including the as-is statement that "a disabled account has a
  password-correctness oracle (throttled by the backoff)");
  ⑦ 🟢 small items — a wrong method uniformly 405 (path_known branches on the path shape, aligned
  with the error-code table); flock_pake.js decHex/decB64 expected-length checks + writeParam's
  zero-length short-circuit (a pure JS asset; the .wasm artifact unchanged); the series
  vip_in_registry includes remote server VIPs (the multi-primary server_keys view — no 404 before
  the first sample after a restart; covered by the multi-primary integration test); config.rs's
  admin_bind+1 uses checked_add (a 65535 overflow no longer debug-panics); the session/access
  Mutex-poison handling switched to into_inner;
  ⑧ this changelog entry is the 8th item (the design.md wording synced with the implementation's
  behavior).
