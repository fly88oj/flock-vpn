# Showroom protocol-layer verdict: is it industry-best as of 2026-10-31

- Evaluator: architecture review officer (a dynamic workflow subagent)
- Verdict date: 2026-10-31
- Input materials (all read in full this time):
  `docs/research/showroom-analysis.md`, `docs/research/crypto-2026.md`,
  `docs/research/compression-2026.md`, `docs/research/vpn-mesh-2026.md`,
  `docs/research/frp-compat.md`
- Subject of evaluation: `E:\Works\showroom`'s `showroom-common` (SR-SIG1 + encrypted envelope
  v1 + OPAQUE) and its caller conventions, as the candidate foundation for the ChmlVPN protocol
  library.
- Scenario distinction (verdict premise): showroom = file/request transfer (short-lived
  envelopes, one-time keys, HTTP request-response semantics); ChmlVPN = a long-lived tunnel
  (many small packets mixed with high-throughput bulk, a single FRP TCP, multi-primary
  active-active). The VPN-side new surfaces (tun, multi-primary active-active) do not take part
  in the adopt/upgrade/hedge verdicts, but must enter the upgrade list (the protocol library
  must provide interfaces for them).

---

## 0. Source spot-checks performed first-hand this time (the verdict's evidence baseline)

Each item below was verified by directly reading the `E:\Works\showroom` sources during this
evaluation, **all consistent** with showroom-analysis.md's description:

| Claim | Verification location (read this time) |
|---|---|
| `SIG_WINDOW_SECS=300`; `KEY_LEN=32`/`NONCE_LEN=12`/`TAG_LEN=16`/`SEG=4MiB`/`WRAP_LEN=384` | showroom-common/src/lib.rs:48-55 |
| `nonce_hex()` = 16 random bytes → 32 hex characters (the implementation stronger than the doc's "8 random bytes") | lib.rs:75-79 |
| SR-SIG1 canonical string of seven fields + Ed25519 signature + base64url unpadded | lib.rs:221-261 |
| Verification: format → ±300s window → try each public key under the user | lib.rs:289-340 |
| Envelope: one-time random 32B k → RSA-3072-OAEP-SHA256 encapsulation, enforced 384B header | lib.rs:383-394 |
| Per segment: a fresh random 12B nonce + AES-256-GCM, **no AAD, no segment sequence number** | lib.rs:396-411 (the encrypt call takes only nonce+plaintext) |
| Opening is streaming, errors do not panic, clean EOF on segment boundaries | lib.rs:416-461 |
| OPAQUE Suite = Ristretto255(OPRF+KE) + TripleDH + Identity KSF | showroom-common/src/opaque.rs:32-39 |
| argon2id m=19456KiB/t=2/p=1, salt = `b"showroom-opaque-v1"+user` | opaque.rs:53-70 |
| **opaque.rs:1's comment mistakenly writes "RFC 9380"** (OPAQUE is actually RFC 9807; 9380 is H2C) — crypto-2026.md §1's finding is real | opaque.rs:1 (visually confirmed this time) |
| Nonce duplicate-check: `HashMap<"user:nonce", expiry instant>` + lazy retain cleanup + cleared on restart; bind_token 60s one-time | showroomctl/src/serve.rs:34-44 (AppState), serve.rs:913-922 (nonce_fresh), serve.rs:924-951 (auth) |
| zstd fixed at level 19 (upstream docker save / downstream pg_dump) | showroom/src/main.rs:318, showroomctl/src/dbmaint.rs:158 |
| Magic-byte adaptive unpacking (zstd `28 B5 2F FD`) | showroomctl/src/unpack.rs:15 |
| ndjson 30s heartbeat `{"hb":true}` | showroomctl/src/streams.rs:28, 68-69 |
| dump chunking ≤4MiB (`DUMP_CHUNK_MAX = 4<<20`) | dbmaint.rs:155 |
| import 8MB chunks (the wasm console contract) | showroom-web/smoke-wizard.mjs:808-811 (CHUNK8=8*1024*1024 as test corroboration) |
| Locked dependencies: opaque-ke 3.0.0 / aes-gcm 0.10.3 / rsa 0.9.10 / ed25519-dalek 2.2.0 / argon2 0.5.3 / sha2 0.10.9 / rand 0.8.8 / zstd 0.13.3 / curve25519-dalek 4.1.3 | Cargo.lock (checked item by item by grep this time) |
| **The no-trust-anchor-on-first-login boundary** (newly verified in the re-check round): "first login over plaintext HTTP has no trust anchor — PAKE only guarantees the password is not leaked; an active MITM can relay login-finish and register its own public key at key-bind to take over the account (mitigation: site B on the public network behind Caddy TLS; when the LAN is untrusted, use the CLI key path)" | E:\Works\showroom\SPEC.md:285-287 (§16.2 risk boundary; the original text read via sed this time) |
| ML-KEM-768 size figures (run in the re-check round): `ML-KEM-768 sizes: ek=1184B ct=1088B dk=64B \| hybrid X25519+ML-KEM-768: key-share=32+1184=1216B, ciphertext=32+1088=1120B`. **Calibration note (added in the third re-check)**: `dk=64B` is the **seed serialization form** returned by ml-kem 0.3.x's `KeyExport::to_bytes()` (Seed=d‖z, always 64B), not the FIPS 203 full decapsulation-key length (ML-KEM-768 dkLen=**2400B**); no conclusion in this report cites the dk size — the ek/ct values are the FIPS 203 parameter set | executed this time: `cd .tmp/cryptobench && cargo run --release` (ml-kem 0.3.3, with new size-check code); the seed semantics verified against the local registry sources: ml-kem-0.3.3/src/decapsulation_key.rs:231-233 (`fn to_bytes(&self) -> Seed`) and :243-245 (the seed is always 64B; the expanded form ML-KEM-768=2400B); the performance output re-run in the same round is in §3.3/§3.7 |

Checks **not re-run** this time (stated as-is): compression-2026.md §2's compression
measurements were executed by the earlier research on this same machine; this evaluation cites
the data without reproducing it. crypto-2026.md Appendix A's cryptographic benchmarks **were
re-run in the re-check round** (cryptobench, output matching the original report: old-kernel
AES-GCM 2.21–2.29 GB/s, GCM-SIV 5.09–5.27 GB/s, Ed25519 13.3/22.7μs, ML-KEM-768 keypair
0.022ms / encap+decap 0.044ms). streams.rs's line-by-line implementation and serve.rs's kid
derivation details were not re-checked line by line; taken on the reports' word (key constants
spot-checked).

---

## 1. Overall judgment

**The whole cannot be considered industry-best as of 2026-10-31 (overallKeep = false).**

The showroom protocol layer is circa-2024-grade **excellent classical cryptography
engineering**: its algorithm choices in both authentication (OPAQUE) and request signing
(Ed25519) are still top-tier industry picks today and can be carried over directly; the
engineering discipline (streaming constant memory, EtM, anti-enumeration, 0600 persistence,
same-stack wasm vector tests) is solid. But the whole lags on five points:

1. **Key encapsulation is a previous-era answer**: RSA-3072-OAEP has no forward secrecy, no
   post-quantum path, and is computationally expensive; the 2026 default answer for new
   protocols is the X25519+ML-KEM-768 hybrid (RFC 10024).
2. **Post-quantum readiness is zero**: the whole stack has not a single PQ element. For
   showroom's own "store now, open when the key leaks" style backup envelopes, the
   harvest-now-decrypt-later threat applies in particular.
3. **Control-plane trust bootstrap is missing (added in the re-check round)**: the first login
   over a plaintext link has no trust anchor; an active MITM can relay login-finish and, via
   bind_token, register its own public key to take over the account (SPEC.md:285-287 verified
   this time); the existing mitigations are deployment-level only (fronting TLS / switching to
   the CI key path), with no protocol-layer mechanism. For a VPN — account takeover ≈ network
   access takeover — this is a dimension the protocol layer must solve.
4. **Dependency generations lag and performance is left on the table**: aes-gcm 0.10.3 rides
   the old aes 0.8.4 kernel (the new 0.11/VAES generation measured ~2.3×, confirmed by the
   re-check-round re-run); opaque-ke 3.0.0 is a major version behind (4.0.1); ed25519-dalek
   2.2.0 (3.0.0 released); rand 0.8.8 (the ecosystem already runs 0.9/0.10 in parallel).
5. **Missing a transport-framing/multiplexing layer and compression policy tiers**: showroom
   leans on HTTP semantics and has no frames or streams of its own; compression is a single
   zstd-19 bulk tier — both are surfaces a long-lived VPN tunnel must newly build, and direct
   reuse of the compression would carry the VORACLE-family side-channel risk.

---

## 2. Per-dimension verdict table

| # | Dimension | showroom today | Industry best as of 2026-10-31 | Verdict |
|---|---|---|---|---|
| 1 | User authentication (OPAQUE) | OPAQUE ristretto255-SHA512 + TripleDH + Identity KSF + external argon2id(19MiB/t2/p1); opaque-ke 3.0.0 | same protocol and suite; implementation upgraded to opaque-ke 4.0.1; PQ-PAKE not yet standardized | **adopt** |
| 2 | Request signing (SR-SIG1/Ed25519) | Ed25519 canonical signing + prehashed streaming; ed25519-dalek 2.2.0 | Ed25519 (FIPS 186-5 approved) still mainstream; dalek 3.0.0; ML-DSA only an optional add-on | **adopt** |
| 3 | Envelope key encapsulation (RSA-3072-OAEP) | RSA-3072-OAEP-SHA256 wrapping a one-time 32B k, 384B fixed header | X25519+ML-KEM-768 hybrid (RFC 10024; already mainstream in Chrome/OpenSSH/Cloudflare) | **upgrade** |
| 4 | Symmetric encryption and streaming segmentation (AES-256-GCM/4MiB segments) | AES-256-GCM, random 96-bit nonce per segment, no AAD, one-time k; aes-gcm 0.10.3 (the old aes 0.8 kernel) | algorithm unchanged; counter-nonce discipline (long sessions) + segment-sequence AAD + the aes-gcm 0.11 new kernel + XChaCha/GCM-SIV fallback tiers | **hedge** |
| 5 | Compression (zstd) | zstd fixed at level 19, compress-then-encrypt, magic-routed unpacking | tiered zstd (pass-through/dictionary/chunked streaming) + non-expansion fallback + off by default, on by policy (VORACLE) | **hedge** |
| 6 | Anti-replay and session management | ±300s window + in-memory per-user nonce duplicate check + bind_token 60s + EtM; no session/rekey/keepalive | control plane carried over; data plane 64-bit counters + sliding window + dual-threshold rekey + keepalive (WireGuard constants) | **hedge** |
| 7 | Post-quantum readiness | zero (RSA/Ed25519/OPAQUE all classical) | X25519+ML-KEM-768 hybrid as the transport-layer default; ML-DSA-65 signature add-on optional | **upgrade** |
| 8 | Transport framing and multiplexing | no framing/multiplexing layer of its own (HTTP + ndjson + chunked endpoints; 30s JSON heartbeat) | over a single TCP: length-prefixed frames + yamux (rust-yamux 0.14.1) riding on top of the E2E session; explicit EOF frames | **upgrade** |
| 9 | First-login trust anchor / control-plane MITM (added in the re-check round) | first login over plaintext HTTP has no trust anchor: a MITM can relay login-finish, front-run bind_token, register its own public key, and take over the account (SPEC.md:285-287) | protocol-layer trust bootstrap: TOFU + public-key fingerprint pinning, out-of-band preset credentials/invites, or the server's long-term identity key entering OPAQUE/the handshake and pinned by the client (RFC 9807's aPAKE model requires the client to hold an authenticated server identity) | **upgrade** |

---

## 3. Per-dimension detail (evidence + reasoning + actions)

### 3.1 User authentication (OPAQUE) — adopt

**Current state** (verified this time: opaque.rs:32-39, 42, 53-70): OPAQUE, Suite =
Ristretto255 (OPRF group + KE group) + TripleDH + Identity KSF; password hardening externalized
argon2id m=19456KiB/t=2/p=1 (the OWASP tier), salt = constant prefix + username; unknown users
go down the dummy fake-record path against enumeration. Depends on opaque-ke 3.0.0 (Cargo.lock
checked this time). The comment mis-cites RFC 9380 (opaque.rs:1, visually confirmed this time).

**Industry best** (crypto-2026.md §4.1, sources [4][5][28]): OPAQUE's official number is
**RFC 9807** (2025-07); its §7's recommended configurations put **ristretto255-SHA512 first** —
showroom's suite choice matches the RFC's recommendation, and ristretto255 is not deprecated
(RFC 9496 still cited by new drafts). PQ-PAKE has no standardized implementation yet
(draft-vos-cfrg-pqpake still under discussion), so "classical OPAQUE at the authentication
layer + hybrid KEM at the tunnel layer" is the correct 2026 division of labor — there is no
more advanced, deployable alternative than OPAQUE. On the implementation side, the latest
stable is opaque-ke **4.0.1** (2025-11-03); showroom is a major version behind.

**Reasoning**: the algorithm/suite/anti-enumeration design = industry best, with nothing better
to switch to; the gaps are only the crate version, the RFC citation typo, and the argon2
parameter tier — all upgrade-list items, not reasons to change algorithms.
**Actions**: upgrade to opaque-ke 4.0.1 (mind API-generation regression testing; the
fixed-vector tests are the gatekeeper); fix the RFC citation; make the argon2 parameters an
upgradable versioned profile (the RFC 9807 tier m=2GiB/t=1/p=4 as the high tier, the OWASP tier
kept for WebAssembly/low-end devices).

### 3.2 Request signing (SR-SIG1/Ed25519) — adopt

**Current state** (verified this time: lib.rs:221-261, 289-340): the seven-field canonical
`SR-SIG1\nuser\nts\nnonce\nMETHOD\npath_with_query\nsha256(body)`, Ed25519 signature,
base64url unpadded; streaming prehashed signing for large files (sign_prehashed);
any-key-hits among multiple public keys + kid locating. ed25519-dalek 2.2.0 (Cargo.lock checked
this time).

**Industry best** (crypto-2026.md §4.2, sources [13][14][28]): Ed25519 is a **FIPS 186-5
approved algorithm** (2023-02); compliance is no longer a reason to switch to ML-DSA;
per-request asymmetric signing (versus AWS SigV4's symmetric HMAC) paired with a multi-device
public-key profile + kid revocation is the mainstream best form of device/user request
authentication. New code uses ed25519-dalek 3.0.0 (2026-07-06). ML-DSA-65 (FIPS 204) is only an
optional parallel tier for "future non-repudiation + harvest resistance", not a must — PQ-ifying
signing key profiles is not yet industry-urgent (Cloudflare's origin-side ML-DSA is itself only
a mid-2026 roadmap item).

**Reasoning**: the algorithm and protocol design meet industry grade with no shortcomings; the
upgrade items (dalek 3.0.0, optional parallel ML-DSA public keys) do not change the "already
best" characterization.
**Actions**: upgrade to ed25519-dalek 3.0.0; reserve kid→algorithm-type dispatch in the key
profile, leaving room for parallel ML-DSA-65 public keys (PQ dimension handled uniformly).

### 3.3 Envelope key encapsulation (RSA-3072-OAEP) — upgrade

**Current state** (verified this time: lib.rs:383-394, 347-349): a one-time random 32B AES key
per envelope, encapsulated with OAEP-SHA256 to the platform RSA-3072 public key, an enforced
384B fixed header; the platform RSA is persistent and unrotated (rotated only on leak).

**Industry best** (crypto-2026.md §3.2/§3.3, sources [12][20][22]-[26][37]): the
**X25519 + ML-KEM-768 hybrid KEM** is already the 2026 default answer for new protocols —
RFC 10024 (2026-08, Proposed Standard) fixed the TLS hybrid group X25519MLKEM768; default since
Chrome 131; default `mlkem768x25519-sha256` since OpenSSH 10.0; Cloudflare's PQ share of human
traffic >65% (2026-04). The cost is negligible — **re-check-round run**
(`.tmp/cryptobench`, ml-kem 0.3.3, release): keypair 0.022ms, encap+decaps 0.044ms. Size
figures (the same round's output; the FIPS 203 parameter set): ML-KEM-768 **ek=1184B,
ct=1088B** ⇒ the hybrid encapsulation's **ciphertext = 32(X25519 ephemeral public key)+1088 =
1120B**, and the receiver's hybrid **public key (key share) = 32+1184 = 1216B**. Erratum:
crypto-2026.md §3.3's original "hybrid ciphertext ~32+1184B" mixed the ek (the encapsulation
public key) into the ciphertext figure; this report corrects it per the actual run.

**Reasoning**: RSA-3072-OAEP is triply behind — ① no forward secrecy (the platform private-key
holder can open historical envelopes at any future time; for the dump-backup "store now, open
when the key leaks" form this is a substantive weakness, which neither EtM nor the one-time k
mitigates); ② no PQ path (RSA falls inside the SHC attack surface); ③ computationally
expensive: OAEP encrypt/decrypt in the hundred-microsecond-to-millisecond range, RSA-3072
keygen costly (more painful in the per-server-key multi-primary active-active scenario). On
size, RSA's 384B header is actually **smaller** than the 1120B hybrid ciphertext — RSA's only
size advantage, and not a reason to keep it. NIST SP 800-57 also only puts RSA-3072 in the 2035
tier. This is not a vulnerability (no known practical attack under the one-time-k discipline),
but as a 2026 long-term plan it must be replaced.
**Actions**: change the encapsulation header to the X25519+ML-KEM-768 hybrid (an RSA-OAEP
compatibility tier can be kept for transitional dual encapsulation); the envelope semantics
naturally upgrade from "recipient = platform public key" to "recipient = ephemeral share",
gaining one-time-envelope forward secrecy along the way.

### 3.4 Symmetric encryption and streaming segmentation (AES-256-GCM / 4MiB segments) — hedge

**Current state** (verified this time: lib.rs:396-411, 51-55): AES-256-GCM, 96-bit nonce, a
fresh **random** nonce per segment, **no AAD, no segment sequence number**; the key is a
one-time random 32B per envelope; segment = 4MiB plaintext, streaming with constant memory
(one ~4MiB buffer in seal / two in open). aes-gcm 0.10.3 (→ the old aes 0.8.4 kernel, Cargo.lock
checked this time).

**Industry best** (crypto-2026.md §2, sources [2][15]-[17][27][30] and the Appendix A
measurements):
- Algorithm: AES-256-GCM remains first choice on desktop/server CPUs (AES hardware
  ubiquitous) — the algorithm choice itself is best; ChaCha20/XChaCha20-Poly1305 as the
  fallback on hosts without AES hardware; AES-256-GCM-SIV (RFC 8452) for misuse-resistant
  scenarios.
- **Nonce discipline is the watershed**: random 96-bit nonces are usable only when "messages
  per key ≪ 2^32 and the key is one-time" (the SP 800-38D random-IV cap, relayed via C2SP/
  ePrint 2024/1111; 38D Rev.1 under revision). showroom's "one-time k + segments per envelope =
  n/4MiB" happens to sit inside the safe zone — **legal for the file-envelope scenario**; but a
  long-lived VPN session must switch to a 64-bit strictly monotonic counter nonce per direction
  (the WireGuard model).
- **Segment AAD**: the standard practice binds the segment sequence number (and total
  length/envelope ID) into the AAD — showroom lacks this, meaning the envelope layer itself
  does not defend against segment reordering/splicing (each segment within one envelope is
  independently decryptable); it is currently backstopped by the outer SR-SIG1 whole-envelope
  hash (EtM, verify-then-decrypt, security.md:84). As a general protocol library, the AAD
  should be added.
- **Implementation generation**: the new RustCrypto aes-gcm 0.11.1 (aes 0.9 kernel, runtime
  VAES detection) measured **~2.3× faster** than the old generation showroom uses (2.23 →
  5.20-5.22 GB/s @4MiB segments, crypto-2026.md Appendix A; reproduced by the re-check-round
  re-run: 2.21-2.29 → 5.09-5.27 GB/s) — the number-one-priority upgrade with zero cryptographic
  risk and pure performance gain.
- The 4MiB segments themselves are legal (GCM's per-message cap ~64GiB; the constant-memory
  design is right); the VPN data plane, however, should segment at MTU-scale small packets;
  large segments belong to file envelopes.

**Reasoning**: the algorithm and streaming architecture are correct and tested (length-invariant
assertions), but three retrofits (segment AAD, the 0.11-generation kernel, and a separate
counter-nonce + rekey tier for the VPN) are mandatory — keep the body, add new tiers; hence
hedge.
**Actions**: upgrade to aes-gcm 0.11.1; add segment-sequence AAD to envelope v2 (v1
compat-read); the protocol library offers two explicit, separately documented tiers — "one-time
k + random nonce (envelope tier)" and "session key + counter nonce (tunnel tier)" — each with
its security preconditions written down; negotiate the fallbacks XChaCha20-Poly1305 and
AES-256-GCM-SIV.

### 3.5 Compression (zstd) — hedge

**Current state** (verified this time: main.rs:318, dbmaint.rs:158, unpack.rs:15): zstd fixed
at level 19, compress-then-encrypt (the order is right); unpacking adapts by magic bytes
(zstd/gzip/bare stream); common deliberately contains no zstd (the compression pipeline is in
the callers). This single tier only — no dictionary, no chunked streaming, no non-expansion
fallback switch.

**Industry best** (compression-2026.md §0/§2/§3/§6, sources S1-S13):
- **The algorithm family is right**: zstd is the dual best for bulk streams and (with a
  dictionary) small packets; brotli/snappy are out. That part is adopt.
- **But the tiers must be redone** (per local measurements + primary sources): ① <128B pass
  through (measured: 40B expands to 122.5%, 120B zero gain; zstd #3722 fixed costs dominate);
  ② 128B–1.5KB structured small packets at zstd level 1 + a trained 4–16KB dictionary
  (measured: 120B→28–30%, 1400B→9.4%, and faster than without); ③ bulk streams zstd -1 chunked
  at 16–64KB + a 5–10ms timed flush (measured: 64KB chunks lose only 0.2pp); ④ non-expansion
  fallback (RFC 3173 §2.2 MUST) + adaptive skipping; ⑤ context reuse (measured 3×).
- **The security premise changed**: showroom compresses its own bulk payloads (docker layers,
  DB dumps) with a small injection surface; the ChmlVPN tunnel carries all members' web traffic
  + the FRP relay is precisely a ciphertext-length observation point — all three
  CRIME/BREACH/VORACLE preconditions hold (compression-2026.md §3.2). Industry conclusions:
  WireGuard does no compression at all (preferring 16B padding); OpenVPN 2.5→2.6 disabled it by
  default and plans removal. Hence VPN data-plane compression must be **off by default, on by
  policy + output padding**.

**Reasoning**: the single zstd-19 tier is sufficient for showroom's bulk scenarios and
ratio-first is reasonable there, but as a protocol library's compression layer it lacks both
performance tiers (small packets/latency-sensitive) and safety tiers (policy gating/fallback/
padding); copied into a VPN it would lose both performance and safety.
**Actions**: rebuild the compression layer into the four tiers above; keep level 19 as the
"bulk/archive" tier; add a compression flag + original-length field to the frame format (so
the decompressing side can preallocate); the safe default = off; train dictionaries on
synthetic templates and distribute them versioned.

### 3.6 Anti-replay and session management — hedge

**Current state** (verified this time: lib.rs:48, 326-328; serve.rs:34-44, 913-951): time
window |now−ts|≤300s + per-user nonce duplicate-checking (`HashMap<"user:nonce", expiry
instant>`, lazily cleaned on insert, entry lifetime = the window, **cleared on restart** — SPEC
declares this acceptable); bind_token 60s one-time; EtM verify-then-decrypt; server-enforced
seq/total on chunked imports. **No session concept**: no rekey, no keepalive (the ndjson stream
has a 30s JSON heartbeat, but that is HTTP-layer), no data-plane counters.

**Industry best** (crypto-2026.md §2.2/§6, sources [6][8][9][10]; vpn-mesh-2026.md §5):
- Control plane/API surface: time window + nonce duplicate-checking is standard practice (the
  same shape as AWS SigV4, with stronger nonce storage); showroom's design can stay.
- Data plane/long-lived sessions (WireGuard constants, wireguard-go `device/constants.go`):
  nonce = 32-bit zero + 64-bit LE counter; receiver-side 64-bit counter + sliding window
  (implementation 2048); rekey dual threshold 2^60 packets or 120s; 180s / 2^64−2^13−1 hard
  reject; 10s keepalive; reconnect = a brand-new handshake (no PSK resumption); forgery-attempt
  limits triggering disconnect.
- New multi-primary active-active constraints: the cross-server semantics of nonce/session/
  revocation state need design (in-memory state cleared on restart amounts, in an
  active-active cluster, to a "restart-window network-wide replay surface"; shared state or a
  session-level mechanism must take over).

**Reasoning**: within showroom's single-server scenario the design holds and its boundaries are
known and accepted by SPEC; but the protocol library, aimed at long-lived tunnels, has no
session-level anti-replay/rekey/keepalive tier at all — the VPN scenario must add one; keep and
add tiers, hedge.
**Actions**: keep the API-surface mechanism as-is; add a session tier (counters + sliding
window + dual-threshold rekey + keepalive, constants per wireguard-go); make the ownership of
replay state under multi-primary active-active explicit (the Raft state machine or session
tickets).

### 3.7 Post-quantum readiness — upgrade

**Current state** (verified this time: Cargo.lock has no ml-kem/ml-dsa/liboqs entries;
encapsulation = RSA, signing = Ed25519, authentication = OPAQUE, all classical): **zero PQ
elements**.

**Industry best** (crypto-2026.md §3.2/§7, sources [12][13][20]-[26]): the X25519+ML-KEM-768
hybrid is the 2026 default for new protocols (RFC 10024 / FIPS 203; Chrome 131 default,
OpenSSH 10.0 default, Cloudflare >65% and targeting full PQ by 2029); the pure-Rust ml-kem
0.3.3 (FIPS 203) is usable (the re-check round ran its latency, consistent with crypto-2026.md
Appendix A: keypair 0.022ms / encap+decaps 0.044ms); on signatures, ML-DSA-65 (FIPS 204) is an
optional add-on (the crate self-describes as unaudited; or use the formally verified libcrux as
an alternative); **do not use liboqs** (officially not recommended for production). PQ-PAKE at
the authentication layer is not yet standardized → putting PQ in the transport layer suffices.

**Reasoning**: this is the only "completely blank" dimension. The RSA envelopes are especially
vulnerable to harvest-now-decrypt-later (backup dumps are long-lived by nature); evaluated
against "industry best 2026", lacking a PQ path is disqualifying.
**Actions**: execute together with 3.3 — switch encapsulation/handshake to the hybrid KEM;
optionally parallel ML-DSA-65 public keys in the key profile; reserve algorithm-tier fields in
version negotiation for future upgrades.

### 3.8 Transport framing and multiplexing — upgrade

**Current state** (verified this time: streams.rs:28/68-69 heartbeat, dbmaint.rs:155 dump
chunking, smoke-wizard.mjs:808-811 import 8MB-chunk corroboration; showroom-analysis.md §4.2):
showroom **has no transport-framing/multiplexing layer of its own** — the control plane is
HTTP/1.1 request-response (axum), the downstream is ndjson streams (a 30s `{"hb":true}`
heartbeat against proxy disconnects), and large payloads rely on endpoint-level chunking
(import 8MB/chunk, dump ≤4MB/chunk). Adaptation to the FRP plaintext relay leans on HTTP's own
proxyability.

**Industry best** (vpn-mesh-2026.md §4; frp-compat.md §1.5): a VPN tunnel over a single FRP
TCP relay should use: **length-prefixed frames + stream-ID multiplexing, riding on top of the
E2E encrypted session** — specifically recommended: yamux (the hashicorp spec; the Rust
implementation rust-yamux 0.14.1, still active 2026-09-21, used at scale by libp2p): its
premise of relying on a reliable ordered byte stream fits a single TCP exactly, keepalive is
native, flow control/backpressure built in. Explicitly not chosen: HTTP/2 (semantic mismatch
and the same TCP head-of-line blocking), QUIC-over-TCP (double-layer reliable transport; zero
benefit, doubled complexity). **Hard constraints** (proven on frp): do not rely on TCP
half-close to express one-directional end (the T3 experiment: after SHUT_WR the return path is
0/65536 bytes and the whole chain tears) — an explicit EOF frame or length prefixes are
mandatory; any first-byte value is safe (no probing at the user port, proven by T2); the data
plane has no idle timeout, but node restarts/NAT will hard-drop — an application-layer
heartbeat + reconnect are needed.

**Reasoning**: this is not "showroom did it insufficiently well" — the layer simply does not
exist in showroom (HTTP did the framing and multiplexing on its behalf). A VPN tunnel must
build this layer; hence upgrade.
**Actions**: the protocol library gains a framing layer (length prefix + stream ID + frame
types including explicit EOF/keepalive) and a multiplexing layer (yamux or equivalent
semantics: flow control, backpressure, keepalive, multi-stream priorities — the control flow at
high priority); the session/reconnect semantics pair with 3.6's WireGuard model.

### 3.9 First-login trust anchor / control-plane MITM (dimension added in the re-check round) —
upgrade

**Current state** (verified this time: SPEC.md:285-287 read in the original;
showroom-analysis.md §6 item 5 carries the same): the first login over plaintext HTTP has no
trust anchor — SPEC §16.2's risk boundary states it plainly: "PAKE only guarantees the password
is not leaked; an active MITM can relay login-finish and register its own public key at
key-bind to take over the account"; the current mitigations are **deployment-level only** (a
public-network site fronted by Caddy TLS; the CI key path when the LAN is untrusted); the
protocol layer has no trust-bootstrap mechanism at all. Attack path (extrapolated from the
verified mechanisms): OPAQUE can be relayed end to end (PAKE does not authenticate the server
identity to a first-login client — showroom's `SERVER_ID=b"showroom-server"` is a literal
constant, opaque.rs:42 verified this time, not authenticated key material); after
login-finish, the server issues the 60s one-time bind_token (serve.rs:43-44 verified this
time), a bearer credential that a relaying attacker can front-run the client to use for
key-binding a public key it holds (the key-bind signature is made by the candidate new key
itself, proving only possession of the new key, not of the account password) — the account is
taken over. A secondary boundary of the same class: the UnknownUser fake record has
statistical residue in response length/timing (SPEC.md:287-288).

**Industry best**: identity bootstrap is a standard topic of authenticated key exchange —
RFC 9807's aPAKE security model **requires the client to hold an authenticated server
identity**, otherwise PAKE provides no server authentication; the mature engineering
approaches: ① TOFU + public-key fingerprint pinning (the SSH known_hosts model, with
fingerprint-change warnings); ② out-of-band preset credentials/invites (innernet's one-time
invite files, Tailscale's IdP outsourcing, ZeroTier's controller certificates); ③ the server's
long-term signing identity key entering the OPAQUE envelope/handshake transcript, pinned by
the client at first login and enforced on subsequent logins (naturally combinable with the
hybrid KEM's server static share).

**Reasoning**: showroom itself declares this boundary honestly and mitigates it at the
deployment layer — a known trade-off within its "administrator-controlled deployment"
scenario; but for ChmlVPN the account is network access itself: taking over the account =
taking over mesh membership, and the FRP plaintext relay is a structural amplifier of this
attack (the relay sits in the relay position by definition). As a mandatory dimension of a VPN
protocol library, this is a structural gap.
**Actions**: upgrade-list P0-5: protocol-layer trust bootstrap (a dual path of TOFU pinning +
out-of-band preset credentials, with the server's long-term identity key entering the
handshake/OPAQUE and covering the integrity of bootstrap credentials such as bind_token);
first-login fingerprint display and pin-change warnings go into the admin plane.

---

## 4. Upgrade list (the hard input for protocol-library design)

Ordered by priority; ★ items are VPN-new surfaces (not part of the verdicts above, but the
protocol library must provide interfaces).

**P0 (security-structure items; without them it cannot claim to be 2026-best)**
1. Replace key encapsulation with the **X25519 + ML-KEM-768 hybrid KEM** (RFC 10024 / FIPS
   203; ml-kem 0.3.3 pure Rust; no liboqs); one-time envelopes gain forward secrecy + PQ; an
   RSA-OAEP compatibility tier can be kept for transitional dual encapsulation. (Size
   reference, re-check-round run: hybrid ciphertext 32+1088=1120B, hybrid public key
   32+1184=1216B, latency <0.1ms)
2. **Session/tunnel-tier AEAD discipline**: a 64-bit strictly monotonic counter nonce per
   direction; 2^60-packet or 120s dual-threshold rekey; 180s / 2^64−2^13−1 hard reject;
   forgery-attempt limit disconnects; random 96-bit nonces banned for long sessions (the
   envelope tier keeps "one-time k + random nonce" with its preconditions documented).
3. **Envelope v2 segment AAD**: the segment sequence number (+ envelope ID/segment count)
   enters the AAD, preventing segment reordering and splicing; v1 read-only compatible.
4. **Compression-layer hardening**: compression off by default, enabled per policy/per stream
   (the VORACLE/CRIME preconditions hold in ChmlVPN — the FRP relay is a length observation
   point); sessions with it on get output padding; non-expansion fallback (RFC 3173 §2.2 MUST)
   + adaptive skipping.
5. **First-login trust anchor / control-plane MITM (added in the re-check round)**:
   protocol-layer trust bootstrap — ① the server's long-term signing identity key enters the
   OPAQUE envelope/handshake transcript; the client TOFU-pins at first login (fingerprint
   display + change warnings) and enforces the check on subsequent logins; ② out-of-band
   preset credentials/invites as the strong path (modeled on innernet's invite files / SSH
   known_hosts); the integrity of bootstrap credentials such as bind_token must be covered by
   the server identity key. Basis: the takeover attack already declared at SPEC.md:285-287;
   RFC 9807's aPAKE model requires the client to hold an authenticated server identity.

**P1 (performance and tiering items)**
6. **crate generation upgrades**: aes-gcm 0.10.3 → 0.11.1 (the aes 0.9/VAES kernel, measured
   ~2.3×); opaque-ke 3.0.0 → 4.0.1; ed25519-dalek 2.2.0 → 3.0.0; evaluate rand 0.8.8 →
   0.9/0.10 (an API generation gap; 0.8.x is still maintained — can be deferred but needs a
   plan).
7. **Compression tier rebuild**: <128B pass-through; 128B–1.5KB zstd-1 + 4–16KB dictionary
   (synthetic-template training, dictID negotiation, versions strictly matched); >1.5KB zstd -1
   chunked at 16–64KB + 5–10ms flush; context reuse; level 19 kept only as the bulk/archive
   tier; the frame header gains a compression flag + original length; lz4_flex as the
   CPU-constrained fallback tier.
8. **AEAD negotiation fallback tiers**: XChaCha20-Poly1305 (hosts without AES hardware),
   AES-256-GCM-SIV (misuse-resistant/multi-primary-replication scenarios; fastest locally).
9. **Transport framing and multiplexing layer**: length-prefixed frames + stream IDs +
   explicit EOF frames (no reliance on TCP half-close, proven by frp T3) + keepalive;
   multiplexing via yamux (rust-yamux 0.14.1) or equivalent semantics (flow control/
   backpressure/keepalive/control flow at high priority); any first-byte value compliant (no
   probing at the frp user port).
10. **Handshake**: WireGuard-style 1-RTT (Noise IK structure) + the hybrid-KEM slot; sessions
    indexed by the peer's static public key to support roaming; reconnect = a brand-new
    handshake (no PSK resumption); the 10s keepalive doubles as relay liveness probing.

**P2 (authentication/signature maintenance items)**
11. OPAQUE: upgrade to opaque-ke 4.0.1 (fixed-vector tests as the gate); versioned argon2id
    parameter profiles (the RFC 9807 high tier vs the OWASP tier); fix the RFC citation
    9380 → **9807** (opaque.rs:1; the typo's existence verified this time).
12. Signatures: ed25519-dalek 3.0.0; reserve ML-DSA-65 parallel public keys / kid-type dispatch
    in the key profile (an optional PQ add-on).
13. Doc correction: the nonce-length spec-implementation deviation follows the implementation
    (16 random bytes/32 hex, lib.rs:75-79).

**★ VPN-new surfaces (interfaces must be provided; not part of the verdicts)**
14. **tun data-plane interface**: frame TUN IP packets into logical streams; adapt tun-rs
    2.8.16 (the fullest Win/macOS/Linux/Android/iOS platform matrix); Linux routing via
    rtnetlink; MTU 1280 (same as Tailscale, the IPv6 floor); access seams for Android
    `protect()` / iOS fd injection.
15. **Multi-primary active-active sync interface**: device registry/credentials/config
    versions through a strongly consistent state machine (openraft); online state via gossip
    leases; session tickets delegated to local issuance; network-wide-effective revocation
    semantics + the cross-server ownership of nonce/replay state; the protocol library must
    expose the "per-server independent keys / per-rotation re-wrapping" permission point.
16. **frp relay adaptation interface**: application-layer heartbeat + disconnect-reconnect (a
    brand-new handshake); no half-close reliance; multi-session multiplexing over a single
    tunnel (no multi-tunnel reliance); frpc subprocess supervision (the dual stack of pinned
    ChmlFrp v0.51.2 + pinned original; ChmlFrp's exit-after-three-reconnects needs process
    supervision).

---

## 5. Method and limitation statement

- This report's "industry best" conclusions are relayed from the five research reports'
  primary-source chains (RFC/NIST/official blogs/upstream sources/the crates.io API + the
  reports' local measurements); the evaluator cross-checked the reports' conclusions against
  the source side (the §0 table); web searches were not re-run. The cryptographic benchmarks
  were re-run and reproduced in the re-check round (cryptobench, §0 table); the compression
  measurements were not re-run.
- Not done this time: any ChmlVPN-side implementation verification (the repository has no code
  yet); cross-compilation tests of pure-Rust crates on mobile (iOS/Android) (crypto-2026.md
  gaps #6); live end-to-end testing on a real ChmlFrp node (frp-compat.md gaps #1).
- Of the 9 dimensions: 2 adopt, 3 hedge, 4 upgrade; the overall judgment overallKeep = false,
  driven mainly by the four upgrades — #3 (encapsulation), #7 (PQ), #8 (framing/multiplexing),
  #9 (trust anchor) — plus the tier gaps of #4/#5/#6.

---

## 6. Re-check revision record (2026-10-31, round two)

The reviewer raised two objections; the item-by-item verification results:

1. **The "first-login trust anchor / control-plane MITM" dimension was missing — upheld;
   revised.** Verification: SPEC.md:285-287 was read in the original this time and indeed
   carries "first login over plaintext HTTP has no trust anchor — PAKE only guarantees the
   password is not leaked; an active MITM can relay login-finish and register its own public
   key at key-bind to take over the account"; showroom-analysis.md §6 item 5 (lines 229-231)
   carries the same. Neither the original verdict's 8 dimensions nor its 15-item upgrade list
   covered it — a completeness gap. Revision: dimension 9 added (the §2 table, detailed in
   §3.9, verdict upgrade) and upgrade-list item P0-5 added (TOFU pinning / out-of-band preset
   credentials / the server identity key entering OPAQUE and the handshake); the overall
   judgment overallKeep=false stands, with strengthened argumentation.
2. **§3.3's hybrid-ciphertext figures were wrong — upheld; revised.** Verification: this
   round's cryptobench run (ml-kem 0.3.3) output `ek=1184B ct=1088B`, i.e. the hybrid
   ciphertext = 32+1088 = **1120B** and the hybrid public-key key share = 32+1184 = **1216B**.
   crypto-2026.md §3.3's original "hybrid ciphertext ~32+1184B" mixed the ek into the
   ciphertext figure (1184 is the encapsulation public key's length; the ciphertext is 1088);
   the original verdict's "hybrid ciphertext ~1120B + 32B" was a double summation. Revision:
   §3.3's figures corrected per the actual run with the erratum noted; the reasoning paragraph
   also corrected — RSA's 384B header is actually **smaller** than the 1120B hybrid ciphertext
   (RSA's only size advantage, not a reason to keep it); the replacement arguments are forward
   secrecy + PQ + speed. The dimension's upgrade verdict is unchanged.

## 7. Re-check revision record (2026-10-31, round three)

The reviewer raised two items (both clerical; no verdicts affected); the item-by-item
verification results:

1. **§4 upgrade-list numbering conflict — upheld; renumbered.** Verification: grepping this
   file confirms that after round two inserted item 5 (first-login trust anchor) at the end of
   the P0 block, the P1 block still started numbering at "5. crate generation upgrades",
   producing two 5s; P2 remained 10–12 and ★ remained 13–15, without shifting. No entries were
   lost, and §3.9's "P0-5" reference is unambiguous within the P0 block. Revision: P1
   renumbered 6–10, P2 renumbered 11–13, ★ renumbered 14–16 — 16 items with consecutive
   numbering; entry contents unchanged.
2. **The §0 table's "dk=64B" figure lacked a qualifier — upheld; annotated.** Verification: the
   local cargo registry sources, ml-kem-0.3.3/src/decapsulation_key.rs:231-233, confirm
   `KeyExport::to_bytes()` returns `Seed` (d‖z, always 64B), and :243-245 confirm the expanded
   form (FIPS 203 dkLen) for ML-KEM-768 is 2400B. The §0 table reproduced the program output
   `dk=64B` verbatim without noting it is the seed serialization form, easily misread as the
   FIPS dk size. Revision: a "calibration note" added to that row of the §0 table; no
   conclusion in the report cites the dk size; the verdicts are unaffected.
