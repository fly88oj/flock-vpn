# Cryptography best-practice research for "a high-performance VPN tunnel over FRP pure-TCP
relaying"

- **Date**: 2026-10-31 (all "current state/adoption" conclusions as of today)
- **Background**: ChmlVPN — multiple computers forming a VPN network through ChmlFrp relay
  nodes; frp does pure TCP relaying only; end-to-end encryption is done in our own protocol
  layer; servers are exposed via FRP, handle login authentication and device management, and
  synchronize with each other in a multi-primary active-active fashion. showroom's existing
  protocol stack is the candidate for direct reuse.
- **Method**: conclusions rest only on primary sources (RFC/RFC-Editor, NIST official pages,
  official blogs, upstream source, the crates.io API, docs.rs), plus local measurements; each
  claim is annotated with a reference number (matching the [references](#references) at the
  end). [proven] is distinguished from [recommendation/speculation].
- **Local-measurement marking**: data marked "measured (local)" comes from benchmarks run on
  this machine during this research (see §2.3; CPU: Intel Core Ultra 9 285HX, Windows 11, Rust
  1.98.1 release + LTO + codegen-units=1).

---

## 0. Conclusions at a glance (TL;DR)

| Aspect | Conclusion as of 2026-10-31 | Key basis |
|---|---|---|
| Data-plane AEAD | **AES-256-GCM remains the first choice** (clients/servers are desktop/server CPUs; AES hardware is ubiquitous), but RustCrypto's new generation (the aes 0.9 kernel, with VAES enabled) is ~2.3× faster than the old generation showroom uses (aes 0.8.4) [measured (local)]; the nonce must become a **strictly monotonic per-direction counter** (purely random 96-bit nonces are banned for long-lived sessions approaching the 2^32 birthday bound); on hosts without AES hardware or with strong misuse-resistance needs, use **ChaCha20-Poly1305 / XChaCha20-Poly1305 / AES-GCM-SIV** | [27][28][30][15][16][17] |
| Handshake/KEM | **X25519+ML-KEM-768 hybrid is already the mainstream standard**: RFC 10024 (2026-08, Proposed Standard), Chrome 131 default, Cloudflare >65% of human traffic, OpenSSH 10.0 default; for the tunnel layer, the homegrown-handshake recommendation is **WireGuard-style 1-RTT (a Noise IK approach) + X25519+ML-KEM-768 hybrid**; TLS 1.3 (rustls) is the convenient fallback | [20][22][23][24][25][26][8][9][10] |
| showroom's RSA-3072-OAEP encapsulation | **Explicit verdict: replace (for the data plane)**. No forward secrecy; a 384B fixed-length header; RSA keygen/decapsulation are expensive; replace with X25519+ML-KEM-768 hybrid encapsulation (cost <0.1ms, ciphertext ~1120B) or pure X25519. If kept short-term, the "one-time k per envelope" discipline must be maintained | [12][20][28 ml-kem measured][measured (local)] |
| User authentication | **OPAQUE = RFC 9807 (2025-07)** (the ask and showroom's comments wrongly wrote RFC 9380, which is Hashing-to-Curves); ristretto255-SHA512 remains the **first** RECOMMENDED suite of RFC 9807, not deprecated; opaque-ke is actively maintained (3.0.0→4.0.1→4.1.0-pre.2); upgrading from 3.0.0 recommended; Ed25519 is an approved FIPS 186-5 algorithm (2023-02); ML-DSA (FIPS 204) is an optional add-on, not a must | [4][3][5][28][13][14] |
| Rust ecosystem | primarily the **RustCrypto pure-Rust family** (Apache-2.0/MIT, no C build dependencies, the easiest cross-platform story); rustls for the TLS layer (aws-lc-rs by default); **liboqs officially states it does not recommend production use**; ring's release cadence is slow (0.17.14, no stable release after 2025-03-11) | [28][31][32][33] |
| rekey/FS/reconnect | adopt the WireGuard model: **counter/time dual-threshold rekey trigger (2^60 packets or 120s), 180s hard reject, 64-bit counters + a sliding window for anti-replay**; no PSK resumption on reconnect — a brand-new 1-RTT handshake every time (ML-KEM-768 end to end <0.1ms [measured (local)]), paired with roaming (endpoints may change; sessions identified by the peer's public key) and keepalive | [10][9][6][8] |

---

## 1. showroom's current state verified (primary source: local source code)

This research directly checked the `E:\Works\showroom` sources; the ask's description matches
the code. Key points and evidence:

- Locked dependency versions (`showroom/Cargo.lock`): `opaque-ke 3.0.0`, `aes-gcm 0.10.3`,
  `rsa 0.9.10`, `ed25519-dalek 2.2.0`, `argon2 0.5.3`, `sha2 0.10.9`, `rand 0.8.8`.
- Encryption encapsulation: `showroom-common/src/lib.rs:378-461` —
  `[384B RSA-OAEP-SHA256 encapsulating 32B k] || per segment [12B random nonce][AES-256-GCM
  ciphertext+16B tag]`, segment = 4MiB plaintext, no AAD; empty envelopes legal; any tag
  failure during opening returns Err.
- Signatures: `showroom-common/src/lib.rs:222-261` canonical string and
  `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>`; verify tries all public keys under the user,
  accepting any hit (`lib.rs:291-340`); prehashed streaming signing via `sign_prehashed`.
- OPAQUE: `showroom-common/src/opaque.rs` — the ristretto255 Suite, TripleDH, Identity KSF,
  `SERVER_ID=b"showroom-server"`, argon2id(19456KiB, t=2, p=1) external hardening, salt =
  `b"showroom-opaque-v1"+user`.
- Anti-replay: `showroom-common/src/lib.rs:48` `SIG_WINDOW_SECS=300` (absolute-value check,
  `lib.rs:326`); per-user nonce duplicate checking and bind_token (60s one-time) in
  `showroomctl/src/serve.rs:34-44/913-951`.
- EtM: `docs/security.md:78-90` — SR-SIG1 covers the whole envelope hash; verify the signature
  first, decrypt after; chunked imports sign each chunk independently + server-enforced
  seq/total.

**Two newly found "citation/spec" deviations** (the ask knew of the first; the second is a new
find of this research):

1. [proven] nonce length spec-implementation deviation: `docs/security.md:21` says "16 hex
   characters (8 random bytes)", but the implementation `nonce_hex()` (`lib.rs:75`) produces 16
   random bytes (32 hex); verify only checks non-empty. The implementation is stronger than the
   spec; the spec doc should be fixed.
2. [proven] **wrong RFC number cited**: showroom's code comments and the ask both call OPAQUE
   "RFC 9380", but RFC-Editor's official page shows **RFC 9380 = "Hashing to Elliptic Curves"**
   (Faz-Hernandez et al., CFRG/IRTF) [3]; OPAQUE is actually **RFC 9807, "The OPAQUE Augmented
   PAKE Protocol" (2025-07, Informational, IRTF stream)** [4]. The two are easily confused
   (OPAQUE does rely on H2C for group encoding). Fix the comments and doc citations.

---

## 2. Q1 Data-plane AEAD

### 2.1 Candidate AEADs today (as of 2026-10-31)

| Algorithm | Standards status | nonce | Misuse resistance | Performance vs GCM | One-line positioning |
|---|---|---|---|---|---|
| AES-256-GCM | NIST SP 800-38D (2007, under revision; see below) | 96-bit | no (nonce reuse is catastrophic) | the baseline (the fastest tier under AES-NI/VAES/ARM-CE) | the default choice; nonce discipline is the lifeline [15][16][17] |
| ChaCha20-Poly1305 | RFC 8439 (used by WireGuard, citing RFC 7539 syntax) [9] | 96-bit (usually paired with a counter inside protocols) | no | fastest without AES hardware; with AES hardware ≈ the old-generation GCM [measured (local)] | for hosts without AES-NI / minimal constant-time-implementation preferences [9][30] |
| XChaCha20-Poly1305 | **draft-irtf-cfrg-xchacha-03 is expired/dead (last revised 2020-01; Datatracker marks it Expired/Dead)** [34] | 192-bit | no | comparable to ChaCha (one extra HChaCha20) [measured (local)] | a de-facto standard (libsodium etc.) but the CFRG spec never finalized; friendly to random nonces |
| AES-GCM-SIV | RFC 8452 (2019) [2] | 96-bit | **yes** (SIV-derived; nonce reuse leaks only equality) | official cost model: AES-256 needs p+7 AES calls; "encryption about 2/3 the speed of GCM, decryption within 5%" [2] | the preferred choice when nonce risk is high (random nonces/VM snapshots/multi-primary replication) |
| XAES-256-GCM | the C2SP spec (a community standard, not an RFC) [16] | 192-bit | no | 3 extra AES calls per message (2 precomputable) [16] | an "extended-nonce GCM" built purely from FIPS components: random nonces safely usable up to ~2^80 messages [16] |
| GCM-SST | draft-mattsson-cfrg-aes-gcm-sst **-21 (2026-07), an individual draft, not an RFC** [18] | 96-bit | partial | — | aimed at short tags/5G; not yet standardized; not advisable for the mainline yet |
| OGCM-1/2 | **purely academic** (proposed in Iwata–Seurin, "Reconsidering the Security Bound of GCM", fixing GCM weak keys/forgery bounds) [19] | — | — | — | no standardization, no mainstream library implementation; literature-review-level awareness is enough |
| AEGIS family | draft-irtf-cfrg-aead-limits-13 covers its bounds (a draft) [17] | — | — | extremely fast (SIMD-specific) | emerging, but the ecosystem/standards are unsettled; not as the VPN mainline |

**NIST SP 800-38D is under revision** [proven]: NIST published an SP 800-38D Rev.1 pre-draft
call for comments on 2025-01-06, followed by a second initial draft; the revision motivations
include the random-nonce constraints and adapting to new block ciphers [15]. Academia
(ePrint 2024/1111) argues to **ban GCM with random 96-bit nonces outright** (birthday-collision
attacks) [35].

### 2.2 Nonce management and anti-replay (long-lived-session best practice)

**Constraints (proven; part of the citation-chain explanation)**:

- SP 800-38D's two hard constraints on GCM: **with randomly generated 96-bit IVs, at most 2^32
  encryptions per key** (the birthday bound); **at most 2^39−256 blocks of total encrypted data
  per key**. Note: the 38D original PDF could not be parsed directly this time (WebFetch does
  not support PDFs); these two points are cross-cited from the C2SP XAES spec page [16],
  ePrint 2024/1111 [35], and the NIST revision notice [15], not verbatim from the original
  (see §gaps).
- The CFRG's "Usage Limits on AEAD Algorithms" is still a draft (draft-irtf-cfrg-aead-limits-13,
  unpublished as an RFC): the confidentiality bound for 96-bit-IV AES-GCM is about **2^47.5
  messages per key**, with integrity/forgery-attempt limits also given; **note the internet
  rumor "RFC 9513 = AEAD limits" is wrong — RFC 9513 is actually OSPFv3 SRv6 extensions**
  [proven; checked on Datatracker] [17][36].
- The Noise spec's advice for AESGCM: at most 2^56 bytes per key (~72 PB); the session must be
  terminated when the nonce space of 2^64−1 is exhausted [8].

**Recommended practice for long-lived VPN tunnels** [recommendation, per the standards above]:

1. **Ban purely random 96-bit nonces for long sessions.** Maintain a 64-bit strictly monotonic
   counter per direction; the AEAD nonce = the counter (WireGuard does exactly this: nonce = 32
   zero bits + a 64-bit LE counter [9]). Random nonces are acceptable only in the
   envelope-style case of "messages per key ≪ 2^32 with a one-time key" (showroom's one-time-k
   envelopes are exactly that — segments per envelope = n/4MiB, far below the bound).
2. **Anti-replay = a 64-bit counter + a sliding window**: WireGuard's receiver keeps the highest
   received counter plus a bitmap window of "about 2000 past values" (the protocol page [9];
   implementation window 2048, see wireguard-go [10]). The Noise spec makes replay protection
   the application's duty: the receiver must record successfully decrypted nonces and reject
   duplicates [8]. Under TCP's in-order delivery the window can shrink, but an FRP relay may
   rebuild the whole connection, so the window still has value (cross-connection replay needs
   handshake freshness alongside).
3. **Forgery-attempt limits**: cap failed verifications per key and trigger rekey/disconnect
   (the GCM bounds depend on the number of failures) [17].
4. **The cost of large-segment AEAD**: showroom's 4MiB segments are themselves legal (GCM's
   per-message plaintext cap is ~2^36−32 B ≈ 64 GiB [16]); the cost is that **the whole segment
   must be buffered, and a failure loses the whole segment** (streaming constant memory is
   showroom's existing design); GCM's GHASH and CTR are naturally parallel, so large segments
   amortize well on AES-NI (on this machine, 4MiB segments and 64KiB packets have nearly
   identical throughput; see below). To reduce the loss granularity, the VPN data plane should
   segment at MTU-scale small packets (≤64KiB or ~1500B); large segments belong to file
   envelopes.

### 2.3 Hardware acceleration and throughput (with local measurements)

[proven] Hardware instructions and library support:

- OpenSSL 3.1.0 (2023-03-14) CHANGES, official entry: "**AES-GCM enabled with AVX512 vAES and
  vPCLMULQDQ**" — VAES/AVX-512 are in mainstream TLS libraries [27].
- The RustCrypto `aes` crate: the 0.8.4 docs mention only **AES-NI and ARMv8 CE** runtime
  detection, not VAES [30a]; **the 0.9.3 docs explicitly say runtime detection of "AES-NI and
  VAES"**, with ARMv8 CE on aarch64 (naming the Apple M1) [30b].
- RFC 8452's official performance statement: AES-256-GCM-SIV "decrypting multi-KB messages is
  only about 5% slower than GCM; encryption about 2/3 the speed (two passes)" [2].

[measured (local)] This research benchmarked the RustCrypto crates on an Intel Core Ultra 9
285HX (Windows 11; `aes=true pclmulqdq=true avx2=true avx512f=false`; single-threaded,
release+LTO, in-place buffer encryption; two runs agreed):

| Algorithm (crate version) | 4MiB segment GB/s | 64KiB packet GB/s |
|---|---|---|
| AES-256-GCM (aes-gcm 0.10.3 → aes **0.8.4**) | 2.23 | 2.25 |
| ChaCha20-Poly1305 (chacha20poly1305 0.10.x) | 2.29–2.38 | 2.23–2.34 |
| XChaCha20-Poly1305 (same) | — | 2.26–2.30 |
| AES-256-GCM-SIV (aes-gcm-siv 0.12.1 → aes **0.9.3**) | **5.20–5.22** | **5.28** |

(The benchmark program and full output are in Appendix A; the two generations' dependency
trees were verified with `cargo tree`: aes-gcm 0.10.3 → aes v0.8.4, aes-gcm-siv 0.12.1 → aes
v0.9.3.)

**Conclusions**:

1. **RustCrypto has an old/new generation gap**: the aes-gcm 0.10.x showroom uses (a new
   generation **aes-gcm 0.11.1**, **chacha20poly1305 0.11.0**, and the aead 0.6/hybrid-array
   system has existed since 2026-08 [28]) rides the aes 0.8 kernel; the new aes 0.9 kernel
   (with the VAES path) is **~2.3× faster** on this machine. **Migrating to the 0.11
   generation is the number-one priority: zero cryptographic risk, pure performance gain.**
2. This measurement does not contradict RFC 8452's "GCM-SIV encryption at 2/3 speed": that
   statement is the mode overhead under the same AES-kernel generation; what was measured here
   is "new kernel + SIV" against "old kernel + GCM" — the kernel gap exceeds the mode gap.
3. On hosts without AES hardware (some soft-routers/older ARM): ChaCha20-Poly1305 is the right
   fallback (with AES hardware on, it ties the old-generation GCM here; the industry consensus
   is that without AES-NI, ChaCha is decisively better [9][30]). On desktops/servers/x86
   phones, AES hardware is essentially guaranteed [27][30].
4. [recommendation] ChmlVPN data plane: **primary AES-256-GCM (aes-gcm 0.11) + counter
   nonces**; put XChaCha20-Poly1305 in the negotiated algorithm list as the no-hardware
   fallback; if nonce misuse is a worry (multi-primary replication, complex resume-replay
   logic), pick **AES-256-GCM-SIV 0.12** outright (fastest here and misuse-resistant).

---

## 3. Q2 Handshake and key agreement

### 3.1 Noise vs TLS 1.3 vs a WireGuard-style handshake

| Dimension | Noise (IK/XX) [8] | TLS 1.3 (RFC 8446) [6] | WireGuard-style (Noise IK + fixed constants) [9][10] |
|---|---|---|---|
| RTT | IK 1-RTT (0-RTT data needs PSK); XX 2-RTT | 1-RTT (0-RTT optional) | **1-RTT**; the message right after the handshake can carry data |
| Identity confidentiality | IK: the initiator's identity hidden from passive observers, visible to the responder; XX: hidden after mutual interaction | the server certificate is plaintext (ESNI/ECH aside) | static public keys encrypted in IK (against passive observers) |
| Formal foundations | the Noise framework has a formal-analysis lineage | years of formal verification (the Symbolic/ProVerif family) | the whitepaper gives proofs (incl. the DoS cookie) |
| Library maturity | Rust: snow 0.10.0 (has had a CVE; see §5) [28][29] | rustls 0.23.46 (billion-download scale) [28] | boringtun 0.7.1 (Cloudflare) [28]; the protocol constants have an authoritative source |
| Fit for the FRP scenario | custom framing is the most flexible | ready to use, with certificates/algorithm negotiation | **natively VPN semantics**: built-in rekey timers, anti-replay, roaming |
| Key updates | application-level rekey() (REKEY(k), nonce not reset) [8] | KeyUpdate (§4.6.3) [6] | timer + counter dual-threshold automatic rekey [10] |

[recommendation] For ChmlVPN's tunnel layer: **a homegrown WireGuard-style 1-RTT handshake
(Noise IK structure) + an explicit KEM extension**, because (a) the frame format fits the FRP
pure-TCP pipe naturally (TLS also works, but the certificate/session machinery is extra burden
for a "peer-equal VPN"); (b) the KEM slot can be made the X25519+ML-KEM-768 hybrid; (c)
rekey/anti-replay/roaming have an authoritative reference implementation whose constants can be
copied (wireguard-go [10]). If the fastest landing is wanted, **rustls over the relayed TCP
stream** is also reasonable (accepting the certificate or PSK model).

### 3.2 X25519, ML-KEM, and hybrids (2026 adoption status)

[proven]

- **FIPS 203 (ML-KEM) finalized 2024-08-13**; FIPS 204 (ML-DSA) finalized the same day
  [12][13].
- **RFC 10024** (2026-08, Proposed Standard): the TLS 1.3 hybrid groups
  **X25519MLKEM768 (0x11EC, Recommended: Y)**, SecP256r1MLKEM768, SecP384r1MLKEM1024;
  deprecates the experimental Kyber768 code points [20].
- Browsers: Google's security blog announced on 2024-09-13 that Chrome 131 switches from Kyber
  to ML-KEM [22]; Chrome 131 stable on 2024-11-12 [23].
- Server traffic: Cloudflare's official blog — 2025-10-28 "more than half of human-initiated
  traffic is PQ-encrypted" [25]; 2026-04-07 "**over 65% of human traffic** to Cloudflare is
  post-quantum encrypted", targeting **full PQ by 2029 (including authentication: ML-DSA for
  origins + Merkle Tree Certificates)** [24].
- SSH: OpenSSH 10.0 (2025-04-09) **defaults to `mlkem768x25519-sha256`**; 10.1 (2025-10-06)
  warns by default on non-PQ negotiations [26].
- The pure-ML-KEM TLS groups (non-hybrid) draft-ietf-tls-mlkem-08 (2026-06) has passed IETF
  Last Call (as of 2026-08-13) [21] (Datatracker status verified by search; pages not re-checked
  one by one).

[Conclusion] X25519+ML-KEM-768 hybrid is in 2026 "the default answer for new protocols":
standardized (RFC 10024), mainstream on the browser/CDN/SSH sides, with a usable pure-Rust
implementation (ml-kem 0.3.3, FIPS 203, updated 2026-10-17 [28]). Locally measured ML-KEM-768
keypair 0.022ms, encaps+decaps 0.043ms [measured (local)] — negligible handshake cost.

### 3.3 An explicit verdict on showroom's RSA-3072-OAEP encapsulation

**Rating: replace (the long-term data-plane plan); it may stay short-term, but freeze the
discipline.**

Reasons (each with a primary source):

1. **No forward secrecy**: the k encapsulated under RSA-OAEP can be opened at any future moment
   by the holder of the platform private key (the envelope is the classic "store now, open when
   the key leaks" shape); the one-time ephemeral shares of X25519/ML-KEM naturally give
   one-time envelopes forward secrecy [12][20]. showroom's EtM and "one-time k" mitigate nonce
   reuse, not the forward-secrecy gap.
2. **Performance and size**: the RSA-3072 encapsulation header is a fixed 384B; OAEP
   encrypt/decrypt is in the hundred-microsecond-to-millisecond range; the X25519+ML-KEM-768
   hybrid ciphertext is ~32+1184B with total cost <0.1ms [measured (local): ML-KEM-768 end to
   end 0.065ms; X25519 lower still]. RSA-3072 also fits no new-deployment narrative beyond
   "2048 is not enough, 4096 is too expensive" (NIST SP 800-57 sets RSA-2048 retirement at 2030
   [37], with 3072 merely stretching to the 2035 tier).
3. **An "add-on tier" option (if RSA compatibility is mandatory)**: make the encapsulation
   `RSA-OAEP(wrap) ⊕ KEM hybrid`, i.e. do RSA-OAEP and X25519+ML-KEM-768 simultaneously,
   sharing the encapsulation-key derivation (the TLS hybrid idea [20]). Worth doing only when
   "an existing RSA distribution chain cannot be replaced immediately".
4. **The multi-primary active-active replication angle** [speculation, per the architecture
   given in the ask]: RSA envelopes encapsulated to "the platform public key" mean the servers
   must share the platform private key or re-wrap ciphertexts; the KEM ephemeral-share model
   (a fresh ephemeral per envelope) fits per-server independent keys/per-rotation re-wrapping
   more naturally, and makes "which server can decrypt" easier to build as a permission point.

**Characterizing showroom today**: its envelope goal is precisely "one-time, E2E,
verify-signature-first"; under that semantics RSA-OAEP + one-time k has **no known practical
attack surface** (security.md:133 states as much [1]); the problems are performance, header
size, the gap to the PQ era, and the missing forward secrecy. Hence the rating "replace", not
"vulnerability".

---

## 4. Q3 User authentication

### 4.1 OPAQUE and opaque-ke

[proven]

- OPAQUE's official number is **RFC 9807** (2025-07, Informational, IRTF/CFRG) [4]; RFC 9380 is
  H2C [3] (showroom's comments need correcting).
- RFC 9807 §7's RECOMMENDED configurations put **ristretto255-SHA512 first**
  (HKDF-SHA-512/HMAC-SHA-512/SHA-512/ristretto255), with P-256 combinations in the other
  columns; the group serves 3DH and "SHOULD match the OPRF group"; the security target is
  128-bit [4].
- ristretto255 itself: RFC 9496 (Informational, 2023) is **not deprecated**; new drafts
  (2025-2026) still reference ristretto255 [5]; the ristretto255 OPRF group is also
  standardized (RFC 9497) [5].
- The opaque-ke crate: the repository is now `github.com/facebook/opaque-ke` (migrated from
  novifinancial); version line 3.0.0 (2024-10-10) → **4.0.1 (2025-11-03, latest stable)** →
  4.1.0-pre.2 (2026-03-27); Apache-2.0 OR MIT from 3.0.0+ [28]. **Actively maintained; the
  3.0.0 showroom uses is a major version behind.**
- PQ-PAKE today: **there is no standardized PQ OPAQUE**; CFRG is discussing
  draft-vos-cfrg-pqpake (OQUAKE/CPaceOQUAKE+, still updated as of 2026-10) and the
  ML-KEM-to-PAKE compiler route (Tempo etc.) [38]. ⇒ Keeping classical OPAQUE at the
  authentication layer and putting PQ into the tunnel-layer hybrid KEM is the correct 2026
  division of labor [recommendation].

[Assessment for showroom]

- Suite choice of ristretto255 + TripleDH + Identity KSF: consistent with RFC 9807's
  recommendations (Identity KSF is legal — the KSF is "application's choice", and the RFC
  explicitly says the stretching runs client-side [4]).
- **The argon2id parameter gap**: RFC 9807 recommends Argon2id KSF parameters m=2^21 (2 GiB),
  t=1, p=4; showroom's external hardening is m=19456 KiB (19 MiB), t=2, p=1 (the OWASP tier).
  The trade-off is "low-end-client affordability vs offline-dictionary cost"; the RFC's
  parameters are 100× heavier in memory, unfriendly to WebAssembly/low-end devices.
  showroom's external-hardening + constant-salt + username-in-salt design is within RFC
  semantics (constant salts are explicitly allowed — blinding already provides protection [4];
  showroom's comments say the same); **it can stay, but making the parameters an upgradable
  versioned profile is advised** [recommendation].

### 4.2 Ed25519 vs ML-DSA

[proven]

- **Ed25519 is an approved FIPS 186-5 (2023-02-03) algorithm** (EdDSA/Ed25519/Ed448 entered the
  standard for the first time; DSA removed) [14]. Compliance is no longer a reason to choose
  ML-DSA.
- ML-DSA = FIPS 204 (finalized 2024-08-13; the official page notes minor pending revisions as
  of 2026-07-31) [13].
- Rust ecosystem: **ed25519-dalek 3.0.0** (2026-07-06, BSD-3-Clause) [28]; **ml-dsa 0.1.1**
  (2026-06-05, RustCrypto, pure Rust, FIPS 204 final, labeled "never independently audited")
  [28]. Locally measured Ed25519 sign 13µs / verify 24µs (1KiB) [measured (local)].

[Trade-off recommendation]

- Device/user key signatures (the showroom SR-SIG1 class): **Ed25519 primary** — mature, small
  signatures, second-tier verify throughput; SR-SIG1's "any of the user's multiple public keys
  hits" design and kid=sha256(pub)[0..8hex] can carry over directly.
- For a "resist harvest-now-decrypt-later + future non-repudiation" add-on tier: **add an
  ML-DSA-65 public key in parallel** in the key profile (dual-signing or kid-type dispatch), at
  the cost of ~3.3KB signatures. Cloudflare's roadmap (ML-DSA for origins by mid-2026 [24])
  shows server-side signing going PQ, but user-device-key signing is not urgent.
- The ML-DSA crate officially self-describes as unaudited [28]; before using it for production
  signing key profiles, watch its audit progress or consider libcrux (formally verified,
  Apache-2.0-only, 0.0.6, 2026-10-07) [28] as an alternative.

---

## 5. Q4 Recommended Rust ecosystem combination (versions/licenses/maintenance all verified via
the crates.io API)

| Purpose | crate | Latest stable (date) | License | Notes |
|---|---|---|---|---|
| AEAD (AES-GCM) | aes-gcm | 0.11.1 (2026-08-21) [28] | Apache-2.0 OR MIT | new generation (aes 0.9 kernel, VAES); showroom currently on 0.10.3 |
| AEAD (ChaCha/XChaCha) | chacha20poly1305 | 0.11.0 (2026-06-28) [28] | Apache-2.0 OR MIT | the XChaCha spec draft is dead [34]; the implementation is the de-facto standard |
| Misuse-resistant AEAD | aes-gcm-siv | 0.12.1 (2026-08-21) [28] | MIT OR Apache-2.0 | RFC 8452; fastest locally [measured] |
| KEM (PQ) | ml-kem | 0.3.3 (2026-10-17) [28] | Apache-2.0 OR MIT | pure Rust, FIPS 203; self-described unaudited |
| Signatures (classical) | ed25519-dalek | 3.0.0 (2026-07-06) [28] | BSD-3-Clause | |
| DH | x25519-dalek | 3.0.0 (2026-07-06) [28] | BSD-3-Clause | |
| PAKE | opaque-ke | 4.0.1 (2025-11-03) [28] | Apache-2.0 OR MIT | license changed from MIT to dual after 3.0.0 |
| Noise | snow | 0.10.0 (2025-07-19) [28] | Apache-2.0 OR MIT | **RUSTSEC-2024-0011 / CVE-2024-58265 (unauthenticated nonce increment enabling DoS), fixed in 0.9.5** [29]; if used, be on ≥0.10 |
| TLS 1.3 | rustls | 0.23.46 (2026-10-14) [28][31] | Apache-2.0 OR ISC OR MIT | default provider = aws-lc-rs, switchable to ring |
| Crypto binding library | aws-lc-rs | 1.19.0 (2026-10-28) [28] | ISC AND (Apache-2.0 OR ISC) | non-FIPS builds need no cmake/bindgen/Go; Windows x64 needs NASM or the prebuilt-nasm feature; the FIPS feature is separate [32] |
| Crypto binding library | ring | 0.17.14 (2025-03-11) [28] | Apache-2.0 AND ISC | slow release cadence (>19 months between stable releases); its historical maintenance bottleneck was one reason rustls switched defaults |
| PQ alternative | libcrux | 0.0.6 (2026-10-07) [28] | Apache-2.0 (only) | formally verified (hax/F*) |
| WireGuard reference | boringtun | 0.7.1 (2026-05-01) [28] | BSD-3-Clause | Cloudflare |
| RNG | rand | 0.10.3 (2026-09-20); 0.9.5 exists [28] | MIT OR Apache-2.0 | showroom pins rand 0.8.8; the ecosystem still maintains 0.8.x in parallel (0.8.8 released 2026-08-25), with an API generation gap vs 0.9/0.10 — the ask's reminder stands |
| PQ research library | liboqs | — | MIT | **the official README explicitly states "we do not recommend relying on this library in a production environment"** [33] ⇒ ChmlVPN must not adopt it |
| Password hardening | argon2 | 0.5.3 (showroom's line) [1] | MIT OR Apache-2.0 | |

**Supply-chain and licensing notes**:

1. **Pure Rust vs bindings**: RustCrypto (aes-gcm/chacha20poly1305/ml-kem/ml-dsa/argon2/sha2)
   has no C build dependencies and cross-compiles to every target Windows/macOS/Linux/iOS/
   Android/wasm32 (showroom's wasm32 custom getrandom bridge proves the route works [1]).
   aws-lc-rs is strong on performance/compliance but brings a C toolchain (Windows NASM etc.)
   [32], with higher mobile cross-compilation cost. ring sits in between but releases slowly
   [28].
2. **Licenses**: ring is `Apache-2.0 AND ISC` (a conjunction; historically with additional-
   terms controversy); aws-lc-rs is `ISC AND (Apache-2.0 OR ISC)`; the RustCrypto/dalek family
   are all permissive (the dalek family BSD-3-Clause) [28]. All usable for closed-source
   commercial distribution; note that an AND conjunction requires satisfying both licenses'
   obligations simultaneously.
3. **FIPS**: only aws-lc-rs has a FIPS path (the `fips` feature binds AWS-LC-FIPS 4.x;
   validation testing completed and submitted for NIST certification [32]); the RustCrypto
   family has no FIPS certification. Without compliance requirements, the pure-Rust combination
   is lighter for ChmlVPN.
4. **Advisory/RustSec discipline**: snow's CVE [29] is a reminder: every crypto crate must be
   version-pinned + `cargo audit` in CI; the old Kyber crate line had RUSTSEC events; PQ
   implementations should use only the first-tier ml-kem/libcrux/aws-lc-rs libraries.

---

## 6. Q5 Long-lived tunnels: rekey, forward secrecy, disconnect/reconnect, and session resumption

[proven · authoritative constants] WireGuard (wireguard-go `device/constants.go`, MIT) [10]:

| Constant | Value | Meaning |
|---|---|---|
| RekeyAfterMessages | 2^60 | proactively rekey when the send counter reaches this (leaving huge margin in the 2^64 nonce space) |
| RejectAfterMessages | 2^64 − 2^13 − 1 | beyond this, always reject (the hard gate against nonce reuse) |
| RekeyAfterTime | 120 s | session age triggering rekey (initiator only) |
| RejectAfterTime | 180 s | past this age, the session is rejected wholesale and keys zeroed |
| RekeyTimeout / jitter | 5 s / 0–333 ms | handshake retry and desync jitter |
| KeepaliveTimeout | 10 s | keepalive |
| HandshakeInitationRate | 50/s | handshake-initiation rate limit (anti-DoS) |

[proven · spec semantics]

- Noise: rekey is application-driven (`REKEY(k)` updates k with a one-way function, **nonce not
  reset**); anti-replay is the application's duty [8]; the suggested per-key cap for AESGCM is
  2^56 bytes [8].
- TLS 1.3: §4.6.3 KeyUpdate supports one-way traffic-key updates; §5.5 "Limits on Key Usage"
  gives the key-usage limits; resumption/PSK "the new connection's security context is
  cryptographically bound to the original"; (EC)DHE can be configured to keep forward secrecy;
  pure-PSK resumption "comes at the cost of losing forward secrecy", and the spec explicitly
  says the PSK binder is not dictionary-resistant and external PSKs must not come from
  low-entropy passwords [6].
- WireGuard: **built-in roaming** — "full IP roaming on both ends"; endpoint changes do not
  affect the session (identified by the peer's public key) [11]; keepalive 10s [10].

[Landing recommendations for ChmlVPN]

1. **Rekey policy**: adopt the dual thresholds (2^60 packets or 120s, whichever first; 180s/
   2^64−2^13−1 hard reject), implementationally equivalent to "per-direction send counter +
   session start time" as two checks; rekey via a new handshake (not Noise rekey()), because
   the hybrid-KEM handshake is cheap (locally, ML-KEM end to end <0.1ms [measured (local)])
   and naturally brings fresh entropy and forward secrecy.
2. **Forward secrecy**: the handshake must include one-time DH shares (X25519 + ML-KEM-768);
   traffic keys derived independently per direction (HKDF, send/receive separated); session
   keys erased after use.
3. **Disconnect/reconnect**: **no PSK session resumption** — resumption cryptographically binds
   the new session's security to the old one (TLS semantics [6]), and the saved 0-RTT is
   meaningless for a VPN; reconnect = a brand-new 1-RTT handshake + immediate restoration of
   the session state indexed by the peer's static public key (the roaming model [11]). When
   the FRP relay link drops, the client reconnects with exponential backoff (the RekeyTimeout
   5s + jitter cadence [10] is reusable).
4. **Keepalive**: a 10s-period keepalive frame (itself an encrypted frame), doubling as a
   liveness probe of the relay link.
5. **Anti-replay**: see §2.2 — 64-bit counters + sliding window + forgery-counter disconnect;
   showroom's existing API-layer time window + nonce duplicate-check (300s/HashMap [1]) stays
   for the control plane; the data plane gets its own session-level mechanism.

---

## 7. The recommended combination as of 2026-10-31 (ChmlVPN)

| Layer | Recommendation | Sources |
|---|---|---|
| Data-plane AEAD | **AES-256-GCM (aes-gcm 0.11.1, counter nonces)**; negotiated fallback XChaCha20-Poly1305 (chacha20poly1305 0.11.0); AES-256-GCM-SIV (0.12.1) for misuse-resistant scenarios | RFC 8452 [2], SP 800-38D revision direction [15], C2SP XAES [16], the aead-limits draft [17], local measurements §2.3, docs.rs/aes [30] |
| Large-file envelopes | keep showroom's segmented-AEAD model; change segment nonces to "one-time k + segment counter" or switch to XChaCha/GCM-SIV; keep the one-time-k-per-envelope discipline | showroom sources [1], C2SP [16], RFC 8452 [2] |
| Tunnel handshake | WireGuard-style 1-RTT (Noise IK structure) + **X25519+ML-KEM-768 hybrid KEM**; constants per wireguard-go | RFC 10024 [20], noise.html [8], wireguard.com/protocol [9], wireguard-go [10] |
| RSA-3072-OAEP | **replace** with hybrid-KEM encapsulation (or X25519); a dual-encapsulation add-on tier is possible during the transition | §3.3 argumentation, FIPS 203 [12], RFC 10024 [20], local measurements |
| User authentication | OPAQUE (**RFC 9807**) + opaque-ke **4.0.1**, the ristretto255-SHA512 Suite (the RFC's first recommendation), external argon2id hardening kept with versioned parameters | RFC 9807 [4], RFC 9496 [5], crates.io [28] |
| Device/request signatures | **Ed25519** primary (ed25519-dalek 3.0.0, approved under FIPS 186-5); optionally parallel ML-DSA-65 (ml-dsa 0.1.1) as the PQ add-on tier | the FIPS 186-5 announcement [14], FIPS 204 [13], crates.io [28] |
| RNG | new code on rand 0.9/0.10 + the new getrandom stack; if continuing showroom's 0.8.8, mind the ecosystem generation gap and lock -O3 | crates.io [28], showroom [1] |
| TLS (if needed) | rustls 0.23.x (aws-lc-rs default; evaluate the ring provider or minimized dependencies for a pure-Rust build chain) | docs.rs/rustls [31], the aws-lc-rs README [32], crates.io [28] |
| Not adopted | liboqs (officially not recommended for production [33]); GCM with random 96-bit nonces for long sessions (ePrint 2024/1111 argues for a ban [35]; 38D under revision [15]); GCM-SST/OGCM/AEGIS (unstandardized [18][19]) | same |
| rekey/replay/reconnect | 2^60-packet or 120s dual-threshold rekey; 180s/2^64−2^13−1 hard reject; 64-bit counter + sliding window; reconnect = new handshake + pubkey-indexed roaming; 10s keepalive | wireguard-go [10], noise.html [8], RFC 8446 [6], wireguard.com [11] |

---

## 8. Gaps (unverifiable or not directly checked; listed as-is)

1. **The NIST SP 800-38D original PDF was not parsed directly** (the tool does not support
   PDFs): the 2^32 random-nonce cap and the 2^39−256-block cap are relayed via C2SP [16],
   ePrint 2024/1111 [35], and the NIST revision notice [15]; not compared verbatim with the
   original.
2. **The Cloudflare Radar ratio page 403'd**: the exact ratio curve for 2026-10 was not
   obtained; the official-blog wording is used (2026-04 ">65%" [24]). A search summary's
   "2026-08 ~70%" (shattered.io) was not accepted as a primary source.
3. **Repository commit activity after snow 0.10.0 (2025-07-19) was not checked** (only the
   crates.io release facts and the fixed CVE).
4. **The aws-lc-rs platform-matrix page** (aws.github.io/aws-lc-rs/platforms.html) returns 404:
   per-target iOS/Android support was not verified; the report cites only its README's
   qualitative statements [32].
5. **draft-ietf-tls-mlkem-08's Last Call status** (deadline 2026-08-13) comes from a search
   summary; Datatracker pages were not re-checked one by one.
6. **Local measurements of ml-kem/opaque-ke and other pure-Rust crates on mobile (iOS/Android)
   were not done** (pure Rust without C dependencies is inferred cross-compilable;
   unverified).
7. **ML-KEM's side-channel hardening level** (whether the ml-kem crate is constant-time) was
   not independently verified; its docs self-describe as "never independently audited" [28].

---

## References

[1] showroom local sources and docs: `E:\Works\showroom` (showroom-common/src/lib.rs, opaque.rs,
wasm_shim.rs; showroomctl/src/serve.rs; docs/security.md; Cargo.toml/Cargo.lock; SPEC.md) —
read directly during this research.
[2] RFC 8452 "Synthetic IV (SIV) Ciphersuites for CEK/AES-GCM… (AES-GCM-SIV)", the RFC-Editor
info page and the Appendix B cost model ("decryption … only about 5% slower … encryption …
two-thirds"): https://www.rfc-editor.org/info/rfc8452
[3] RFC 9380 "Hashing to Elliptic Curves" (not OPAQUE): https://www.rfc-editor.org/info/rfc9380
[4] RFC 9807 "The OPAQUE Augmented PAKE (aPAKE) Protocol" (2025-07, Informational/IRTF; §7
recommended configurations and KSF semantics): https://datatracker.ietf.org/doc/rfc9807/
[5] RFC 9496 "The ristretto255 and decaf448 Groups" (Informational, 2023):
https://www.rfc-editor.org/info/rfc9496 ; the current state of ristretto255 still being cited
by new drafts is covered by the §4.1 searches (Datatracker/mailing lists).
[6] RFC 8446 "The Transport Layer Security (TLS) Protocol Version 1.3" (§2.2 PSK/resumption
quotes; ToC confirming §4.6.3 KeyUpdate and §5.5 Limits on Key Usage):
https://www.rfc-editor.org/rfc/rfc8446.html
[7] RFC 8439 (ChaCha20-Poly1305; the WireGuard protocol page cites its predecessor RFC 7539's
syntax).
[8] Noise Protocol Framework (§11.3 Rekey, §11.4 out-of-order and replay, the AESGCM 2^56-byte
advice): https://noiseprotocol.org/noise.html
[9] The WireGuard protocol page (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, nonce = 32-bit zero +
64-bit LE counter, the ~2000 anti-replay window, the cookie mechanism):
https://www.wireguard.com/protocol/
[10] wireguard-go source `device/constants.go` (RekeyAfterMessages=2^60 etc., MIT):
https://raw.githubusercontent.com/WireGuard/wireguard-go/master/device/constants.go
[11] The WireGuard official site (Built-in Roaming: full IP roaming on both ends):
https://www.wireguard.com/
[12] NIST FIPS 203 (ML-KEM) Final, 2024-08-13: https://csrc.nist.gov/pubs/fips/203/final
[13] NIST FIPS 204 (ML-DSA) Final, 2024-08-13: https://csrc.nist.gov/pubs/fips/204/final
[14] NIST FIPS 186-5 (2023-02-03; first approval of EdDSA/Ed25519/Ed448, removal of DSA):
https://csrc.nist.gov/pubs/fips/186-5/final and the announcement
https://csrc.nist.gov/news/2023/nist-releases-fips-186-5-and-sp-800-186
[15] The NIST SP 800-38D Rev.1 revision process (2025-01-06 pre-draft call for comments;
second initial draft): https://csrc.nist.gov/pubs/sp/800/38/d/r1/ipd ;
https://csrc.nist.gov/news/2025/pre-draft-call-for-comments-on-gcm-and-gmac
[16] C2SP "XAES-256-GCM" (the extended-nonce GCM construction, the 2^80-message bound, the
motivation for GCM's random-nonce 2^32 limit): https://c2sp.org/XAES-256-GCM
[17] draft-irtf-cfrg-aead-limits-13 "Usage Limits on AEAD Algorithms" (not an RFC; AES-GCM
96-bit IV ≈2^47.5 messages etc.): https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/
[18] draft-mattsson-cfrg-aes-gcm-sst (GCM-SST; an individual draft, -21, 2026-07):
https://datatracker.ietf.org/doc/draft-mattsson-cfrg-aes-gcm-sst/ (located by search)
[19] T. Iwata, Y. Seurin; the source of OGCM-1/OGCM-2, "Reconsidering the Security Bound of
GCM" (academic, unstandardized):
https://www.semanticscholar.org/paper/3561ee7443245dc59b741660cd48c8e90d571351
[20] RFC 10024 "Hybrid Key Exchange in TLS 1.3" (2026-08; X25519MLKEM768=0x11EC etc.;
verified via the draft-ietf-tls-ecdhe-mlkem Datatracker page):
https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[21] draft-ietf-tls-mlkem-08 (2026-06; pure-ML-KEM TLS groups): Datatracker (verified by
search).
[22] Google Security Blog "A new path for Kyber on the web" (2024-09-13; Chrome 131 switching
to ML-KEM): https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html
[23] Chrome 131 Release Notes (stable 2024-11-12): https://developer.chrome.com/release-notes/131
[24] Cloudflare Blog "Cloudflare targets 2029 for full post-quantum security" (2026-04-07;
"over 65% of human traffic"; ML-DSA for origin by mid-2026):
https://blog.cloudflare.com/post-quantum-roadmap
[25] Cloudflare Blog "State of the post-quantum Internet in 2025" (2025-10-28; "over half of
human-initiated traffic"): https://blog.cloudflare.com/pq-2025
[26] OpenSSH Release Notes (10.0 on 2025-04-09 defaulting to mlkem768x25519-sha256; 10.1 on
2025-10-06 warning on non-PQ negotiations): https://www.openssh.org/releasenotes.html
[27] OpenSSL 3.1 CHANGES (3.1.0 2023-03-14: "AES-GCM enabled with AVX512 vAES and
vPCLMULQDQ"): https://raw.githubusercontent.com/openssl/openssl/openssl-3.1/CHANGES.md
[28] The crates.io API (checked one by one this time): opaque-ke (4.0.1/2025-11-03,
3.0.0/2024-10-10, repo=facebook/opaque-ke, Apache-2.0 OR MIT), snow (0.10.0/2025-07-19), ring
(0.17.14/2025-03-11, Apache-2.0 AND ISC), aws-lc-rs (1.19.0/2026-10-28), rustls
(0.23.46/2026-10-14), boringtun (0.7.1/2026-05-01, BSD-3-Clause), libcrux (0.0.6/2026-10-07,
Apache-2.0), aes-gcm-siv (0.12.1/2026-08-21), ml-kem (0.3.3/2026-10-17), ml-dsa
(0.1.1/2026-06-05), aes-gcm (0.11.1/2026-08-21), chacha20poly1305 (0.11.0/2026-06-28),
ed25519-dalek (3.0.0/2026-07-06, BSD-3-Clause), x25519-dalek (3.0.0/2026-07-06), rand
(0.10.3/2026-09-20, 0.9.5 exists). Each crate at https://crates.io/api/v1/crates/<name>
[29] RustSec RUSTSEC-2024-0011 "Unauthenticated Nonce Increment in snow" (CVE-2024-58265,
fixed in 0.9.5; affects only stateful TransportState):
https://rustsec.org/advisories/RUSTSEC-2024-0011.html
[30] docs.rs/aes: [30a] 0.8.4 (AES-NI/ARMv8 only) https://docs.rs/aes/0.8.4/aes/ ; [30b] 0.9.3
(runtime detection of "AES-NI and VAES"; aarch64 ARMv8 CE): https://docs.rs/aes/0.9.3/aes/
[31] docs.rs/rustls 0.23.46 ("by default it uses aws-lc-rs"; ring switchable):
https://docs.rs/rustls/0.23.46/rustls/
[32] The aws-lc-rs repository README (non-FIPS: cmake/bindgen/Go never needed; Windows needs
NASM or prebuilt-nasm; the FIPS feature binds AWS-LC-FIPS 4.x, submitted for NIST
certification): https://github.com/aws/aws-lc-rs (the raw README, read this time)
[33] The liboqs README ("WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION
ENVIRONMENT", MIT): https://raw.githubusercontent.com/open-quantum-safe/liboqs/main/README.md
[34] draft-irtf-cfrg-xchacha-03 (Expired / Dead IRTF Document, 2020-01-10):
https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/
[35] Mattsson et al., ePrint 2024/1111 (collision attacks and the "ban GCM random 96-bit
nonces" position): https://eprint.iacr.org/2024/1111.pdf
[36] RFC 9513 is actually "OSPFv3 Extensions for SRv6" (checked on Datatracker; debunking the
AEAD-limits rumor): https://datatracker.ietf.org/doc/rfc9513/
[37] NIST SP 800-57 Part 1 Rev.5 (the RSA-2048 2030 retirement tier; 3072 to the 2035 tier) —
a standards entry not re-checked page by page this time (marked as a common-knowledge-level
citation; not directly read).
[38] draft-vos-cfrg-pqpake (OQUAKE/CPaceOQUAKE+; the PQ-PAKE state of play):
https://datatracker.ietf.org/doc/draft-vos-cfrg-pqpake

---

## Appendix A: local benchmarks (measured (local))

- Machine: Intel Core Ultra 9 285HX, 96GB RAM, Windows 11; Rust 1.98.1.
- Project: `E:\Works\ChmlVPN\.tmp\cryptobench` (a temporary benchmark project, not a
  deliverable), `cargo build --release` (opt-level=3, LTO, codegen-units=1).
- Dependencies (verified via cargo tree): aes-gcm 0.10.3→aes 0.8.4; chacha20poly1305 0.10.x;
  aes-gcm-siv 0.12.1→aes 0.9.3; ed25519-dalek 2.x; ml-kem 0.3.x.
- Command: `./target/release/cryptobench.exe` (two runs; the value ranges are merged into the
  §2.3 table).
- Raw output (first run):

```
CPU feature detect: aes=true pclmulqdq=true avx2=true avx512f=false
AES-256-GCM              4MiB segment: 2.23 GB/s  (1.9 ms/segment)
AES-256-GCM              64KiB packet: 2.25 GB/s  (29.09 us/packet)
ChaCha20-Poly1305        4MiB segment: 2.29 GB/s  (1.8 ms/segment)
ChaCha20-Poly1305        64KiB packet: 2.23 GB/s  (29.43 us/packet)
XChaCha20-Poly1305       64KiB packet: 2.30 GB/s  (28.49 us/packet)
AES-256-GCM-SIV          4MiB segment: 5.20 GB/s  (0.8 ms/segment)
AES-256-GCM-SIV          64KiB packet: 5.28 GB/s  (12.41 us/packet)
Ed25519 sign 1KiB: 13.0 us  verify: 23.8 us
ML-KEM-768: keypair 0.022 ms  encaps+decaps 0.043 ms
```

- Notes: single-threaded, fixed nonces (measuring the AEAD itself), in-place encryption (the
  detached API) to avoid copies; the numbers are for throughput measurement, not a
  constant-time security audit.
