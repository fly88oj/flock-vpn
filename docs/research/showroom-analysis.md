# Showroom protocol-layer analysis (application-layer encryption / compression / authentication)

> Goal: inventory the application-layer security protocol in `E:\Works\showroom` that runs over
> the FRP relay (a plaintext link), as the foundation for later extraction into a standalone Rust
> library (the ChmlVPN protocol layer).
> Evidence format: `file:line`, all from source/docs actually read this time; versions from
> `Cargo.lock`.
> Analysis date: 2026-10-31.

---

## 0. Overall positioning

Showroom's security premise: control-plane traffic may traverse an untrusted plaintext link
(public tunnels, non-TLS reverse proxies), **with no reliance on the transport layer** —
authentication, integrity, and confidentiality are all implemented at the application layer
(docs/security.md:5). The protocol layer is concentrated in one crate: `showroom-common` (the
lib.rs header comment self-describes it as the "protocol contract layer",
showroom-common/src/lib.rs:1-2), shared by `showroomctl` (server), `showroom` (the CLI client),
and the wasm console. Native targets `forbid(unsafe_code)`, with only the wasm32 shim excepted
(lib.rs:4-5).

The protocol layer consists of four parts:

| Module | Responsibilities | Spec source |
|---|---|---|
| SR-SIG1 request signing (lib.rs:175-340) | Ed25519 authentication + anti-replay for every HTTP request | SPEC.md §1 |
| Encrypted envelope v1 (lib.rs:342-473) | Hybrid encryption for large payloads (RSA encapsulation + AES-GCM segmented stream) | SPEC.md §2, security.md §2 |
| OPAQUE login (opaque.rs, whole file) | Password-authenticated AKE (blinded OPRF; the password never goes on the wire) | SPEC.md §16, RFC 9380 |
| Real-time downstream streams (showroomctl/src/streams.rs) | ndjson streaming bridge (not encrypted, but part of the protocol contract §10.4) | SPEC.md §10.4 |

---

## 1. Algorithm inventory

| # | Purpose | Algorithm / parameters | Implementation | Evidence |
|---|---|---|---|---|
| 1 | **Request signing (SR-SIG1)** | Ed25519 (signing key = raw 32B seed); canonical = `SR-SIG1\n<user>\n<ts>\n<nonce>\n<METHOD>\n<path_with_query>\n<sha256_hex(body)>`; Authorization value `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>` (base64url unpadded) | `ed25519-dalek` SigningKey/Verifier; `build_canonical`/`sign`/`sign_prehashed`/`verify`/`verify_with_hash` | lib.rs:222-231 (canonical), lib.rs:235-261 (signing), SPEC.md:8-10, security.md:13-29 |
| 2 | **Envelope key encapsulation** | RSA-3072-OAEP (OAEP with SHA-256), sealing a 32B one-time AES key, fixed-length 384B header | `rsa` crate `Oaep::new::<Sha256>()`; `PlatformKeys::generate` (RSA-3072) | lib.rs:347-349, lib.rs:385-393, lib.rs:429-431; SPEC.md:18 |
| 3 | **Envelope AEAD** | AES-256-GCM, 96-bit nonce, 128-bit tag; key a one-time random 32B | `aes-gcm` Aes256Gcm; `seal`/`open` | lib.rs:51-53, lib.rs:396-411, lib.rs:453-457 |
| 4 | **Envelope segmentation** | plaintext in 4MiB segments, each independently `[12B random nonce][ciphertext‖16B tag]`; no AAD; segment boundaries are the streaming boundaries | constant `SEG=4*1024*1024`; a fresh random nonce per segment (not a counter) | lib.rs:54, lib.rs:403-404; security.md:58 |
| 5 | **Login AKE** | OPAQUE (RFC 9380, `opaque-ke` 3.0.0), Suite = Ristretto255 (OPRF group + KE group) + TripleDH + **Identity KSF** (hardening externalized, see #6); identities client=user, server=`b"showroom-server"`, credential_identifier=user; unknown users go down the crate's native dummy fake-record path (ke2 same shape, anti-enumeration) | `opaque_ke::CipherSuite for Suite` | opaque.rs:32-39, opaque.rs:42, opaque.rs:74-76, opaque.rs:192-211; SPEC.md:239-254 |
| 6 | **Password hardening (rwd)** | argon2id, m=19456 KiB / t=2 / p=1 (the OWASP tier), output 32B; salt = `b"showroom-opaque-v1" + user` (constant prefix + username; the username in the salt makes the same password derive differently across accounts); executed **before** OPRF blinding; fixed-vector tests guard against native/wasm drift | `argon2::Argon2::hash_password_into`; `rwd()` | opaque.rs:53, opaque.rs:56-70, opaque.rs:298-312 |
| 7 | **Compression** | zstd level **19** (high compression), compressing **before encryption** (compress-then-encrypt, no entropy leak); upstream (docker save pipe) and downstream (pg_dump -Fc wrapping) both zstd-19; the server's unpacking adapts by magic bytes: zstd `28 B5 2F FD` / gzip `1F 8B 08` / bare stream passed through | CLI `IMPORT_ZSTD_LEVEL=19`; dump `DUMP_ZSTD_LEVEL=19`; `MagicSink` | showroom/src/main.rs:318, showroomctl/src/dbmaint.rs:157-158, unpack.rs:15-30, security.md:86-88 |
| 8 | **Hashing** | SHA-256 everywhere: request-body hash into the signature (including a streaming 64KiB-buffered variant), kid derivation (first 8 hex of the pubkey's sha256), envelope EtM integrity (the signature covers the whole ciphertext hash) | `sha2::Sha256`; `sha256_hex` / `sha256_hex_stream` | lib.rs:57-72, security.md:45, security.md:84 |
| 9 | **Randomness (native)** | `rand::rngs::OsRng` (rand 0.8): Ed25519 seed, envelope k, per-segment nonce, RSA keygen, OPAQUE (rng injected as a parameter, `RngCore+CryptoRng`) | lib.rs:23-24, lib.rs:77, lib.rs:180-183, lib.rs:384, opaque.rs:89-92 |
| 10 | **Randomness (wasm32)** | getrandom has no default backend for that target → a custom backend is registered, bridging to a JS-injected entropy pool (`sr_entropy`), driving a global `StdRng` (ChaCha12 CSPRNG); the seal session supports a deterministic seed for resumable-upload replay | lib.rs:38-42, wasm_shim.rs:22-26 |
| 11 | **Time-window anti-replay** | `\|now − ts\| ≤ 300s` (constant `SIG_WINDOW_SECS`), absolute-value check; the server checks the window before signature verification | lib.rs:47-48, lib.rs:326-328; SPEC.md:12 |
| 12 | **Nonce anti-replay** | per-user nonce duplicate check: `HashMap<"user:nonce", expiry instant>`, lazily cleaned on insert (`retain(exp > now)`), entry lifetime = the window; cleared on server restart (SPEC declares this acceptable). Note: nonce generation and duplicate-checking are both in the **caller**; common only returns `Verified.nonce` | serve.rs:34-36, serve.rs:913-922, lib.rs:289-290; SPEC.md:12 |
| 13 | **Name/identifier validation** | project `^[a-zA-Z0-9][a-zA-Z0-9-]{0,30}$` (loosened in §11) + reserved names `v2/_api/_bootstrap/_console`; user and other auxiliary names use lowercase `^[a-z0-9][a-z0-9-]{0,30}$`; docker tag rules; random project names `[a-zA-Z0-9]{8}` (OsRng) | `names::*` (hand-written matching, no regex dependency) | lib.rs:103-173 |
| 14 | **Encoding conventions** | signatures = base64url unpadded; OPAQUE messages/on-disk = base64 standard alphabet unpadded; kid/nonce/hashes = hex | lib.rs:20-21, opaque.rs:18-19, opaque.rs:8-9 |
| 15 | **registry credentials** (periphery) | bcrypt cost 10 into htpasswd (outside the protocol layer, but part of the key system) | showroomctl | security.md:139, security.md:157 |

**One spec-implementation deviation found (recorded as-is)**: SPEC.md:8 and security.md:21 both
write the nonce as "16 hex characters (8 random bytes)", but the implementation `nonce_hex()`
generates **16 random bytes → 32 hex characters** (lib.rs:74-79); `verify_with_hash` only
requires the nonce to be non-empty (lib.rs:319), without checking its length. The implementation
is more conservative than the spec (double the entropy), but the extraction should treat the
implementation as authoritative and fix the docs back, or the two sides' calibers will drift.

---

## 2. Public API surface inventory (the seams to preserve when extracting a library)

The following are all `pub` items of `showroom-common` (showroom-common/src/lib.rs, opaque.rs;
wasm_shim is a wasm32-specific C-ABI shim, not counted as a library seam):

### Constants
- `SIG_WINDOW_SECS: i64 = 300` (lib.rs:48)
- `KEY_LEN = 32`, `NONCE_LEN = 12`, `TAG_LEN = 16`, `SEG = 4MiB`, `WRAP_LEN = 384` (lib.rs:51-55,
  pub for reuse by the wasm shim and the console JS length accounting)
- `opaque::SERVER_ID: &[u8] = b"showroom-server"` (opaque.rs:42)
- `opaque::RWD_LEN: usize = 32` (opaque.rs:56)
- `names::RESERVED: [&str; 4]` (lib.rs:133)

### Types
- `Result<T> = std::result::Result<T, Box<dyn Error>>` (lib.rs:45; seal/open use `io::Result`
  separately)
- `UserKey(SigningKey)` — the Ed25519 user key (lib.rs:177)
- `Verified { user, ts, nonce }` (lib.rs:263-268)
- `AuthError { Format | Stale | BadSignature }` (lib.rs:270-287, impl Display+Error)
- `PlatformKeys(RsaPrivateKey)` — the platform RSA-3072 keypair (lib.rs:344)
- `opaque::Suite` — the CipherSuite definition (opaque.rs:32-39)
- `opaque::server_types::{Setup, Record}` — server handle aliases (opaque.rs:45-49)

### Functions — hashing / randomness / persistence
- `sha256_hex(&[u8]) -> String`, `sha256_hex_stream(impl Read) -> io::Result<String>` (64KiB
  buffer, lib.rs:57-72)
- `nonce_hex() -> String` (lib.rs:75-79)
- `write_private(&Path, &[u8]) -> io::Result<()>` (0600 persistence, native only, lib.rs:82-99)

### Functions — SR-SIG1
- `UserKey::generate / from_seed_file / save_seed (native only) / pub_string / from_pub_string`
  (lib.rs:180-218)
- `build_canonical(user, ts, nonce, method, path_with_query, body_sha256_hex) -> String`
  (lib.rs:222-231)
- `sign(user, &UserKey, method, path_with_query, body, now_unix, nonce) -> String`
  (lib.rs:235-245)
- `sign_prehashed(...body_sha256_hex...)` — hash large files streaming first, then sign
  (lib.rs:249-261)
- `verify(auth_value, &[VerifyingKey], method, path, body, now) -> Result<Verified, AuthError>`
  (lib.rs:291-300)
- `verify_with_hash(...body_sha_hex...)` — same semantics as verify, reused by callers that do
  not keep the body, such as import (lib.rs:304-340)

### Functions — envelope v1
- `PlatformKeys::generate / save_pem (native only) / load_pem / public_pem` (lib.rs:347-373)
- `seal(&RsaPublicKey, impl Read, impl Write) -> io::Result<u64>` (returns total bytes written,
  lib.rs:378-412)
- `open(&RsaPrivateKey, impl Read, impl Write) -> io::Result<u64>` (returns total plaintext
  bytes, lib.rs:416-461)

### Functions — OPAQUE (opaque.rs)
- Client: `login_start(rng, pw, user)`, `login_finish(state, pw, user, ke2_b64)`,
  `reg_start(rng, pw, user)`, `reg_finish(rng, state, pw, user, m2_b64)` (opaque.rs:89-150)
- Server: `server_setup_new(rng)`, `server_setup_load(b64)`, `server_reg_start`,
  `server_reg_canonical`, `server_record_from_b64`, `server_login_start(rng, setup,
  Option<&Record>, ke1, user)`, `server_login_finish(state_bytes, ke3_b64)` (opaque.rs:156-221)
- Hardening: `rwd(pw, user) -> [u8; 32]` (opaque.rs:60-70)

### Name validation (names module, lib.rs:103-173)
- `valid_project / valid_aux / valid_tag / check_project / check_aux / check_tag /
  random_project`

### Re-exports
- `pub use {ed25519_dalek, rsa}` (lib.rs:32) — downstream reuses the versions common has locked,
  avoiding separately pulled versions causing type incompatibility. **This "version funneling"
  semantics must be preserved when extracting the library**.

### Caller conventions above the protocol layer (not inside common; the extraction must also
draw this boundary)
- nonce generation/duplicate-checking and bind_token (60s one-time) are in serve.rs
  (serve.rs:34-44, 913-951);
- kid derivation and hit location (single-key re-verification) in serve.rs:938-946;
- compression pipelines and magic-byte unpacking are in the callers (showroom/src/main.rs,
  dbmaint.rs, unpack.rs) — common deliberately contains no zstd (lib.rs:377 comment).

---

## 3. Dependency table

From showroom-common/Cargo.toml (10-31) and the versions actually locked in Cargo.lock:

| crate | Declared | Locked version | Purpose | Notes |
|---|---|---|---|---|
| `ed25519-dalek` | `2` | 2.2.0 | SR-SIG1 signing/verification | re-exported via `pub use` |
| `rsa` | `0.9` | 0.9.10 | RSA-3072-OAEP-SHA256 encapsulation, PKCS#8 PEM | re-exported via `pub use`; pure Rust (no C) |
| `aes-gcm` | `0.10` | 0.10.3 | AES-256-GCM segmented AEAD | with aead/generic_array re-exports |
| `sha2` | `0.10` | 0.10.9 | SHA-256 | |
| `rand` | `0.8` | 0.8.8 | OsRng / StdRng / Alphanumeric | the 0.8 series (not 0.9); mind the API generation gap when extracting |
| `base64` | `0.22` | 0.22.1 (0.23.1 also in-tree, belonging to other deps) | signature/OPAQUE encoding | Engine API |
| `hex` | `0.4` | 0.4.3 | nonce/kid/hash output | |
| `opaque-ke` | `3`, default-features=false, features=["ristretto255-voprf"] | 3.0.0 | OPAQUE AKE | default features off to avoid getrandom "js" (a wasm constraint) |
| `argon2` | `0.5`, default-features=false, features=["alloc"] | 0.5.3 | rwd password hardening | pure Rust, wasm32-cross-compilable; only `hash_password_into` used |
| `curve25519-dalek` | (transitive) | 4.1.3 | ristretto255 group operations | the workspace singles it out for -O3 |
| `getrandom` | `0.2` features=["custom"], **wasm32 target only** | 0.2.17 | custom entropy backend bridge | Cargo.toml:28-30 |
| `zstd` | `0.13`, **wasm32 target only** (inside common) | 0.13.3 | browser compression session (sr_zstd_*) | native decompression consumers each depend on zstd in showroomctl/showroom |

Caller additions: showroomctl additionally natively depends on `zstd` (unpacking) and `flate2`
(the gzip fallback path, unpack.rs:40). The workspace Cargo.toml pins `opt-level=3` package by
package for rsa/num-bigint-dig/curve25519-dalek/opaque-ke/argon2/aes/aes-gcm/ctr/ghash/polyval/
sha2/zstd (Cargo.toml:27-61), plus `[profile.test] opt-level=1` (comment with measurements: 8MiB
aes-gcm at -O0 takes 0.61s vs -O1 0.013s, 46×) — **these performance attributions are directly
relevant to the benchmark setup after extraction**.

---

## 4. Streaming and segmentation details

### 4.1 Byte layout and segmentation loop of the encrypted envelope

```
[384B RSA-OAEP-SHA256(k)] || per segment { [12B random nonce][AES-256-GCM ciphertext ‖ 16B tag] }, segment = 4MiB plaintext
total-length invariant: 384 + n + ceil(n/4MiB) × (12+16)   (n = post-compression plaintext bytes)
```
(layout: lib.rs:376, security.md:54-71; the invariant test asserts: lib.rs:578)

`seal` (lib.rs:378-412) streaming semantics:
- each call generates a one-time 32B k (OsRng); after RSA-OAEP encapsulation it **verifies the
  fixed 384B length** before writing the header (lib.rs:388-393);
- a single 4MiB allocation; a `read_full` loop (pipe-short-read safe, lib.rs:464-473) fills one
  segment → fresh random nonce → encrypt → write nonce+ciphertext (lib.rs:398-411); **the last
  segment may be shorter than 4MiB** (any n>0 forms a segment);
- empty input is legal: only the 384B header, corresponding to 0 plaintext bytes (lib.rs:414-415);
- returns total bytes written (header included).

`open` (lib.rs:416-461) streaming semantics:
- `BufReader::with_capacity(SEG+NONCE_LEN+TAG_LEN)` (≈4MiB+28, lib.rs:421) — memory stays
  roughly "a couple of SEG buffers" in magnitude (one in seal, two in open);
- header under 384B / unwrap not 32B / truncated nonce / segment shorter than the tag / tag
  verification failure → all io::Error (no panic, lib.rs:423-457);
- a clean EOF ending on a segment boundary (reading 0 nonce bytes ends it, lib.rs:441-442);
- **the inherent boundary of truncation tolerance**: decryption proceeds segment by segment and
  `out` is written streaming; once earlier segments are written out, a later failure does not
  roll back (the caller uses the SR-SIG1 hash over the whole envelope as a prior integrity check,
  security.md:84 — EtM: verify the signature first, decrypt after).

A fresh random nonce per segment + a one-time random key: no counter/no AAD/no segment sequence
number. Security rests on "the envelope is one-time" (the same k is never reused, security.md:133);
to support key reuse after extraction, this must be reworked into deterministic nonces or key
derivation.

### 4.2 Transport-layer segmentation (above the envelope)

- **Upstream chunked import (§8.1/§8.3)**: slices of the envelope's raw bytes appended in order
  in **8MB chunks** (`POST /_api/import-chunk`, each chunk with its own SR-SIG1 whose hash covers
  that chunk; seq contiguous + total enforced, SPEC.md:88-95, SPEC.md:102); on the wasm side,
  `sr_seal_begin_seed` replays the already-transferred chunks with a deterministic seed (same
  seed + same push sequence ⇒ byte-identical envelope, wasm_shim.rs:24-26).
- **Downstream db-dump three-stage (§10.4)**: the server streams `pg_dump -Z0 -Fc → zstd-19 →
  seal` into `_tmp/<id>.bin` (memory constant ~4MiB; plaintext >256MB → E_QUOTA, dbmaint.rs:243-272,
  SPEC.md:143); the client pulls in **≤4MB chunks** (`DUMP_CHUNK_MAX = 4<<20`, dbmaint.rs:155) in
  a loop; after the last chunk is read, the server deletes the session (SPEC.md:144).
- **ndjson real-time downstream (streams.rs)**: `GET /_api/logs-stream` (a docker logs -f bridge)
  and `GET /_api/events` (docker events filtered to start/stop/die/health_status); one JSON per
  line `{"t":unix_ms,"l":...}` / `{"t","e","actor"}`; a 30s heartbeat `{"hb":true}` guards
  against proxy disconnects (streams.rs:28, 67-70); client disconnect → send failure →
  kill_wait reaps the child (streams.rs:105-129); stdout+stderr dual streams merged, non-UTF-8
  logs converted lossily (streams.rs:116).

### 4.3 Adaptive unpacking of the compression stream

Decryption output in three forms is routed once by the first 4 magic bytes: a zstd frame
`28 B5 2F FD` (the browser's per-push independent-frame concatenated stream / the CLI's zstd /
the server's zstd-19), gzip `1F 8B 08` (browser fallback), or a bare stream (docker save tar,
pg_dump -Fc "PGDMP") passed through (unpack.rs:1-30, 36-42). Residual streams shorter than 4B
are flushed straight through for the downstream to error on. zstd frame boundaries = push
boundaries and the output depends only on (level, input) (no randomness) → resumable-upload
replay is byte-identical (wasm_shim.rs:28-34).

---

## 5. Key files and lifecycle

Server root: `/srv/showroom` (state layout SPEC.md:49-62); client root: `~/.showroom`.

| Key/credential | File | Format and permissions | Generation | Lifecycle / rotation | Evidence |
|---|---|---|---|---|---|
| Publisher Ed25519 private key | client `~/.showroom/id_ed25519` | raw 32B seed, 0600 | `UserKey::generate` (OsRng seed) → `save_seed` (write_private 0600; tightens old permissions on overwrite) | rotation = `keygen --force` + re-registration; console login auto-generates/reuses via password binding (localStorage, a P1 experimental tier) | lib.rs:180-200, lib.rs:83-99, security.md:44, SPEC.md:101 |
| Publisher public keys (multiple) | server `state/tokens/<user>/<kid>.pub` | ed25519 public-key string `ed25519:<b64>`, kid = first 8 hex of the pubkey's sha256 | user-add / OPAQUE key-bind | `key-rm` revokes a single key; verification tries all the user's keys and records the identity of the hit kid (whoami/admin determination) | security.md:45-46, serve.rs:932-946, SPEC.md:55 |
| Admin marker | `state/tokens/<user>/<kid>.admin` | an empty file's existence = admin | admin authorization / user-add --admin | key-admin removes the right; the marker is on the key, not the account | security.md:94-95, serve.rs:956-962 |
| Password-binding marker | `state/tokens/<user>/<kid>.bound` | empty file = password-bound key | OPAQUE login → bind_token (60s one-time) → key-bind (SR-SIG1 verifies against the **candidate** public key in the body) | keep-N GC: by .pub mtime keep the most recent `BOUND_KEYS_MAX` (default 5) keys; CI keys without .bound are exempt; logout --purge → key-selfrm (can only delete your own) | SPEC.md:247-249, SPEC.md:257-269, serve.rs:43-44, serve.rs:862-895 |
| Platform RSA-3072 pair | server `state/platform_rsa` (PKCS#8 PEM 0600) + `platform_rsa.pub`; the public key distributed to clients at `~/.showroom/platform_rsa.pub` | PKCS#8 PEM; save_pem private key 0600, public key written normally | `PlatformKeys::generate` (RSA-3072) / `init-keys`; serve auto-generates at startup if missing | rotation = delete the file + init-keys + redistribute the public key (severs the decryptability of historical envelopes); leak handling in threat#10 | lib.rs:347-359, serve.rs:113-115, security.md:155, SPEC.md:23 |
| One-time RSA-3072 (downstream dump) | inside the client process, **never on disk** | generated in-process, public key PEM sent upstream | naturally rotated with every dump | backup end-to-end encryption: the platform that produced the envelope cannot itself decrypt it | security.md:78-80, security.md:156, wasm_shim.rs:17-20 |
| Server OPRF key | `state/opaque.key` | b64, 0600 | `server_setup_new`; serve auto-generates at startup if missing (same pattern as platform_rsa) | persistent (rotation invalidates all pass.opaque — this coupling must be made explicit when extracting) | SPEC.md:245, serve.rs:117-120, ops.rs:568-575 |
| OPAQUE registration record | `state/users/<u>/pass.opaque` | b64, 0600 (normalized via `server_reg_canonical` before writing) | pw-begin/pw-commit (change password while logged in) or the admin's passwd-set | atomic replacement; user-revoke deletes the whole users directory | SPEC.md:246, serve.rs:312-314, ops.rs:595, opaque.rs:178-182 |
| registry credentials | `state/users/<u>/reg.cred` (0600 plaintext) + htpasswd (bcrypt cost 10) | basic_auth | user-add / issued after login via `/_api/reg-cred` | invalidated in sync by user-revoke; issued **separately** from the login password (argumentation in plan-16 §1.3) | security.md:139, security.md:157, SPEC.md:248-249 |
| Exhibit DB credentials | `state/projects/<project>.env` (0600) | key-value env (DB_PASSWORD random) | injected on first publish | reissued on db reset (password unchanged) | security.md:158, SPEC.md:57-58 |

In-memory key material (per-process, not in the table): the envelope's one-time k (during
seal/open); OPAQUE in-flight login state (between ke2/ke3; loss on server restart acceptable,
SPEC.md:275); bind_token (60s one-time, serve.rs:43-44); the nonce duplicate-check table (cleared
on restart, acceptable, SPEC.md:12).

---

## 6. Notes for extracting a standalone library (based on the facts above)

1. **Clean seams**: lib.rs's SR-SIG1 + envelope and opaque.rs's OPAQUE have zero mutual
   dependencies; they can be split into two crates or one crate with two features; `names` is
   protocol-irrelevant and can stay or go.
2. **Four things deliberately left to callers**: nonce duplicate-checking, bind_token, the
   compression pipeline (common contains no zstd, lib.rs:377), and kid derivation — when
   extracting, either bring them into the library or pin them in the docs as caller contracts.
3. **The three hard wasm constraints** are solved and worth carrying over as-is: the getrandom
   custom backend bridge, opaque-ke with default features off, argon2 pure Rust
   (Cargo.toml:18-29 comments).
4. **Same-stack interop strategy**: both ends use the same crate and Suite definition + rwd
   fixed-vector tests against drift (opaque.rs:5-6, 294-297) — after library-ization, the vector
   tests are the gatekeeper of cross-version compatibility.
5. Known boundaries (stated as-is): first login over plaintext HTTP has no trust anchor; an
   active MITM can relay login-finish and register its own public key (SPEC.md:285-286); the
   UnknownUser fake record has statistical residue in response length/timing (SPEC.md:287-288);
   wasm localStorage holding the seed is a P1 experimental tier (security.md:144).
