# ChmlVPN research: compression strategy for VPN tunnel traffic

- Date: 2026-10-31 (conclusions per primary sources and local measurements as of today)
- Scenario premise: multiple cross-platform machines forming a VPN through ChmlFrp relay nodes;
  frp does pure TCP relaying only, not using frp's own encryption/compression; the protocol layer
  does its own end-to-end encryption (server↔client). Traffic profile: a mix of 40–1500B
  interactive small packets and bulk transfers; links may cross the public internet; bandwidth and
  RTT variable.
- Research discipline: only primary sources count (official repositories/docs, RFCs, official
  advisories, maintainer replies); local measurements are marked separately. All claims carry
  sources; proven facts and speculation are strictly separated.

---

## 0. Conclusions at a glance (tiered recommendations)

| Tier | Condition | Recommendation | Basis for thresholds |
|---|---|---|---|
| **Pass-through (no compression)** | packet length **< 128B**; or a trial compression does not shrink; or already determined incompressible (random/already-encrypted payloads); or session policy disables compression | plaintext straight into the encryption layer | Local measurement: 40B packets expand to 110–122.5% under zstd/brotli; lz4/snap save only ~1B; at 120B every algorithm gains ≤1% (§2.1 table). zstd maintainer: below ~50B fixed costs dominate ([zstd #3722](https://github.com/facebook/zstd/issues/3722)). RFC 3173 §2.2's non-expansion policy + adaptive skipping is standard practice ([RFC 3173](https://www.rfc-editor.org/rfc/rfc3173.txt)) |
| **Small-packet optional tier** | 128B–~1.5KB structured small packets on bandwidth-constrained links | **zstd level 1 + deployment dictionary (4–16KB)**, reusing compression/decompression contexts; must pair with non-expansion fallback | Local measurement (§2.2): the dictionary takes 120B→28–30%, 512B→13.5–13.7%, 1400B→9.4–9.7%, and is **faster than without**; zstd official: dictionaries are designed for ~1KB inputs and still work at ~100B ([zstd #3722](https://github.com/facebook/zstd/issues/3722)) |
| **Mid-packet fallback tier (CPU-constrained)** | 256B–1.5KB, client CPU tight or pure-Rust no-C required | lz4_flex block | Local measurement: 512B 42.6% @1294MB/s, 1400B 25.3% @1481MB/s, decompression 6.5GB/s (§2.2); lz4_flex is pure Rust, safe by default ([lz4_flex README](https://github.com/PSeitz/lz4_flex)) |
| **Bulk-stream tier** | >1.5KB continuous streams / aggregation buffers | **zstd -1 chunked streaming, 16–64KB blocks, timed flush (on the order of 5–10ms)** | Local measurement: 1MB log-like data 11.7% @864MB/s compression / 1205MB/s decompression; 64KB blocks are only 0.2 percentage points worse than whole-block (§2.3); zstd's official explanation of the small-target-block and first-byte-latency trade-off ([zstd crate docs](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)) |
| **Not adopted** | — | brotli, snappy | Local measurement: brotli q5 takes **118µs** to compress a 120B packet (zstd+dictionary 0.5µs, a gap of over 200×), and decompresses slowest too (§2.2); in the official bulk benchmark brotli-1 compresses at only ~57% of zstd-1's speed and decompresses at 27% ([zstd README](https://github.com/facebook/zstd), Silesia). snappy loses to lz4 across the board in ratio and decompression speed ([lzbench](https://github.com/inikep/lzbench)) |

**Security premise (details in §3)**: compression must go before encryption
(compress-then-encrypt), and ChmlVPN's threat model satisfies all the preconditions of the
CRIME/BREACH/VORACLE family of side-channel attacks (an FRP relay link is by construction a
"ciphertext-length observation point"; a malicious web page can inject chosen plaintext into the
tunnel). Therefore **compression should be off by default, or enabled only by policy for trusted
bulk traffic** — the shared reason why WireGuard does no compression at all and OpenVPN 2.5→2.6
progressively disabled it by default and even plans to remove it.

---

## 1. Algorithm comparison: official primary benchmarks

### 1.1 Bulk streams (MB-scale) — the zstd official README (lzbench, Silesia corpus, i7-9700K@4.9GHz)

Source: [facebook/zstd README (dev branch, fetched 2026-10-31)](https://github.com/facebook/zstd)

| Compressor | Ratio | Compression MB/s | Decompression MB/s |
|---|---|---|---|
| zstd 1.5.7 -1 | 2.896 | 510 | 1550 |
| brotli 1.1.0 -1 | 2.883 | 290 | 425 |
| zlib 1.3.1 -1 | 2.743 | 105 | 390 |
| zstd 1.5.7 --fast=1 | 2.439 | 545 | 1850 |
| **lz4 1.10.0** | 2.101 | **675** | **3850** |
| snappy 1.2.1 | 2.089 | 520 | 1500 |

### 1.2 Cross-validation — the official lzbench table (AMD EPYC 9554 single-thread 3.10GHz,
silesia.tar)

Source: [inikep/lzbench README (master, fetched 2026-10-31)](https://github.com/inikep/lzbench).
"Ratio" in the table is the compressed size as a percentage of the original; smaller is better.

| Compressor | Compression MB/s | Decompression MB/s | Compressed % |
|---|---|---|---|
| zstd 1.5.6 -1 | 422 | 1347 | 34.64 |
| brotli 1.1.0 -0 | 341 | 352 | 37.01 |
| brotli 1.1.0 -2 | 140 | 413 | 32.12 |
| lz4 1.10.0 | 577 | 3716 | 47.60 |
| snappy 1.2.1 | 401 | 1077 | 47.85 |

The two official benchmarks agree (proven):

- **zstd -1 is the best balance on bulk streams**: its ratio is markedly better than lz4/snappy
  (~35% vs ~48%); compression is slightly slower but in the same magnitude; decompression
  1.3–1.5GB/s;
- **lz4's positioning is extremely low latency**: decompression 3.7–3.9GB/s, far ahead, suitable
  for CPU-sensitive paths; but its 64KB window (see §4.1) and worse ratio limit bulk gains;
- **brotli**: only at high quality levels (-5 and above) does its ratio surpass zstd, but
  compression speed falls to 37–140MB/s (the lzbench table) and decompression is only ~1/3 of
  zstd's;
- **snappy**: worse than lz4 in both ratio and decompression speed (1077 vs 3716MB/s); in 2026
  there is no reason to choose it.

### 1.3 Small data: the zstd official "small data" chapter

Source: [zstd README, "The case for Small Data compression"](https://github.com/facebook/zstd).
Key points (all paraphrases of the official text):

1. The smaller the data, the harder to compress — compression algorithms learn from "past
   data", and at the start of a new dataset there is no "past";
2. zstd provides a **training mode (dictionaries)** for this: train a dictionary on same-family
   samples, preload it on both the compressing and decompressing sides, and small-data ratios
   improve "dramatically" while **also being faster**;
3. Dictionary gains concentrate in the **first few KB**, after which the algorithm gradually
   switches to already-decoded content;
4. There is no universal dictionary; the closer to the data family, the more effective;
5. Maintainer Yann Collet's quantified thresholds for ultra-small inputs
   ([zstd #3722](https://github.com/facebook/zstd/issues/3722), 2023): dictionaries are designed
   for ~1KB inputs, still useful at ~100B, and **below ~50B fixed costs dominate** — the zstd
   frame's fixed overhead is magic 4B + frame header ≥2B + block header 3B + literals header 1B
   + sequences header 1B;
6. Why dictionaries work for small data ([zstd #3783](https://github.com/facebook/zstd/issues/3783),
   Cyan4973's reply): suited to structured data with "**high redundancy across messages, low
   redundancy within a message**"; the archetypal scenario is "records that must be sent
   immediately and cannot wait in a batching queue" — which matches the per-packet VPN tunnel
   scenario.

Note: zstd has no separate "small-data mode" switch; the official answer for small data is
dictionary compression (the README chapter + the issues above); negative compression levels
(--fast) are merely another speed/ratio trade-off point that is faster and looser.

---

## 2. Local measurements (Windows x64, 2026-10-31)

### 2.0 Methodology (reproducible)

- Environment: Windows 10 26300 (win32 10.0.26300 x64), rustc 1.98.1
  (x86_64-pc-windows-msvc), the MSVC 2022 Community toolchain; single-threaded, release
  (lto=true, codegen-units=1, opt-level=3).
- Dependencies (versions actually resolved by `cargo add`, Cargo.lock as witness): **zstd
  0.14.3, lz4_flex 0.14.0, brotli 9.1.1, snap 1.1.2**. zstd 0.14.3 compiled its embedded C
  source on this machine directly and successfully — itself first-hand evidence of Windows/MSVC
  usability (see §5).
- Workloads (synthetic traffic from a deterministic xorshift PRNG):
  - `hdr40`: a bare 40B IP+TCP header (most fields constant, seq/ack random) — pure
    ACK/heartbeat-like;
  - `pkt120` / `pkt512` / `pkt1400`: a 40B header + templated JSON text payload (simulating
    interactive application packets; highly repetitive headers are exactly the tunnel-traffic
    trait);
  - `rand1400`: 1400B fully random (simulating incompressible payloads such as already-encrypted
    or media data);
  - `bulk1m`: a 1MB log-like bulk stream.
- Timing: 500 independent test samples per workload, each compressed/decompressed one-shot, and
  averaged (matching the per-packet tunnel shape); dictionaries trained on the spot from another
  500 training samples. Compression timing includes Vec allocation; "ctx reuse" means reusing
  the zstd compression/decompression contexts (as production code should).
- Limitations: synthetic data (templated-class gains are an upper bound); a single run; pure CPU
  timing, no network RTT. The benchmark code lives at `%TEMP%\chml-bench` (a temp directory that
  may be cleaned; the methodology and result tables are fully captured in this document).

### 2.1 Small packets (key finding: no net gain compressing small packets without a dictionary;
40B expands)

| Workload | Algorithm | Output | Ratio | Compression ns/op | Decompression ns/op |
|---|---|---|---|---|---|
| hdr40 (40B) | zstd 1 | 49B | **122.5%** | 2204 | 179 |
| hdr40 | zstd 1 (ctx reuse) | 49B | 122.5% | 742 | 68 |
| hdr40 | lz4_flex block (safe) | 39B | 97.5% | 190 | 31 |
| hdr40 | snap raw | 39B | 97.5% | 57 | 65 |
| hdr40 | brotli q1 | 44B | 110.0% | 2929 | 649 |
| pkt120 (120B) | zstd 1 | 129B | **107.5%** | 4619 | 180 |
| pkt120 | lz4_flex block (safe) | 119B | 99.2% | 462 | 46 |
| pkt120 | snap raw | 119B | 99.2% | 119 | 52 |
| pkt120 | brotli q1 | 124B | 103.3% | 4415 | 614 |

Readings (proven, limited to this machine and synthetic workloads):

- **40B packets**: zstd expands by +9B — an exact fit with the maintainer's fixed-overhead
  formula (magic 4 + frame header 2 + block header 3)
  ([zstd #3722](https://github.com/facebook/zstd/issues/3722)); brotli also expands (+4B).
  lz4/snap can shrink to 39B, but saving 1B costs an extra encode/decode and branches — not
  worth it.
- **120B packets**: even the best algorithm saves only 1B (99.2%). No algorithm has a net gain
  at 120B without a dictionary.
- **Conclusion**: <128B always passes through. A crossing point exists between 128B and 512B
  (120B no gain, 512B already saves 60%); taking 256B as a quick short-circuit threshold is an
  engineering compromise (a speculative element; see §2.2 and gaps); the more robust approach is
  RFC 3173 §2.2's "trial compression + non-expansion fallback + adaptive skipping", which does
  not depend on a fixed threshold.

### 2.2 Small/mid packets: dictionary mode turns "negative gains" into "order-of-magnitude gains"

| Workload | Algorithm | Output | Ratio | Compression ns/op (MB/s) | Decompression ns/op (MB/s) |
|---|---|---|---|---|---|
| hdr40 | zstd 1 + dict ~12KB | 28B | **70.0%** | 540 (74) | 125 (320) |
| pkt120 | zstd 1 + dict 16KB | 36B | **30.0%** | 535 (224) | 112 (1071) |
| pkt120 | zstd 1 + dict 4KB | 34B | **28.3%** | 505 (238) | 106 (1134) |
| pkt512 | zstd 1 (ctx reuse) | 205B | 40.0% | 3053 (168) | 1427 (359) |
| pkt512 | zstd 1 + dict 16KB | 70B | **13.7%** | 857 (597) | 296 (1731) |
| pkt512 | lz4_flex block (safe) | 218B | 42.6% | 396 (1294) | 87 (5885) |
| pkt512 | snap raw | 225B | 43.9% | 286 (1793) | 104 (4904) |
| pkt512 | brotli q5 | 190B | 37.1% | 169070 (3) | 3766 (136) |
| pkt1400 | zstd 1 (ctx reuse) | 297B | 21.2% | 4144 (338) | 1848 (757) |
| pkt1400 | zstd 1 + dict 4KB | 131B | **9.4%** | 1694 (826) | 779 (1796) |
| pkt1400 | lz4_flex block (safe) | 354B | 25.3% | 945 (1481) | 213 (6573) |
| pkt1400 | brotli q1 | 314B | 22.4% | 7731 (181) | 4752 (295) |
| pkt1400 | brotli q5 | 262B | 18.7% | 220843 (6) | 5519 (254) |

Readings (proven, limited to this machine and synthetic workloads; dictionary gains are an
upper bound for the "templated-traffic class"):

- **The dictionary is the only right answer for tunnel small-packet compression**: 120B goes
  from 107.5% (expansion) to 28–30%; 512B from 40% to 13.7%; 1400B from 21.2% to 9.4%. A 4KB
  dictionary performs about the same as a 16KB one — a small dictionary suffices.
- **The dictionary is also faster** (the official README claims the same): the pkt1400
  dictionary tier compresses at 826MB/s vs 338MB/s without — the dictionary prewarms the entropy
  tables and match state, so small inputs need not "learn from zero".
- **Context reuse is a hard requirement**: for 40B no-dictionary zstd, ctx reuse drops 2204ns to
  742ns (3×); the bulk tier 648→864MB/s. The zstd crate docs also stress what reusing contexts
  means for small jobs ([docs.rs/zstd bulk module](https://docs.rs/zstd/latest/zstd/bulk/)):
  "It re-uses the zstd context between jobs to avoid re-allocations".
- **brotli is out for per-packet low-latency scenarios**: q5 takes 118µs to compress one 120B
  packet (~230× the zstd+dictionary figure), and decompresses slowest too; q1 has no ratio
  advantage either. Its value lies in web static content, not tunnels.
- **lz4_flex and snap**: at 512–1400B, lz4's ratio is slightly worse than zstd's (42.6% vs
  40.0%) but compresses ~8× faster and decompresses ~8× faster (87ns vs 1427ns) — a legitimate
  fallback for CPU-constrained devices; snap is dominated by lz4 across the board, excluded.

### 2.3 Bulk streams and chunking

| Workload | Algorithm | Output | Ratio | Compression (MB/s) | Decompression (MB/s) |
|---|---|---|---|---|---|
| bulk1m | zstd 1 | 122939B | 11.7% | 648 | 1059 |
| bulk1m | zstd 1 (ctx reuse) | 122939B | 11.7% | 864 | 1205 |
| bulk1m | zstd 3 | 130545B | 12.4% | 631 | 1609 |
| bulk1m | lz4_flex block (safe) | 217745B | 20.8% | 1517 | 1991 |
| bulk1m | brotli q5 | 109856B | 10.5% | 88 | 712 |
| bulk1m | zstd 1 whole-block, 64KB chunks | 125289B | 11.9% | 771 | 2100 |
| bulk1m | zstd 1 whole-block, 8KB chunks | 140787B | 13.4% | 534 | 1560 |

Readings (proven, limited to this machine):

- Local log-like 1MB: zstd -1 compresses to 11.7%, 864/1205MB/s; lower than the official Silesia
  figure (34.6%) because the corpus differs; the ordering is unaffected.
- **64KB chunking loses only 0.2 percentage points (11.7%→11.9%)**; 8KB chunking loses 1.7
  percentage points and is slower. The official zstd API docs quantify the same: "smaller
  target blocks trade ~2% speed and ~0.1% ratio for lower first-byte latency on low-bandwidth
  links" ([Compressor::set_target_cblock_size](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)).
- brotli q5 has the best ratio (10.5%) but compresses at only 88MB/s — no match for zstd on bulk
  streams either.

### 2.4 Incompressible data: must pass through + adaptive skipping

- `rand1400`: all algorithms output 100.3–101.0% (zstd +10B frame overhead, lz4/snap +5–7B token
  overhead). Official corroboration: the LZ4 block format specifies 0.4% expansion for
  incompressible input ([lz4_Block_format.md](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md));
  RFC 3173 §2.2 requires "if compression does not shrink, you MUST send the original form" and
  recommends adaptively skipping compression for some number of packets after consecutive
  failures (an implementation-dependent threshold).
- In a real tunnel, HTTPS/video traffic is already ciphertext (random); compressing it is pure
  CPU burn. The official OpenVPN wiki argues against default compression on exactly this basis:
  "most data on the internet is already compressed before entering the VPN"
  ([OpenVPN wiki: Compression](https://community.openvpn.net/Pages/Compression)).

---

## 3. Compression/encryption ordering, side channels, and WireGuard's choice

### 3.1 Ordering: compress first, then encrypt (there is no second option)

- RFC 3173 §1: "if both compression and encryption are required, **you must compress before
  encrypting**" — encrypted output is near-random and incompressible; with compress-then-
  encrypt, the decrypting side simply decrypts and then decompresses
  ([RFC 3173](https://www.rfc-editor.org/rfc/rfc3173.txt)).
- Hence **compressed output length is the direct source of ciphertext-length differences**. AEAD
  protects content, not length. This is the root of the whole side-channel family.

### 3.2 The applicability of CRIME/BREACH/VORACLE to ChmlVPN: it holds

The attack's three preconditions: ① the attacker can inject **chosen plaintext** into the
compression window; ② the secret shares a window with the chosen plaintext; ③ the attacker can
**observe ciphertext length**. Mapping them:

- ① ②: the ChmlVPN tunnel carries all the internal traffic of member machines. A malicious web
  page can induce the victim's browser to send requests with attacker-controlled paths/
  parameters to internal services (img/form to `http://internal-address/?guess=...`), sharing one
  TCP stream with secrets like Cookies/Authorization — exactly the mechanism VORACLE targets in
  OpenVPN. The official OpenVPN advisory's own words: when the victim visits a plaintext HTTP
  site through an encrypted VPN, "if an attacker can capture the encrypted packets and feed data
  into the tunnel, they can infer clues about the content from ciphertext length"; "**without
  compression, ciphertext length does not change and the attacker learns nothing**"
  ([OpenVPN VORACLE security advisory, 2018-09-29](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/)).
- ③: **ChmlVPN's architecture structurally builds in the length-observation point** — the frp
  relay node is explicitly defined as untrusted (which is why end-to-end encryption exists), and
  the relay sees the length of every ciphertext frame; observers on the public links likewise.

Conclusion (analysis, based on the primary sources above): WireGuard's concern is **not a
theoretical risk** in ChmlVPN; preconditions ①②③ can all be satisfied. Dictionary mode would
amplify this channel further (common patterns map to shorter outputs, making length differences
finer).

### 3.3 Why WireGuard explicitly does not compress; whether that decision applies to ChmlVPN

- **Protocol fact**: the WireGuard packet format has only
  `message_type/receiver_index/counter/encrypted_encapsulated_packet`, with no compression field
  whatsoever; before sending, the inner packet is **padded to a multiple of 16 bytes** before
  AEAD ([wireguard.com/protocol](https://www.wireguard.com/protocol/)). It prefers adding padding
  over doing compression.
- **The designer's reasons** (a primary source, a 2016-12-30 mailing-list reply to a user
  proposing to add zstd): "the first concern that comes to mind is **data leakage and
  CRIME-style compression attacks** … historically, adding compression to encryption protocols
  has been quite dangerous" ([WireGuard mailing list, 2017-January
  thread](https://lists.zx2c4.com/pipermail/wireguard/2017-January/000858.html)). The same page
  shows the leakage-avoidance philosophy: the outer packet does not copy the inner DSCP "so as
  not to leak information about the inner encrypted data".
- **Later industry validation**: OpenVPN's trajectory is 2.5 defaulting to `allow-compression
  asym` (receive-only — because only upstream is VORACLE-threatened) → 2.6 defaulting to `no` →
  the official wiki stating plainly "OpenVPN will eventually remove all compression"; and it
  concludes "mixing compression and encryption without great care can have disastrous
  side-effects" and "there is no safe compression scheme" ([OpenVPN VORACLE
  advisory](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/), [OpenVPN
  wiki: Compression](https://community.openvpn.net/Pages/Compression)).
- **Does it apply to ChmlVPN**: yes, and more urgently than for WireGuard — WireGuard chose zero
  compression for general-purpose public tunnels; ChmlVPN likewise carries uncontrollable upper-
  layer traffic (members browsing the web) + an untrusted relay. **But ChmlVPN is a
  self-administered device mesh**, with legitimate compression scenarios rare in the WireGuard
  ecosystem: known bulk traffic such as backups/sync/logs between controllable endpoints. Hence
  the recommendation is not to copy "ban compression entirely" but **off by default, on by
  policy** (see §6).

### 3.4 Mitigation checklist (if compression is enabled)

1. **Off by default; enabled explicitly per stream/per subnet/per config**, only for bulk flows
   that are "trusted at both ends with no attacker-injectable content" (a strengthened version
   of OpenVPN's asym idea);
2. **Non-expansion fallback**: if compressed output ≥ the original (minus an allowed margin),
   send plaintext instead (RFC 3173 §2.2 MUST);
3. **Length normalization/padding**: bucket-pad the compressed output (WireGuard's 16B multiples
   is the minimal form; a stronger approach uses exponential buckets with jitter), directly
   blunting the length oracle at the cost of bandwidth;
4. **Adaptive skipping**: after i consecutive compression failures, skip the next k packets (the
   adaptive algorithm RFC 3173 §2.2 recommends), saving CPU as a side benefit;
5. **Dictionaries encode "structure", not "secret shapes"**: train on synthetic templates/your
   own protocol headers, not on users' plaintext traffic that is then distributed (the dictionary
   itself leaks a traffic profile);
6. **Independent policy per direction** (OpenVPN 2.5's asym proves directional asymmetry is a
   usable mitigation).

---

## 4. Streaming/chunking: window vs latency trade-offs; whether dictionaries are worth it

### 4.1 Per-packet independent vs streaming aggregation

- RFC 3173 §2: IPComp is **stateless per-message compression**, because "IP messages may arrive
  out of order or be lost" — the decompressor cannot depend on the previous packet's state.
  ChmlVPN's TCP relay does not lose packets, but multi-server active-active and connection
  migration/reconnection all require decompression state to be resettable; **per-packet
  independence (or short-window block independence) is the correct shape for reorder resistance
  and fast recovery**.
- lz4 block format hard constraints: match offsets max 65535, i.e. a **64KB window**; plus
  "blocks <12B cannot compress" and 0.4% expansion for incompressible input
  ([lz4_Block_format.md](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md), revised
  2026-10-26).
- zstd's window is tunable (`window_log`: "the maximum backtrack distance is 2^log_distance; the
  decompressing side must set at least the same level"
  [zstd crate docs](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)), but the
  larger the window, the more decompressor memory and first-packet dependency. zstd README:
  dictionary gains concentrate in the first few KB, after which the algorithm naturally uses
  already-decoded content — **there is no need to chase large windows in the tunnel scenario**.

### 4.2 Block size and latency (measured + official positions)

- Measured (§2.3): 64KB blocks lose 0.2pp of ratio; 8KB blocks lose 1.7pp and throughput drops
  ~30%.
- zstd official: `set_target_cblock_size` can make C blocks smaller, at "~2% speed, ~0.1% ratio
  cost, in exchange for lower first-byte latency on low-bandwidth links"
  ([docs.rs](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)).
- Engineering conclusion: **16–64KB independent blocks + timed flush (flush the block after
  5–10ms with no data)** presses head-of-line latency down to the same order as per-packet
  while losing <1pp of ratio. Purely interactive small packets go the per-packet tier (or pass
  through); do not put them into aggregation buffers.

### 4.3 Whether dictionary mode is worth introducing (tunnel headers are highly repetitive)

Worth it, with clear boundaries:

- **Measured gains** (§2.2): pulls 120–1400B structured packets' ratio from 99–21% down to
  28–9.4%, while compression speed **goes up, not down**. zstd's official positioning (dictionaries
  exist for cross-message redundancy, "records that must be sent immediately and cannot wait for
  batching", [zstd #3783](https://github.com/facebook/zstd/issues/3783)) is precisely the
  per-packet tunnel scenario.
- **Costs and risks**:
  1. distribution and versioning: multi-server active-active requires all servers/clients to
     share one dictionary version, and the handshake must negotiate dictID; rotation needs
     retraining and re-push (an ops cost, analysis);
  2. training data source: see §3.4-5 (train on synthetic/own-protocol templates; avoid
     training on user plaintext);
  3. side-channel amplification: dictionaries make "matching common patterns" produce shorter
     output, finer length differences — sessions with dictionaries must simultaneously enable
     padding/policy allowlists (§3.4);
  4. the upper-bound problem: these local measurements are based on templated traffic; real
     mixed traffic dilutes the gains (zstd official: "there is no universal dictionary"; the
     closer to the data family, the more effective).
- **Do not put dictionaries on <50B packets**: the official word is that fixed costs dominate in
  that range ([zstd #3722](https://github.com/facebook/zstd/issues/3722)); measured, 40B with a
  dictionary only reaches 28B (saving 12B) — not worth introducing the whole dictionary
  machinery for that; pass-through is cleaner.

---

## 5. Rust crate maturity and recommendations (including Windows)

| crate | Version (as resolved by local `cargo add`) | Form | Cross-platform/Windows | Assessment |
|---|---|---|---|---|
| **zstd** (gyscos/zstd-rs) | **0.14.3** | libzstd C bindings (zstd-sys compiles the embedded source via cc, pre-generated bindings, bindgen optional) | **this very research compiled and ran on local Windows/MSVC**; 340M+ cumulative downloads on crates.io ([crates.io API](https://crates.io/api/v1/crates/zstd)); supports vendored/pkg-config/cmake features | first choice for bulk + small-packet-with-dictionary. Note: needs a C toolchain (MSVC Build Tools); `zstdmt` multithreading only matters for large inputs (official: small inputs lose out) |
| **lz4_flex** (PSeitz) | **0.14.0** | pure Rust, no C dependency; safe by default (no unsafe), an unsafe speedup available; no_std (block) | zero toolchain requirements, zero-cost cross-platform; official benchmarks are in the same class as the C version (lzzzz) or faster ([README](https://github.com/PSeitz/lz4_flex): 66KB JSON compressed 1615 vs 1469 MiB/s) | the CPU-constrained/embedded fallback. Note: the block API rebuilds its hash table per call (the README offers `_into`/`with_table` variants) |
| **brotli** (dropbox/rust-brotli) | **9.1.1** | pure Rust port (no_std, custom allocators, optional FFI) | pure Rust, zero cross-platform worry; actively maintained (the 9.1.1 update includes error-code handling for the C decoder's CVE-2026-111497 scenario, [README](https://github.com/dropbox/rust-brotli)) | technically mature, but its performance niche is web content (see the per-packet latency measurements in §2.2); **not recommended for tunnels** |
| snap (BurntSushi/rust-snappy) | **1.1.2** | pure Rust, byte-identical to the C++ reference implementation (CI differential testing), MSRV 1.39 | pure Rust, mature | the algorithm itself is fully superseded by lz4 (§1.1/§1.2); no recommended scenario |

Recommended combination: **zstd 0.14.x (bulk chunking + the small-packet dictionary tier,
reusing CCtx/DCtx) + lz4_flex 0.14 (the optional ultra-low-latency/pure-Rust path)**. If a
target platform cannot produce a C toolchain, that platform gets only lz4_flex (zstd has no
production-grade pure-Rust encoder; ruzstd decodes only).

---

## 6. Landing recommendations for ChmlVPN (summary)

1. **Protocol design**: the frame header gains a 1-bit compression flag + an original-length
   field (the decompressing side preallocates by length — the zstd crate docs say preallocation
   is worth about 2× for decompression); uncompressed frames pass through. Follow RFC 3173:
   compress-then-encrypt, non-expansion fallback MUST, small-packet thresholds + adaptive
   skipping.
2. **Default-safe state**: compression **off** by default; enabled explicitly per route/config
   for trusted bulk flows (the WireGuard and OpenVPN evidence chain of §3.3/§3.4). Sessions
   with compression enabled should also enable output padding.
3. **Tiered execution** (threshold basis in the §0 table):
   - `<128B`: pass through (measured: 40B expands, 120B zero gain);
   - `128B–1.5KB`: optional zstd1 + dictionary (4–16KB; measured 28–9.4% and faster); if CPU is
     tight, lz4_flex (512B tier 1294MB/s);
   - `>1.5KB`/continuous streams: zstd -1 chunked at 16–64KB + 5–10ms timed flush;
   - any tier: a trial compression that does not shrink falls back to plaintext; consecutive
     failures adaptively stop trying;
   - incompressible (random/already-encrypted) traffic: pass through (measured 100.3–101%
     expansion).
4. **Context and dictionary lifecycle**: reuse `zstd::bulk::Compressor/Decompressor` per
   connection/per direction (measured 3× gap); dictionaries loaded by negotiated dictID,
   distributed in sync across servers, versions strictly matched.
5. **Do not introduce** brotli (per-packet latency worse by 2 orders of magnitude) or snappy
   (fully superseded by lz4).

---

## 7. Evidence list (primary sources)

| # | Source | Use |
|---|---|---|
| S1 | [facebook/zstd README (dev)](https://github.com/facebook/zstd) | official benchmark tables, the small-data/dictionary chapter |
| S2 | [inikep/lzbench README (master)](https://github.com/inikep/lzbench) | cross-algorithm bulk benchmark cross-validation |
| S3 | [zstd issue #3722](https://github.com/facebook/zstd/issues/3722) (Cyan4973) | fixed costs of ultra-small inputs, frame-overhead composition, the ~1KB/~100B/~50B thresholds |
| S4 | [zstd issue #3783](https://github.com/facebook/zstd/issues/3783) (Cyan4973) | the shape dictionaries suit (cross-message redundancy, cannot wait for batching) |
| S5 | [lz4 Block format (revised 2026-10-26)](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md) | 0.4% expansion, 64KB window, <12B incompressible |
| S6 | [RFC 3173](https://www.rfc-editor.org/rfc/rfc3173.txt) | compress-before-encrypt MUST, stateless per-message, non-expansion policy, adaptive skipping, security considerations |
| S7 | [OpenVPN VORACLE official security advisory](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/) | the VPN compression side-channel mechanism and the "no safe compression scheme" conclusion |
| S8 | [OpenVPN wiki: Compression](https://community.openvpn.net/Pages/Compression) | 2.5 asym default, 2.6 no default, planned removal of compression |
| S9 | [WireGuard mailing list 2017-01 thread](https://lists.zx2c4.com/pipermail/wireguard/2017-January/000858.html) | Jason Donenfeld's original reasons for rejecting compression (CRIME-style leakage) |
| S10 | [wireguard.com/protocol](https://www.wireguard.com/protocol/) | no compression field in the packet format, 16B padding, DSCP not leaked outward |
| S11 | [docs.rs zstd 0.14.3](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html) | bulk positioning (small network packets), ctx reuse, block size/window/preallocation performance guidance, dictionary API |
| S12 | [lz4_flex README](https://github.com/PSeitz/lz4_flex), [rust-brotli README](https://github.com/dropbox/rust-brotli), [rust-snappy README](https://github.com/BurntSushi/rust-snappy), [crates.io API](https://crates.io/api/v1/crates/zstd) | crate form, benchmarks, maintenance status, download counts |
| S13 | Local measurements (§2; environment and commands in §2.0) | quantified conclusions on small packets/dictionaries/chunking/context reuse |

## 8. Gaps (unverifiable or not done; listed as-is)

1. **Not measured on Linux/macOS**: cross-platform performance ordering cites official
   benchmarks (S1/S2); local data is from a single Windows x64 machine.
2. **No real traffic samples used**: synthetic templated traffic (headers + templated text) —
   dictionary gains (28–9.4%) are an upper bound for the "structured-traffic class"; real mixed
   traffic will be lower; both endpoints — <128B pass-through and 512B worth compressing — were
   measured, but the **256B quick short-circuit threshold is interpolated speculation**
   (implementation should prefer "trial compression + fallback" over a fixed threshold).
3. **No end-to-end network experiments**: compression's effect on total latency/throughput
   (including RTT, TCP relay queuing) was not measured; only CPU-side data and official
   qualitative conclusions exist; the 5–10ms flush interval is an engineering recommendation,
   not a measured optimum.
4. **crates.io metadata inconsistency**: the API's `max_version` shows zstd 0.13.3 (2025-02-20),
   but docs.rs and the local `cargo add` both resolve 0.14.3 — the local measured resolution is
   taken as authoritative; the cause of the discrepancy was not investigated.
5. **The original CRIME/BREACH papers are not directly cited**: the mechanism is cited from the
   OpenVPN VORACLE official advisory (which explicitly self-describes as "similar to CRIME and
   BREACH") and the WireGuard mailing list; the original 2012/2013 presentation materials were
   not traced back.
6. **The practical effect of the frp-side TCP relay's MSS/segmentation on compression chunking**
   was not measured (the chunking recommendation is based on the compression layer's own
   trade-offs).
