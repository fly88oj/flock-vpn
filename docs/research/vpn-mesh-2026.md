# ChmlVPN research report: cross-platform Rust VPN architecture references and multi-primary
active-active sync

- Research date: 2026-10-31 (all conclusions per sources verified as of today)
- Subject: this report serves ChmlVPN (the repository is currently empty — verified by
  `ls -la E:\Works\ChmlVPN`, containing only `.tmp/`, `.zcode/`, `docs/`): a cross-platform,
  high-performance Rust VPN; multiple machines form a VPN network through ChmlFrp (an frp relay
  service); frp does pure TCP relaying only; the encryption/protocol layer is homegrown and
  end-to-end; servers are exposed via FRP, handle login authentication and device management,
  and synchronize with each other in a multi-primary active-active fashion.
- Method and discipline: only primary sources count (official docs, RFCs, upstream source/README,
  the official crates.io registry API, Microsoft's official kernel config), each annotated with
  its source number (see "source list" at the end); proven facts are strictly separated from
  speculation/recommendations. Wherever this report says "verified" for a command-based
  conclusion, the actually executed command and its output are given.

---

## 1. TUN virtual NICs across platforms

### 1.1 Per-platform mechanisms (proven)

| Platform | Mechanism | Key facts | Source |
| --- | --- | --- | --- |
| Windows | the Wintun driver (Layer 3 TUN) | officially self-described as "an extremely simple TUN driver equivalent to Linux `/dev/net/tun`"; integration means distributing a single `wintun.dll` with the program (the official precompiled signed 0.14.1 covers AMD64/X86/ARM64/ARM32); the driver source is GPL 2.0, and the only officially supported distribution form is the precompiled signed DLL (under a more permissive license) | [S1] |
| macOS | `utun` (a kernel-control socket) | no standard `/dev/tun`; `utun` behaves essentially like the other platforms' tun; TAP scenarios use the less-public `feth` interface pair (available since 10.13); interface names created must match `utun[0-9]+` (boringtun docs) | [S6][S9] |
| Linux | `/dev/net/tun` + the `TUNSETIFF` ioctl | open `/dev/net/tun` and ioctl-register a network device; `IFF_TUN` (IP packets)/`IFF_TAP` (Ethernet frames); creating a network device needs `CAP_NET_ADMIN`; closing the fd makes the device vanish; multiqueue supported since 3.8 (parallel send/receive over multiple fds); newer kernels add `IFF_BACKPRESSURE` (qdisc backpressure) | [S2] |
| Android | `VpnService` (a Java API; the only non-root path) | `Builder.establish()` creates the virtual NIC and returns an fd: "each read takes one outbound packet routed to this interface; each write injects one inbound packet"; only one VPN at a time; the first use needs user authorization (`prepare()`); the system enforces a persistent notification; underlying sockets must be `protect()`-excluded from VPN routing (against loops); `/dev/net/tun` is root-only, and VpnService has no native-equivalent API | [S3][S6] |
| iOS/tvOS | NetworkExtension `NEPacketTunnelProvider` | iOS allows no arbitrary TUN and does not support TAP; the Rust side sends/receives IP packets over an fd passed in by the Swift layer; on iOS 16+ the old KVO method of getting the fd stopped working; the industry-standard approach (WireGuard) is to walk the fds looking for the `com.apple.net.utun_control` `sockaddr_ctl` peer | [S4][S5][S6] |

Note: Apple's developer.apple.com doc pages render purely in JS, and none of this session's
fetching tools could retrieve the body text (see "open questions/limitations"); the iOS facts in
the table above rest on the official repository docs of three independent upstream projects
(tun, tun-rs, tappers/boringtun).

### 1.2 The Rust ecosystem today (verified via the official crates.io API, 2026-10-31)

| crate | Version | Last update | Status highlights | Source |
| --- | --- | --- | --- | --- |
| **tun-rs** | 2.8.16 | 2026-10-29 (active as of yesterday) | TUN+TAP; claims 11+ platforms including Linux/Windows/macOS/BSD/Android/iOS/tvOS/OpenHarmony; Windows via wintun.dll; Linux supports TSO/GSO offload and multi-queue (self-reported benchmark 70.6 Gbps, offload 3–4× faster); ships an iOS fd-search example and an Android `VpnService.Builder().establish().getFd()` example; both sync and tokio/async-io APIs; Apache-2.0; 680K+ downloads | [S5][S7] |
| tun (meh/rust-tun) | 0.8.14 | 2026-07-21 | the classic cross-platform library (Win/Linux/macOS/FreeBSD/Android/iOS/tvOS/OpenHarmony); now maintained and published by ssrlive; Windows depends on `wintun-bindings`; the README includes a complete iOS `NEPacketTunnelProvider` fd-passing example; WTFPL license | [S4][S7] |
| tun2 | 4.0.0 | 2024-10-27 (unupdated for ~2 years) | a fork of tun (ssrlive/rust-tun); effectively stalled; not recommended for new projects | [S7] |
| tappers (pkts-rs) | 0.x (WIP) | — | positioned for testing/packet-capture friendliness (the pkts.org ecosystem); no mobile support (explicitly states the Android/iOS platform APIs have no native equivalents and it does not wrap them); Windows TAP depends on tap-windows6; uniform cross-platform packet format; minimal dependencies | [S6] |
| wintun (nulldotblack) | 0.5.1 | 2025-01-29 | safe Rust bindings to the Wintun C library: `load` the DLL → `Adapter::create/open` → `start_session(MAX_RING_CAPACITY)` ring-buffer send/receive; MIT; the README explicitly says async support is still TODO | [S8] |
| rtnetlink | 0.23.0 | 2026-08-18 | a high-level netlink library for Linux routing/address/link configuration, tokio-integrated; 28.8M downloads. Note: the original rust-netlink org repository is archived (2022-10-07), but the rtnetlink crate itself keeps releasing under a new maintainer (Gris Ge) | [S10][S11] |
| boringtun | — | — | Cloudflare's Rust userspace WireGuard implementation (library + CLI); officially self-described as deployed on millions of iOS/Android devices and thousands of Cloudflare Linux servers; offers C ABI and JNI bindings; macOS uses utun directly | [S9] |

**Conclusion (recommendation)**: the data-plane NIC layer should use **tun-rs** directly (the
best activity, platform coverage, offload/multi-queue, and mobile fd-access paths); Linux
routing/address programming pairs with **rtnetlink**; on Windows there is no need to depend on
the wintun crate directly (it lacks async) — tun-rs has the wintun integration built in. If
userspace WireGuard protocol compatibility is ever needed, boringtun is the Rust ecosystem's
most mature reference.

### 1.3 `/dev/net/tun` + `NET_ADMIN` inside containers (focus: Docker Desktop on Windows)

- **Native Linux containers (proven)**: Docker's official run reference states "by default
  containers are unprivileged and cannot access any device"; `--cap-add`/`--cap-drop` can
  add/remove Linux capabilities granularly, with `NET_ADMIN` defined as "perform various
  network-related operations"; `--device=[]` allows exposing host devices to the container
  without `--privileged` (the official example is exactly `--cap-add SYS_ADMIN --device
  /dev/fuse`) [S12]. The kernel docs also confirm: opening `/dev/net/tun` requires
  `CAP_NET_ADMIN` (for non-own devices) [S2].
- **Docker Desktop on Windows (this session's focus, proven to kernel level)**:
  1. Docker's official docs: Docker Desktop for Windows supports the WSL 2, Hyper-V, and Docker
     VMM backends, and **"WSL 2 is the default"** (per-user installs: WSL2/Docker VMM only)
     [S13].
  2. Our own verification this session (primary source: Microsoft's official WSL2 kernel config
     file):
     `curl -s https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/master/Microsoft/config-wsl | grep -E "^CONFIG_TUN"`
     output: `CONFIG_TUN=y` — the official WSL2 kernel builds TUN **into the kernel** (not a
     module), so no `modprobe tun` is needed inside the WSL2 VM.
  3. Corroboration (an upstream maintainer, not official docs): the gluetun (containerized VPN
     client) maintainer confirmed in a Docker Desktop (WSL2) discussion that it works without
     installing the tun kernel module; a user's log shows `modprobe tun` inside the VM failing
     with "module not found in 5.4.72-microsoft-standard-WSL2" while the container's own mknod
     of `/dev/net/tun` let OpenVPN work normally — i.e. "the missing-module error is harmless;
     the device node must be created inside the container" [S14].
- **Conclusion (proven)**: running TUN-needing Linux containers under Docker Desktop on Windows
  (the default WSL2 backend) works: give the container `--cap-add NET_ADMIN` plus `--device
  /dev/net/tun` (or `mknod /dev/net/tun c 10 200` inside).
- **Limitation (unverified)**: the Hyper-V / Docker VMM backends use Docker's own kernel, whose
  `CONFIG_TUN` was not verified this time; if target users might switch to those backends,
  verify separately.

---

## 2. Open-source reference points: data plane / control plane / key distribution / relay
architecture

| Project | Data plane | Control plane | Key distribution | Relay/traversal | Source |
| --- | --- | --- | --- | --- | --- |
| **boringtun** | userspace WireGuard (a Rust library; the protocol layer ships no network/tunnel stack — bring your own platform) | none (just a protocol engine; the CLI simulates the wg interface) | inherits the WireGuard static-pubkey model | none | [S9] |
| **innernet** | kernel/wireguard-go WireGuard | a single coordination server (`innernet-server`): manages peers, CIDRs, associations-as-ACLs; peers actively pull config | an invite file (one-time); on redemption the client **generates a fresh keypair** and registers the public key with the server; the server distributes other peers' pubkeys/endpoints to peers | no built-in relay; relies on the public endpoints the server sees for direct connections (manual override-endpoint possible) | [S15] |
| **netbird** | WireGuard (kernel first) p2p mesh | the Management service (gRPC+UI): registration/auth (IdP/one-time setup key), network map, **IP allocation**, access-policy push, control-channel change push | clients generate WireGuard keypairs locally and hand the public key to Management, which distributes it to authorized peers; signaling messages are NaCl box (Curve25519+XSalsa20+Poly1305) end-to-end encrypted | ICE (pion)+STUN hole-punching; the Signal service only relays encrypted signaling and stores no data; on punch failure it falls back to a Relay (formerly Coturn TURN; since v0.29.0 a homegrown WebSocket relay); Rosenpass post-quantum support | [S16][S17] |
| **tailscale** | WireGuard (wireguard-go) full-mesh; ACLs enforced **at each node on inbound decryption** | the "coordination server" = a public-key exchange mailbox: nodes upload pubkeys + current endpoints and download other nodes' pubkeys/addresses in the domain; authentication is outsourced to an OIDC/SAML IdP; policy centrally stored, distributedly enforced | private keys never leave the node; E2E encryption; the coordination server cannot decrypt | STUN/ICE advanced hole-punching; on failure it falls back to **DERP** (Designated Encrypted Relay for Packets): globally distributed "encrypted TCP relays" using HTTPS streams + WireGuard keys; role similar to TURN but blind-forwarding already-encrypted traffic it cannot decrypt | [S18] |
| **zerotier** | homegrown VL2 (VXLAN-like Ethernet emulation) + VL1 (encrypted p2p transport); VL1 encrypted with Salsa20/Poly1305 (the NaCl construction), **explicitly no forward secrecy** | the network controller (an SDN CA): issues member certificates (CoM, a sliding time window to avoid clock dependence), capabilities, tags, and **certificates of ownership (anti IP spoofing)**; revocations propagate p2p quickly via the rumor-mill algorithm | identity = a keypair; the 40-bit address is derived from the public key at computational cost (a collision costs ~10K CPU-years); first-come-first-served; expires after 60 days of inactivity | "planet" root servers (4, run by ZeroTier Inc., DNS-root-like) + user-hosted "moon" roots; roots first relay to trigger transport-triggered link provisioning, then the two sides punch (including symmetric-NAT port prediction, uPnP/NAT-PMP); if punching fails, root relaying continues (slow) | [S19] |

### Points worth borrowing (for ChmlVPN)

1. **"Centralized control plane, distributed data plane"** (the Tailscale model [S18]):
   ChmlVPN's servers already handle login/device management and are natural coordination
   servers; the FRP relay link is the equivalent of a self-hosted "DERP/Coturn role" — both are
   industry-proven: a relay that blindly forwards ciphertext works, and end-to-end security does
   not depend on the relay being trusted.
2. **The relay cannot decrypt**: DERP "never a way for a DERP server to decrypt your traffic",
   and the NetBird relay likewise [S17][S18]. ChmlVPN's "frp does pure TCP relaying + the
   protocol layer encrypts itself" is consistent with that principle, and frp's
   `transport.useEncryption/useCompression` are **off by default** (the frp official README:
   "The features are off by default") [S20], so no conflict with the homegrown encryption layer.
3. **Per-node ingress filtering enforcement** (Tailscale [S18], innernet's CIDR associations
   [S15]): device ACLs are pushed to the endpoints and enforced there, not just filtered at the
   server gateway.
4. **Online/revocation propagation mechanisms** (ZeroTier's rumor-mill revocations and
   certificate sliding windows [S19]): under multi-primary active-active, "kick device/revoke"
   must take effect network-wide without a central single point — worth borrowing.
5. **Anti IP spoofing** (ZeroTier certificates of ownership [S19]): the "device registry +
   virtual IP" binding can be backed by a signed credential that endpoints verify independently.
6. **Post-quantum** (NetBird's Rosenpass integration [S16]): an optional evolution direction.
7. **A reality check for HA**: NetBird's self-hosting docs state plainly that Management/Signal
   high availability is a **commercial feature**, and the self-hosted scaling path is "split
   Relay + SQLite→PostgreSQL" [S21] — showing that "a multi-primary active-active control plane"
   is not a default capability among comparable projects either; ChmlVPN building its own is a
   reasonable differentiator.

---

## 3. Virtual IP allocation, MTU, routing, and NAT

### 3.1 IP address-range choice and allocation/collision avoidance (reference facts)

| Project | Address pool | Allocation and collision strategy | Source |
| --- | --- | --- | --- |
| Tailscale | IPv4 `100.64.0.0/10` (CGNAT, the RFC 6598 reserved range); IPv6 ULA `fd7a:115c:a1e0::/48` | "a node's IP stays the same as long as it remains registered (unless the admin changes it)"; the range does not collide with common private nets like 10/8 or 192.168/16; internally reserves `100.100.0.0/24`, `100.100.100.0/24`, `100.115.92.0/23` as unallocatable; officially stated risks: conflict if the ISP also uses the CGNAT range; backing up/cloning a system disk yields two devices with the same IP | [S22][S23][S27] |
| NetBird | also `100.64.0.0/10` | one random /16 per account; new peers get a **randomly chosen free address** from it; deleting a peer releases the address immediately, no retention, reallocatable | [S17] |
| innernet | your choice (the example uses a `10.60.0.0/16` CIDR tree) | "for security reasons, IPs are never reused and peers can only be disabled, not deleted"; the server CLI auto-suggests the next available IP; the address is fixed after invite redemption | [S15] |
| ZeroTier | the controller-configured pool; plus two NDP-emulating IPv6 modes, rfc4193/6plane (stateless local derivation by nodes, no central allocation) | the binding of the 40-bit cryptographic identity to the IP is protected against spoofing by "certificates of ownership" | [S19] |

**Recommendations for ChmlVPN (speculation/design advice, not sourced conclusions)**:
- adopt `100.64.0.0/10` (the RFC 6598 IANA IPv4 shared address space reserved for CGN [S27];
  Tailscale/NetBird dual precedent [S22][S17]), reserving several /24s for internal use
  (mirroring Tailscale's reserved subnets [S23]); use a ULA prefix for IPv6 (mirroring
  Tailscale's `fd7a::/48` [S22]).
- three collision-avoidance principles (all with precedent): allocation is decided by
  **strongly consistent storage** (see §5); addresses are bound to device pubkeys/device IDs;
  the "release policy" is one of two choices with fixed semantics — learn from NetBird's
  immediate release (address-saving; random re-picking avoids collisions [S17]) or innernet's
  never-reuse (safer but address-consuming [S15]). Given this project's limited device count and
  security-first stance, "disable without deleting, IP retained" is advised, with an explicit
  reclamation command.
- against same-IP from backups/clones: learning from Tailscale's gotcha entry [S23], detect
  duplication at join time and force the later comer to reallocate.

### 3.2 MTU and fragmentation

Proven facts:
- RFC 8200 (IPv6): links with configurable MTU "must be configured to have an MTU of at least
  1280 octets" (the text at [S26]; verified by grep near line 1385 this session).
- Tailscale's official docs: "Tailscale uses a maximum transmission unit (MTU) of 1280", noting
  that larger packets sent by other interfaces may be silently dropped; the fix is lowering the
  link MTU or MSS clamping (verified from the official page's RSC data this session [S24]).
- ZeroTier's official docs: default MTU `2800`, raisable to 9000 (jumbo frames), but "every
  member and the physical path between them must support the larger value or traffic may be
  silently dropped" [S25].

Analysis and recommendation for ChmlVPN (speculation):
- over the **single TCP relay** through FRP, the outer layer is a byte stream: inner IP packets
  will not undergo IP fragmentation due to path MTU (carried by outer TCP segmentation), so
  MTU's meaning is mainly (a) inner TCP negotiates MSS against the inner MTU, and (b) receiver
  reassembly buffers and memory control.
- recommend TUN MTU **1280** (matching Tailscale [S24] and the IPv6 minimum [S26]) or ~1380 as a
  compromise; the key is **avoiding oversized** values that make the peer's kernel silently drop
  packets exceeding the TUN MTU (ZeroTier's docs describe the phenomenon [S25]).
- **TCP-over-TCP must be taken seriously**: running a VPN over "FRP pure TCP relaying" nests
  inner TCP streams inside outer TCP; the two layers' congestion control/retransmission
  interfere with each other, and weak-network performance collapse is a classic problem (the
  classic reference is O. Titz, "Why TCP over TCP is a bad idea", 2001; the original site was
  unreachable this session — its existence and citation record were verified via the references
  of an arXiv OpenVPN performance paper [S28]). Mitigations: reserve a future P2P direct (UDP)
  upgrade path; short-term, per-stream rate limiting/queue management for inner traffic avoids
  amplifying contention across streams.

### 3.3 Routing tables and NAT

Proven facts:
- The WireGuard family (innernet/NetBird/Tailscale) all do cryptographic routing via "peer
  pubkey ↔ destination subnet (allowed-IP style)" mappings, with config pushed by the control
  plane [S15][S17][S18].
- tun/tun-rs automatically configure routes per address when creating devices on macOS/BSD
  (README: `route -n add -net 10.0.0.0/24 10.0.0.1`); tun-rs lists "consistent cross-platform
  automatic routing" as a core feature [S4][S5].
- Android: routing is decided by the `VpnService.Builder` parameters (official: "creates a
  virtual network interface, configures addresses and routing rules"), and underlying sockets
  must be `protect()`-ed to avoid tunneling loops [S3].
- Linux hardening companions (innernet's official advice): strict reverse-path filtering
  (`rp_filter=1`, the RFC 3704 context) against cross-interface source spoofing, and
  `SO_BINDTODEVICE`/`IP_BOUND_IF` to keep control traffic on the physical interface [S15].

Recommendation for ChmlVPN (speculation/design): a small full-mesh network can use a single
"point the whole /16 pool at the TUN" route; for per-group isolation, push specific routes +
endpoint ingress filtering (borrowing from §2.3); if the server does exit-node forwarding, NAT
is needed — Windows uses the built-in NAT/forwarding, Linux uses nftables masquerade — the
specific policy is an implementation decision; no additional facts needing citation were found
this time.

---

## 4. Data-plane multiplexing over a single FRP-relayed TCP connection

Premise (proven): frp's `type = "tcp"` proxy is raw port-level TCP forwarding (official example:
`ssh -oPort=6000 user@frps-public-IP` reaching an intranet port 22) [S20]; frp's own
encryption/compression are off by default [S20]; so ChmlVPN has full protocol-stack freedom
over this TCP stream.

### 4.1 Candidate comparison

| Option | Principle and ecosystem | Pros | Cons/risks | Source |
| --- | --- | --- | --- | --- |
| **yamux** | the hashicorp spec (spec.md), explicitly designed as "stream multiplexing over an underlying reliable, ordered connection (TCP/Unix socket)": bidirectional streams, flow control/backpressure, **native KeepAlive**, low overhead supporting thousands of streams; the Rust implementation is libp2p/rust-yamux (0.14.1, updated 2026-09-21, implementing the official spec) | matches the "reliable byte stream" premise exactly; small protocol, easy to audit; keepalive built in; the Rust implementation is used at scale by libp2p/substrate | stream-level HOL over TCP remains (see 4.2); Go/Rust dual implementations need version/semantics alignment | [S29][S30] |
| HTTP/2 (h2) | RFC 9113; the Rust ecosystem's h2 crate (0.4.20, 930M downloads) is very mature | the deepest ecosystem; the h2 crate usable directly; browser/proxy compatibility | semantics are request-response oriented (one side initiates; header semantics); RFC 9113 states plainly: "Note, however, that TCP head-of-line blocking is not addressed by this protocol" — the same transport HOL unsolved, while taking on needless HTTP semantic complexity | [S31][S32] |
| QUIC (quinn) | RFC 9000: "A UDP-Based Multiplexed and Secure Transport" — designed on the premise of UDP carriage; built-in stream multiplexing, flow control, connection migration; quinn (5.3k stars) is a pure-Rust implementation; `quinn-proto` is I/O-free and can attach to a custom event loop | if the underlying transport were UDP, this would be optimal: no inter-stream HOL, 0/1-RTT, built-in TLS1.3 | **running QUIC inside "a single TCP stream" is double-layer reliable transport** (QUIC's own ACK/retransmit stacked on TCP), and the quinn ecosystem centers on the UDP socket (endpoint = a single UDP socket); adapting it to a stream transport is an unsupported use; zero benefit, doubled complexity | [S33][S34] |
| Custom framing | length-prefixed frames + stream IDs + control frames | simplest, controllable, continuous with the showroom approach | you must build it all yourself: flow control, keepalive, backpressure, sticky-packet boundaries, version negotiation — rewriting half a yamux | (engineering judgment) |

### 4.2 Head-of-line blocking (proven vs analysis)

- Transport-layer HOL: as long as the underlying transport is a single TCP, no multiplexer can
  eliminate it — RFC 9113's statement about HTTP/2 applies equally to yamux [S32]. QUIC's
  inter-stream HOL elimination depends on UDP carriage [S33]; unavailable inside TCP.
- Analysis (speculation): ChmlVPN's practical impact depends on the inner traffic mix. Inner
  UDP/ICMP (games, DNS) is HOL-sensitive; inner TCP is itself ordered, so the loss is mainly
  "fairness across multiple inner streams sharing one outer TCP". Mitigations: yamux
  stream-level backpressure + moderately larger windows + dedicated small high-priority streams
  for control flows (heartbeat/signaling).

### 4.3 Heartbeat and disconnect/reconnect (proven + recommendations)

- yamux's native KeepAlive (explicitly listed in the README); no need to invent ping frames
  [S29].
- On the frp side: the frps↔frpc control connection has its own heartbeat (auth can optionally
  be extended into heartbeat packets), but that is frp's internal connection; the ChmlVPN
  client↔server session heartbeat is our own protocol layer's responsibility [S20].
- Recommendations (speculation): after the outer TCP drops — (1) a session-handle retention
  window + exponential-backoff reconnect (ChmlFrp node-list rotation); (2) after reconnecting,
  restore stream context via session ID + monotonically increasing sequence, or simply rebuild
  everything (the device re-pulls network config on coming online, borrowing Tailscale's
  "re-pull after control-channel reconnect" model [S18]); (3) configurable heartbeat interval,
  default 30s, 3 missed responses = link down (engineering convention, not a sourced
  conclusion).

### 4.4 This topic's recommendation (speculation/design advice)

**Recommended: the E2E encryption layer (continuing the showroom protocol layer; the inventory
was not provided with the task, see open questions) rides on top of yamux**: `TcpStream(FRP) →
handshake/encryption layer (E2E; the server identity authenticated by credentials preloaded at
registration) → yamux → logical streams {device data stream (framing carrying TUN packets),
control stream (network config/heartbeat/events)}`. yamux's Rust implementation
(libp2p/rust-yamux) is actively maintained, its protocol spec is public and auditable, keepalive
is native, and it fits the "one reliable byte stream" premise exactly; HTTP/2 (semantic
mismatch) and QUIC-over-TCP (a double reliable layer) are not advised. If showroom's existing
protocol already has a frame format and stream concept, "custom framing" is the low-migration-
cost alternative, but flow-control and keepalive semantics should be completed before deciding.

---

## 5. Multi-primary active-active server synchronization

### 5.1 Candidate mechanisms compared (facts per sources; assessments are analysis)

| Mechanism | Consistency and conflict handling | Assessment for this project's three data classes | Source |
| --- | --- | --- | --- |
| **Raft (openraft)** | strongly consistent: log replication + a single leader committing; openraft (Rust, 0.9.25 stable / 0.10.0-alpha.37, still releasing as of 2026-10): `ensure_linearizable()` linearizable reads, snapshot/log compaction, joint dynamic membership, learner nodes, chaos tests (8 nemesis classes incl. partition/pause/clock skew) in CI; the consensus engine of Databend's meta-service | **device registry + auth credentials**: read-mostly write-rare, requiring "revocation effective globally immediately" and "read/write consistent on any node" — exactly Raft's sweet spot. Reads via a follower's linearizable read precisely satisfy "clients get identical results on any server" | [S35] |
| **CRDT** | eventually consistent; concurrent writes auto-merge (no conflict, but "merging" ≠ "correct") | suits **online state**, the "last-seen-wins / set add-remove" kind of data; unsuited to credential revocation (must be totally ordered and timely) | (general mechanism knowledge; this report did not verify the CRDT original papers point by point — see open questions) |
| **Gossip/SWIM (memberlist)** | memberlist: SWIM + the Lifeguard extensions, "eventually consistent but converges quickly"; manages membership and failure detection with tunable convergence/bandwidth | suits **online state + server membership discovery**: low-frequency small state, tolerating second-level staleness; carries no strongly consistent data | [S36] |
| **Shared database** (e.g. PostgreSQL) | consistency delegated to the DB (single writer + replication); the application layer must handle concurrent-write semantics for multi-primary itself | the easiest baseline (NetBird's self-hosted path: SQLite→PostgreSQL [S21]); but it introduces an external stateful component and ops surface, and the "multi-primary" is really "load balancing in front of the DB" — failover semantics are not the application's | [S21] |

### 5.2 Conclusions by data class

| Data | Consistency need | Recommended mechanism | Conflict handling |
| --- | --- | --- | --- |
| Device registry (device IDs, virtual IPs, metadata) | strongly consistent; IP allocation must not collide | **openraft replicated state machine** (redb/rocksdb suggested as the state-machine store) | every allocation/release = a serialized operation in the Raft log, naturally conflict-free; snapshots admit new nodes |
| Auth credentials (device keys/revocation list) | strongly consistent + timely revocation | same (the same state machine) | a committed revocation takes effect in total order; short-TTL session tickets bound the propagation-delay surface |
| Online state (who is connected to which server) | weak consistency acceptable (second-level staleness) | **local ownership + gossip propagation** (the memberlist idea: each server authoritatively reports only "devices connected to me", with lease TTLs) | the "same device connected to two servers" conflict: newest lease wins; the old server kicks the session on notification (borrowing ZeroTier's fast revocation propagation [S19]); this is a policy decision, not a data-merge problem |
| Network-config snapshot (peers/routes/ACLs pushed to clients) | derived data | versioned and produced by the Raft state machine; gossip/push to clients | applied idempotently by version number |

### 5.3 Recommended architecture under this project's constraints (speculation/design advice)

Constraint recap: each server attaches to its own FRP relay node; clients get identical results
on any server; servers also interconnect over the public internet (their own FRP links or
direct).

Two phases recommended:

1. **Phase one (quick usability) — "single-writer, multi-reader" Raft multi-primary
   active-active**:
   - 3 servers (tolerating 1 failure; 5 for 2) form an openraft cluster; registry/credentials/
     config all enter the state machine;
   - clients may connect to any server: reads (login validation, config pull) go through that
     node's linearizable read (`ensure_linearizable`); writes (registration, config changes) are
     forwarded by that node to the leader — the extra FRP hop's latency is negligible for a
     low-write workload;
   - online state uses a separate gossip channel (a homegrown UDP/TCP gossip or a port of the
     memberlist idea; Rust has no official memberlist — self-implement or use another crate; see
     open questions) to propagate leases;
   - a whole server or its FRP node going dark: Raft re-elects automatically; clients switch by
     "server list + liveness probing" with equivalent results (mirroring NetBird's design
     orientation of "clients tolerate brief Management outages; established connections are
     unaffected" [S21]).
2. **Phase two (when scale/autonomy demands)**: delegate "session-ticket issuance" to a local
   per-server capability (the credential root lives in Raft; short-TTL tickets issued locally),
   further removing the login path's dependence on the leader.

Explicitly not recommended: CRDT for credentials (revocation semantics unguaranteeable); pure
gossip for the registry (IP allocation can split-brain and collide); a shared DB alone
(offloads the multi-primary problem to the database, and it does not fit the "one FRP node per
server, no shared intranet" deployment form — NetBird's PG scheme still requires the database
to be separately reachable [S21]).

---

## 6. Recommended overall architecture (synthesizing the above; all design advice)

```
┌────────────── clients (Win/macOS/Linux/Android/iOS) ─────────────┐
│ TUN(tun-rs) ←framing→ session layer (E2E encryption, continuing showroom) ←yamux→ single TCP │
│ routing/protect/fragmentation control (§3)                         │
└───────────────┬──────────────────────────────────────────────────┘
                │ via ChmlFrp (frp pure TCP proxy, no encryption no compression)
        ┌───────┴────────┐
        ▼                ▼
   Server A (FRP node A)   Server B (FRP node B) ... (3/5 machines)
        │  openraft strongly consistent state machine: device registry + credentials + config versions │
        │  local session table + gossip leases (online state, membership discovery)      │
        └────────────── inter-server interconnect (public direct or via own FRP) ───────┘
```

Key points: the data plane between client and server is still a "session tunnel" (the first
release does not do peer-direct connections, avoiding NAT-traversal complexity); servers
synchronize only the control plane; FRP sees ciphertext throughout.

---

## 7. Open questions and limitations (stated as-is)

1. **showroom's existing protocol-layer inventory was not provided with the task** (the task
   said "see the inventory below" but it was missing), so this report cannot assess the concrete
   compatibility of "direct reuse"; §4.4's recommendation assumes "the encryption layer and the
   multiplexing layer are decoupled".
2. **Apple's official docs could not be fetched** (developer.apple.com is JS-rendered; WebFetch/
   fetchers got only empty shells/404); the iOS facts rest on the official repository docs of
   the four upstream projects tun/tun-rs/tappers/boringtun; Apple's own text is not directly
   cited.
3. **The ChmlFrp platform itself was not verified** (free quotas, long-connection tolerance,
   xtcp/tcpmux support, bandwidth and stability); frp capabilities are all cited from frp
   upstream [S20].
4. **NetBird Signal's clustering protocol** (whether it internally uses memberlist gossip) has
   no statement in its official docs; this report makes no such claim.
5. **Rust gossip/SWIM library selection was not completed** (memberlist is a Go library [S36];
   Rust counterparts like `chitchat`/`swim` were not each vetted for activity).
6. **Docker Desktop's Hyper-V / Docker VMM backend kernel `CONFIG_TUN` is unverified** (only
   the default WSL2 backend was verified).
7. **The TCP-over-TCP classic reference's original site is unreachable** (Titz 2001; its
   existence and phrasing corroborated via an arXiv paper's references [S28]); its mechanism
   description is labeled as engineering analysis in this report.
8. WireGuard's commonly cited 1420 MTU figure was not source-verified this time; the report
   does not use it.

---

## Source list (all accessed and verified 2026-10-31)

| # | Source | URL |
| --- | --- | --- |
| S1 | the Wintun official site (Layer 3 TUN driver, 0.14.1 signed DLL) | https://www.wintun.net/ |
| S2 | Linux kernel official docs: Universal TUN/TAP device driver | https://docs.kernel.org/networking/tuntap.html |
| S3 | Android official API reference: VpnService | https://developer.android.com/reference/android/net/VpnService |
| S4 | the tun crate upstream repo (meh/rust-tun; README platform notes and the iOS example) | https://github.com/meh/rust-tun |
| S5 | the tun-rs upstream repo (platform matrix, offload/multi-queue benchmarks, iOS/Android access examples) | https://github.com/tun-rs/tun-rs |
| S6 | the tappers upstream repo (utun/feth/Windows driver/mobile-limit notes, comparison table) | https://github.com/pkts-rs/tappers |
| S7 | the official crates.io API (tun-rs 2.8.16@2026-10-29, tun 0.8.14@2026-07-21, tun2 4.0.0@2024-10-27, etc. metadata) | https://crates.io/api/v1/crates/tun-rs etc. |
| S8 | the wintun crate upstream repo (Rust bindings, ring-buffer session, no-async note) | https://github.com/nulldotblack/wintun |
| S9 | the boringtun upstream repo (Cloudflare userspace WireGuard; platform table, utun notes) | https://github.com/cloudflare/boringtun |
| S10 | the rust-netlink org repo (archived notice) | https://github.com/rust-netlink/netlink |
| S11 | crates.io API: rtnetlink (0.23.0@2026-08-18, 28.8M downloads) | https://crates.io/api/v1/crates/rtnetlink |
| S12 | Docker's official run reference (the docker/cli source file vendored in docker/docs; --cap-add/--device/NET_ADMIN definitions) | https://docs.docker.com/reference/cli/docker/container/run/ (source: _vendor/github.com/docker/cli/docs/reference/run.md) |
| S13 | Docker official docs: Install Docker Desktop on Windows (three backends, WSL 2 default) | https://docs.docker.com/desktop/setup/install/windows-install/ |
| S14 | gluetun upstream discussion #534 (tun availability under Docker Desktop WSL2; maintainer confirmation) | https://github.com/passteque/gluetun/discussions/534 |
| S15 | the innernet upstream repo (coordination server, invite redemption with fresh keypairs, IPs never reused only disabled, RPF advice) | https://github.com/tonarino/innernet |
| S16 | the NetBird upstream repo (feature matrix, internals: ICE/STUN/Signal/Relay fallback, Rosenpass) | https://github.com/netbirdio/netbird |
| S17 | NetBird official docs: How NetBird Works (Management duties, 100.64.0.0/10 random /16, immediate address release, Signal/Relay details) | https://docs.netbird.io/about-netbird/how-netbird-works |
| S18 | Tailscale's official blog: How Tailscale works (WireGuard data plane, coordination server, DERP cannot decrypt, node-level ACLs, audit logs) | https://tailscale.com/blog/how-tailscale-works |
| S19 | ZeroTier's official protocol docs (VL1/VL2, planet/moon roots, rendezvous, Salsa20/Poly1305 without forward secrecy, controller CA, CoM/revocation/ownership certificates) | https://docs.zerotier.com/protocol/ |
| S20 | the frp upstream repo (TCP proxy usage, encryption/compression off by default, TLS on by default, heartbeat auth extension, tcpmux/xtcp) | https://github.com/fatedier/frp |
| S21 | NetBird official docs: Splitting Your Self-Hosted Deployment (SQLite→PostgreSQL, Management/Signal HA as commercial features, Relay splitting, clients tolerate Management downtime) | https://docs.netbird.io/selfhosted/maintenance/scaling/scaling-your-self-hosted-deployment |
| S22 | Tailscale official docs: How Tailscale assigns IP addresses (stable 100.x.y.z IPs, fd7a:115c:a1e0::/48) | https://tailscale.com/docs/concepts/ip-and-dns-addresses |
| S23 | Tailscale official docs: Reserved IP addresses (CGNAT RFC 6598, reserved subnets, CGNAT conflicts, cloned-disk same IP) | https://tailscale.com/docs/reference/reserved-ip-addresses |
| S24 | Tailscale official docs: Troubleshoot TCP connection issues (MTU 1280, silent drops, MSS clamping) | https://tailscale.com/docs/reference/troubleshooting/network-configuration/tcp-connection-two-devices |
| S25 | ZeroTier official docs: Central API Examples (default MTU 2800, adjustable to 9000 with silent-drop risk) | https://docs.zerotier.com/api-central-examples/ |
| S26 | RFC 8200 (IPv6; configurable-MTU links ≥1280 octets) | https://www.rfc-editor.org/rfc/rfc8200.txt |
| S27 | RFC 6598 (IANA-reserved IPv4 shared address space /10 for CGN) | https://www.rfc-editor.org/rfc/rfc6598.txt |
| S28 | arXiv 2504.19069 (OpenVPN performance analysis; its reference [12] is O. Titz, "Why TCP over TCP is a bad idea", 2001) | https://arxiv.org/html/2504.19069v1 |
| S29 | the hashicorp/yamux upstream repo (relies on reliable ordered connections; bidirectional streams/flow control/keepalive; spec.md) | https://github.com/hashicorp/yamux |
| S30 | the libp2p/rust-yamux upstream repo + crates.io (0.14.1@2026-09-21, implementing the official spec) | https://github.com/libp2p/rust-yamux |
| S31 | crates.io API: h2 (0.4.20@2026-10-06) | https://crates.io/api/v1/crates/h2 |
| S32 | RFC 9113 (HTTP/2; "TCP head-of-line blocking is not addressed by this protocol") | https://www.rfc-editor.org/rfc/rfc9113.txt |
| S33 | RFC 9000 (QUIC: A UDP-Based Multiplexed and Secure Transport) | https://www.rfc-editor.org/rfc/rfc9000.txt |
| S34 | the quinn upstream repo (pure-Rust QUIC; endpoint = a single UDP socket; quinn-proto I/O-free for custom event loops) | https://github.com/quinn-rs/quinn |
| S35 | the openraft upstream repo + crates.io (0.9.25 stable / 0.10.0-alpha.37; linearizable reads, snapshots, dynamic membership, chaos tests; in production at Databend) | https://github.com/databendlabs/openraft |
| S36 | the hashicorp/memberlist upstream repo (SWIM+Lifeguard; eventually consistent membership and failure detection) | https://github.com/hashicorp/memberlist |

### Verification commands actually executed this session (for review)

- `curl -s https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/master/Microsoft/config-wsl | grep -E "^CONFIG_TUN"` → output `CONFIG_TUN=y` (TUN built into the official WSL2 kernel).
- `curl -s https://www.rfc-editor.org/rfc/rfc8200.txt | grep …"1280 octets"` → hits line 1385,
  "must be configured to have an MTU of at least 1280 octets".
- `curl -s https://www.rfc-editor.org/rfc/rfc9113.txt | grep …head-of-line` → hits "TCP
  head-of-line blocking is not addressed by this protocol".
- `curl -sL https://tailscale.com/docs/reference/troubleshooting/network-configuration/tcp-connection-two-devices | …`
  → hits "uses a maximum transmission unit (MTU) of 1280…might get dropped silently…use MSS
  clamping" in the page data.
- `curl -s https://raw.githubusercontent.com/docker/docs/main/_vendor/github.com/docker/cli/docs/reference/run.md`
  (path located via the GitHub tree API) → extracted the "Runtime privilege and Linux
  capabilities" section and the `--cap-add`/`--device`/`NET_ADMIN` definitions.
- crates.io official API fetches (tun-rs/tun/tun2/rtnetlink/wintun/openraft/yamux/h2) to verify
  versions and update dates (annotated at the citation points).
