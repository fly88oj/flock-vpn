# Security policy (SECURITY)

Scope: this repository's (fly88oj/flock-vpn) flock-server / flock-client / flock-frpc /
flock-sync and the deploy/ deployment assets. The cryptographic protocol proper
(kem/envelope/sig/pake/session/mux/compress/trust/roster) lives in the standalone repository
[fly88oj/flock-protocol](https://github.com/fly88oj/flock-protocol) — please report protocol-layer
vulnerabilities there.

## Reporting channels

**GitHub Private Vulnerability Reporting**:

1. Open <https://github.com/fly88oj/flock-vpn/security/advisories>
2. "Report a vulnerability" → fill in reproduction steps / impact / suggested fix

Or enter via the repository's Security tab. Please **do not** open public issues/PRs/discussions
for unpatched vulnerabilities. Response targets: acknowledgment within 72 hours; the fix window
assessed by severity; public credit after the fix (unless you request anonymity).

## Supported versions

| Version | Status |
|---|---|
| main (0.1.x development line) | supported |
| old tags | unsupported |

## Threat-boundary summary

The full discussion is in
[docs/design.md §2.5](docs/design.md#25-threat-model-boundaries-explicit-statement-to-prevent-security-claims-from-being-misread-as-peer-level-e2e).
Please check against it before reporting — the following four are **declared, accepted
boundaries** and do not count as vulnerabilities:

1. **Cross-peer traffic is plaintext on the access server**: the first version is hub-and-spoke;
   client-to-client traffic is decrypted and then forwarded on the access server; any enrolled
   server can observe/tamper with the cross-peer traffic it forwards (fundamentally different
   from Tailscale's "the coordination server cannot decrypt"). Peer-to-peer end-to-end overlay
   encryption is on the roadmap.
2. **Any server can offline-dictionary all passwords**: compromising any enrolled server yields
   the OPRF key, enabling offline dictionary attacks on all user passwords (inherent in the
   OPAQUE aPAKE model; argon2id is the only speed bump). OPRF key thresholding is on the roadmap.
3. **TOFU does not defend against an online MITM on first login**: a residual risk in
   first-connection trust establishment; organizational deployments enforce the invite file.
4. **Relay and link observers**: FRP relay/link observers see only ciphertext and lengths (the
   length side-channel countermeasure = the compression tiers); the ChmlFrp panel
   credential-channel risk is in design §5.

The link form (Direct connection / FRP relay) is fully isomorphic to the protocol layer: any
third party on any link sees only this protocol's ciphertext. Breakage beyond the boundaries
above (forged sessions, cross-device decryption, successful replays, online password
dictionaries) is within the scope of this policy.
