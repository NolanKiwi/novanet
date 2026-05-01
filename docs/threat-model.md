# NovaNet Threat Model

Version: 0.1-draft

---

## 1. Scope

This document defines the threat model for NovaNet's Phase 1–4 implementation: a userspace
transport protocol over UDP. Later phases (TUN/TAP, kernel module) will extend this model.

All referenced attacks are defined in the context of **authorized lab networks only**. This
document is a defensive specification document, not an offensive capability description.

---

## 2. Assets to Protect

| Asset | Description | Priority |
|---|---|---|
| Session confidentiality | Application data must not be readable by third parties | Critical |
| Session integrity | Application data must not be modifiable in transit | Critical |
| Session authenticity | Endpoints must be able to verify each other's identity | High |
| Session availability | DoS resistance within implementation resources | High |
| Session continuity | Sessions should survive network changes (mobility) | Medium |
| Metadata privacy | Minimize information visible to passive observers | Medium |
| Forward secrecy | Compromise of long-term keys should not reveal past traffic | High |
| Implementation safety | Bugs must not cause crashes, RCE, or memory corruption | Critical |

---

## 3. Attacker Model

### 3.1 Network Attacker (On-Path)

Can: intercept, read, delay, reorder, duplicate, drop, or inject packets on a network path.

Cannot (without cryptographic keys): forge authenticated NovaNet packets.

**Example**: A malicious router on the path between client and server.

### 3.2 Network Attacker (Off-Path)

Can: send packets with spoofed source addresses. Cannot see the victim's traffic.

**Example**: An attacker attempting blind RST injection or amplification.

### 3.3 Active Server Attacker

Can: control a server that the client connects to. Can observe all protocol messages after the
handshake. Cannot retroactively decrypt past sessions with different long-term keys.

**Example**: A compromised server endpoint.

### 3.4 Active Client Attacker

Can: control a client. Can observe all protocol messages sent to that client.

### 3.5 Passive Observer

Can: observe all packets on a network segment but cannot modify or inject.

**Example**: Passive wiretap, traffic analysis.

---

## 4. Threats and Mitigations

### 4.1 Spoofed Source Packets

**Threat**: An off-path attacker sends packets with a spoofed source IP claiming to be a
legitimate endpoint.

**Attack**: Inject DATA or ACK packets to corrupt stream state; trigger RST-equivalent.

**Mitigation**:
- All DATA/ACK/CLOSE packets are AEAD-authenticated. A spoofed packet fails authentication
  (wrong key → garbage ciphertext → auth tag mismatch).
- The server ignores any DATA packet that fails auth tag verification.
- SessionID alone is not sufficient to inject data; the sender must also have the write key.

**Residual risk**: An attacker who has captured a SessionID can send unauthenticated HELLO
packets to probe for session existence. Mitigated by rate-limiting HELLO processing per
source IP.

---

### 4.2 Replay Attacks

**Threat**: An attacker records a valid packet and retransmits it later.

**Attack**: Replay a DATA packet to cause duplicate delivery or a KEY_UPDATE to cause key
confusion.

**Mitigation**:
- Every packet carries a monotonically increasing PacketNumber per (session, path).
- The receiver tracks the largest received PacketNumber and a sliding window of seen packets.
- Packets with a PacketNumber below `largest_received - window_size` are dropped.
- Packets with a PacketNumber within the window but already received are dropped.
- Replay detection window: 2^31 packets (configurable).

**Implementation note**: The replay window must be implemented as a bitmap, not just tracking
the max, to handle out-of-order delivery without false replay detection.

---

### 4.3 Downgrade Attacks

**Threat**: An attacker modifies the version field or capability negotiation to force use of
a weaker protocol version or disabled feature.

**Attack**: Strip encryption or force use of a weak cipher.

**Mitigation**:
- The Version field is part of the AEAD AAD. Modifying it causes authentication failure.
- Capability negotiation bytes are included in the signed handshake transcript.
- Downgrade to "no encryption" mode does not exist in the protocol; there is no plaintext mode.

---

### 4.4 Amplification Attacks

**Threat**: An attacker sends a small HELLO packet with a spoofed source IP (the victim's
address). The server sends a large response to the victim.

**Attack**: Use NovaNet servers as reflectors to amplify traffic toward victims.

**Mitigation**:
- Before address validation, the server's total response is capped at **3x** the bytes received
  from the client (ANTI_AMPL_FACTOR = 3).
- The server issues a RETRY packet (smaller than the HELLO response) to validate the client's
  address before completing the handshake.
- After receiving a HANDSHAKE packet from the validated address, amplification limits are lifted.
- RETRY tokens are server-signed (integrity-protected) and expire after RETRY_TOKEN_LIFETIME.

**Worst-case**: A HELLO packet of 1200 bytes could cause a 3600-byte response. This is still
less than UDP-based DNS amplification factors (10–100x). The RETRY mechanism reduces this further.

---

### 4.5 State Exhaustion (Server)

**Threat**: An attacker sends many HELLO packets to exhaust the server's session table.

**Attack**: Fill memory with half-open sessions.

**Mitigation**:
- The RETRY mechanism is **stateless**: before committing session state, the server sends a
  RETRY packet. No server state is stored for unvalidated sessions.
- After address validation, sessions are admitted to the session table subject to a configurable
  per-IP and global session limit.
- Session limits are enforced with early rejection and a rate limiter per source IP.
- Half-open handshake sessions are garbage-collected after HANDSHAKE_TIMEOUT (10 seconds).

---

### 4.6 Malformed Packet Parser Attacks

**Threat**: A crafted packet triggers a buffer overflow, integer overflow, panic, or undefined
behavior in the packet parser.

**Attack**: Remote code execution or crash via malformed packets.

**Mitigation**:
- **No unsafe code** in `novanet-wire` (the packet parsing crate).
- All length fields are validated against the remaining buffer length before accessing data.
- Integer arithmetic uses checked arithmetic (no `as` casts that could truncate).
- The parser is a primary target for **cargo-fuzz** continuous fuzzing.
- The implementation uses `bytes::Bytes` with bounds-checked access; panics from out-of-bounds
  accesses are impossible with the `bytes` API.

**Verification**: See `/fuzz/packet_decode_fuzz.rs` for fuzz targets.

---

### 4.7 Identity Theft / Impersonation

**Threat**: An attacker impersonates a server (or client) to intercept or modify traffic.

**Attack**: Man-in-the-middle: intercept HELLO, forward modified HANDSHAKE with attacker keys.

**Mitigation**:
- Server authentication: the server signs its ephemeral public key with its long-term Ed25519
  private key. The client verifies the signature against a known or configured server NodeID.
- Client authentication: the client signs its ephemeral public key with its long-term private key.
  The server verifies against a known or configured client NodeID.
- Key pinning: clients can pin a server's NodeID (analogous to SSH known_hosts or TLS cert
  pinning) to prevent substitution attacks.
- Certificate transparency (Phase 5+): NodeID registrations can be logged in an append-only
  ledger within a trust domain.

**Residual risk**: First connection to an unknown server cannot be authenticated without a
pre-established trust anchor. This is the same problem as SSH's "Trust On First Use" (TOFU).

---

### 4.8 Long-Term Key Compromise

**Threat**: An attacker obtains a node's long-term Ed25519 private key.

**Attack**: Impersonate the compromised node; potentially decrypt recorded past traffic.

**Mitigation**:
- **Forward secrecy**: session keys are derived from ephemeral X25519 key pairs. Long-term keys
  are used only for authentication (signature), not for session key derivation. Compromising the
  long-term key does not reveal past session traffic.
- **Key rotation**: long-term keys should be rotated periodically. A revocation mechanism is
  described in docs/security-model.md (Phase 5).
- **Key isolation**: long-term private keys should be stored in hardware security modules (HSMs)
  or platform secure enclaves in production deployments (Phase 6+).

---

### 4.9 NAT Rebinding Abuse

**Threat**: A NAT device changes the port mapping for an existing session, causing the server
to see packets from the same SessionID but a new source port.

**Attack**: An attacker shares a NAT and tries to "steal" a session by sending packets that
arrive from the NAT's port mapping.

**Mitigation**:
- When the server sees a packet from a new source address for an existing SessionID, it does
  **not** immediately migrate the session. Instead, it sends a PATH_CHALLENGE on both the old
  and new paths.
- Only after receiving a valid PATH_RESPONSE on the new path does the server update the active
  path. The attacker cannot forge a PATH_RESPONSE without the session write key.
- The migration timer: PATH_CHALLENGE must be responded to within PATH_CHALLENGE_TIMEOUT (3s).

---

### 4.10 Path Hijacking

**Threat**: An on-path attacker redirects session traffic to a different destination.

**Attack**: Modify the source address in UDP headers to redirect PATH_RESPONSE to themselves.

**Mitigation**:
- PATH_CHALLENGE data (8 random bytes) is generated per-challenge and included in the session
  state. A valid PATH_RESPONSE must contain the same 8 bytes.
- Generating a valid PATH_RESPONSE requires the session write key (AEAD authentication). An
  attacker without the key cannot forge a valid PATH_RESPONSE.
- Path migration only completes after cryptographic proof of reachability.

---

### 4.11 Metadata Leakage

**Threat**: A passive observer learns information about who is communicating and when.

**Visible**: SessionID, packet sizes, timing, source/destination IP:port.

**Not visible**: NodeID, ServiceID, stream counts, payload contents.

**Mitigation**:
- PADDING frames can be added to equalize packet sizes.
- SessionID rotation (Phase 4+) limits long-term linkability.
- Traffic shaping is an application-level concern; the protocol enables but does not enforce it.

---

### 4.12 Traffic Analysis

**Threat**: Even with encryption, an observer can learn facts from packet timing, sizes, and
frequencies.

**Mitigation**: Traffic analysis resistance is a research-level goal (Phase 9+). Phase 1–4 make
no claims about traffic analysis resistance beyond what QUIC provides.

---

### 4.13 Congestion Control Abuse

**Threat**: A misbehaving peer sends ACKs faster than real RTT would allow (ACK stuffing) to
trick the sender into increasing its congestion window aggressively, causing network harm.

**Mitigation**:
- ACK packets are AEAD-authenticated. Only the legitimate peer can send valid ACKs.
- RTT validation: the congestion controller checks that RTT samples are plausible relative to
  observed packet timestamps.
- Send rate is capped by the congestion window regardless of ACK rate.

---

### 4.14 Resource Exhaustion (Streams)

**Threat**: A peer opens 2^31 streams, exhausting memory.

**Mitigation**:
- The implementation enforces `max_concurrent_streams` (configurable, default 100).
- Streams beyond the limit cause a STREAM_LIMIT_EXCEEDED error.
- Stream credits (like QUIC's `max_streams` transport parameter) are negotiated in the handshake.

---

## 5. Implementation Safety Requirements

These are non-negotiable for the implementation, derived from the threat model:

1. **No unsafe code** in packet parsing crates.
2. **Checked arithmetic** for all length and offset calculations.
3. **Input validation** at all decode boundaries before any allocation or buffer access.
4. **Fuzz testing** for all packet decoders with cargo-fuzz.
5. **Property-based tests** for handshake state machine invariants.
6. **Rate limiting** for HELLO/RETRY processing before session admission.
7. **Timeout enforcement** for all state machine transitions.
8. **No secret-dependent branches** in AEAD verification (constant-time comparison via the
   `ring` crate's verified implementation).
9. **Log scrubbing**: Session keys must never appear in log output.
10. **Entropy requirement**: SessionIDs, challenge nonces, and ephemeral keys must be generated
    from a cryptographically secure PRNG (`ring::rand::SystemRandom`).

---

## 6. Out of Scope (Phase 1)

The following are acknowledged but deferred:

- **BGP/routing hijacking**: Requires global routing infrastructure; not addressable at the
  transport layer.
- **Physical layer attacks**: Side-channel attacks on crypto, power analysis, etc. Out of scope
  for a software prototype.
- **Client device compromise**: If the client OS is compromised, all bets are off. This is
  an OS security problem.
- **Tor-level anonymity**: NovaNet does not attempt to hide communication patterns at the
  network level. Applications requiring anonymity should layer NovaNet under an anonymity system.
- **Quantum resistance**: Post-quantum key exchange (e.g., ML-KEM/Kyber) is a Phase 7+ goal.
  For now, X25519 provides adequate security against classical adversaries.
