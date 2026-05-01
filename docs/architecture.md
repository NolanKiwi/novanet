# NovaNet Architecture

## 1. Design Philosophy

TCP/IP is to networking what C is to systems programming: universal, fast, low-level, flexible, and
foundational — but unsafe or incomplete in several modern contexts.

Rust's answer to C was not to discard performance and control. It preserved them while adding
memory safety, concurrency safety, and a richer type system that encodes correctness constraints.

NovaNet applies the same philosophy to TCP/IP:

- Preserve what TCP/IP does well: universal deployability, performance under tuning, low-level
  transparency, debuggability.
- Fix what is structurally broken: address/identity conflation, no native security, poor mobility,
  no built-in observability, ossified evolution path.

This is not a fantasy protocol. It is an experimental research stack with a realistic starting
point: userspace, UDP-based, implemented in safe Rust.

---

## 2. Problems with TCP/IP

### 2.1 IP Layer

| Problem | Description |
|---|---|
| Address = identity | IP addresses are used as both location and identity. Mobility breaks sessions. |
| No native authentication | Any packet can claim any source address (spoofing). |
| NAT complexity | NAT breaks end-to-end semantics, requires STUN/TURN workarounds. |
| Tight routing/addressing coupling | Changing address = losing session. |
| No native multipath | ECMP is opaque; MPTCP is optional and complex. |
| Limited observability | RTT, loss, and path quality are not protocol-visible. |
| Security is external | TLS, IPsec, and DTLS are all retrofitted layers. |

### 2.2 TCP

| Problem | Description |
|---|---|
| Head-of-line blocking | A single lost packet blocks all streams. |
| 4-tuple state | Connection identity = (src IP, src port, dst IP, dst port). Network change = reset. |
| No encryption | TLS handshake must follow TCP handshake: 1.5–2 RTT to first byte. |
| No stream multiplexing | One TCP connection = one byte stream. |
| Middlebox ossification | Middleboxes enforce TCP behavior; new semantics cannot be deployed. |
| Kernel-only | TCP is in the kernel stack; evolution requires kernel patches and OS updates. |
| No priority | All bytes are equal; control messages compete with data. |

### 2.3 What QUIC Already Solved

QUIC (RFC 9000) is the most important recent advance in transport protocols. It should be treated
as a predecessor and baseline.

| Feature | QUIC solution |
|---|---|
| Encryption by default | All QUIC traffic is encrypted (TLS 1.3 built in) |
| Userspace deployment | Runs over UDP; no kernel changes needed |
| Connection IDs | Sessions survive IP/port changes (partial mobility) |
| Stream multiplexing | Multiple streams, no head-of-line blocking across streams |
| Faster handshakes | 1-RTT, optional 0-RTT |
| Better mobility than TCP | Connection ID allows path migration |
| Anti-amplification | Validated before sending large responses |

### 2.4 What NovaNet Explores Beyond QUIC

QUIC is still fundamentally a transport protocol using IP addresses for routing and DNS for naming.
It has no native identity model, no capability-based addressing, no built-in multipath, and limited
observability.

NovaNet's research questions beyond QUIC:

1. **Cryptographic session identity**: Session IDs derived from public keys, not IP 4-tuples.
2. **Service-level addressing**: Connect to a named service identity, resolved through a local trust
   domain, not just an IP:port.
3. **Multipath as a first-class primitive**: Not an extension. Path selection, path quality
   tracking, and per-path congestion state built into the core protocol.
4. **Native observability**: RTT, loss, throughput, congestion window, retransmission counts, and
   path quality are all visible at the protocol level and exportable as structured telemetry.
5. **Pluggable congestion control**: A Rust trait boundary so that AIMD, CUBIC, BBR, and
   datacenter-specific algorithms can be swapped without touching the core transport.
6. **Multiple delivery semantics in one session**: Reliable streams, reliable messages, unreliable
   datagrams, and priority control-plane messages within a single cryptographic session.
7. **Protocol-level capability tokens**: Authorization is carried in the protocol, not inferred
   from IP addresses or application-level tokens.
8. **Formal threat model**: Every feature is analyzed against a defined threat model; mitigations
   are part of the specification, not afterthoughts.

---

## 3. Layer Model

NovaNet does not follow the strict OSI/TCP-IP layering dogma. Instead:

```
┌─────────────────────────────────────────────────────────┐
│  Application (Rust library API, async streams/datagrams) │
├─────────────────────────────────────────────────────────┤
│  Session Layer (session identity, key state, migration)  │
├─────────────────────────────────────────────────────────┤
│  Transport Layer (streams, messages, datagrams, flow ctrl)│
├─────────────────────────────────────────────────────────┤
│  Reliability Layer (packet numbers, ACKs, retransmission)│
├─────────────────────────────────────────────────────────┤
│  Congestion Control (pluggable, per-path)                │
├─────────────────────────────────────────────────────────┤
│  Multipath Layer (path IDs, path probing, scheduling)    │
├─────────────────────────────────────────────────────────┤
│  Security Layer (key exchange, AEAD encryption, identity)│
├─────────────────────────────────────────────────────────┤
│  Wire Format (binary packet encoding/decoding)           │
├─────────────────────────────────────────────────────────┤
│  Network (UDP / TUN-TAP / raw socket / future kernel)    │
└─────────────────────────────────────────────────────────┘
```

Each layer has a well-defined Rust trait interface. The initial prototype collapses several layers
for simplicity, then re-separates them as the implementation matures.

---

## 4. Addressing and Identity Model

### 4.1 The Core Problem

In TCP/IP, an IP address does three things:
1. Identifies where a packet should be routed (locator).
2. Identifies who is sending the packet (source identity).
3. Identifies the session endpoint (connection state key).

These should be separate concepts. Conflating them causes mobility problems (1=3), spoofing
vulnerabilities (2=location), and session teardown on network change (3=1).

### 4.2 NovaNet Identity Hierarchy

```
NodeID      -- stable cryptographic identity of a node (public key hash)
DeviceID    -- a physical or virtual NIC (can have multiple per node)
ServiceID   -- a named service endpoint on a node
SessionID   -- a 128-bit random per-session identifier
PathID      -- identifies one (src_addr, dst_addr) pair within a session
```

**NodeID**: A 32-byte value derived from a long-term Ed25519 public key (SHA-256 hash of the
public key). Stable across reboots, network changes, and IP address changes.

**SessionID**: A 128-bit cryptographically random value chosen during the handshake. Used as the
primary key for all session state. Not derived from IP or port. Survives path migration.

**PathID**: An 8-bit identifier for a specific (local_addr, remote_addr) pair within a session.
Multiple PathIDs can be active simultaneously for multipath.

**ServiceID**: A 32-byte value naming a service. In Phase 1, this is just a label. In later
phases, it becomes a routing primitive within a trust domain.

### 4.3 Routing Compatibility

Since NovaNet runs over UDP in Phase 1, IP addresses are still used for routing. But they are
treated as opaque locators, not as identity or session keys. The NovaNet session survives a change
in IP address because the session is keyed by SessionID, not by the IP 4-tuple.

---

## 5. Crate Architecture

### `novanet-core`
Shared types: `SessionId`, `NodeId`, `ServiceId`, `PathId`, error types, constants, and the
delivery semantics enum. No I/O. No crypto. Pure data types and traits.

### `novanet-wire`
Binary packet encoding and decoding. Operates on `bytes::Bytes` and `bytes::BytesMut`. No crypto
(encryption/decryption happens before encoding or after decoding). Extensive unit tests. Primary
fuzzing target.

### `novanet-crypto`
Key generation, X25519 ECDH key exchange, Ed25519 signing/verification, ChaCha20-Poly1305 AEAD
encryption, HKDF key derivation. Uses `ring` or `chacha20poly1305` crate. No unsafe code.

### `novanet-transport`
UDP socket management, session table (HashMap<SessionId, SessionState>), I/O event loop using
`tokio`, send/receive queues, session creation and teardown. Coordinates all other crates.

### `novanet-congestion`
Pluggable congestion control behind a `CongestionController` trait. Phase 1 provides a simple
AIMD implementation. Phase 2 adds CUBIC-like and BBR-like controllers.

### `novanet-multipath`
Path tracking: `PathState` per PathID, path challenge/response, path quality metrics, packet
scheduler. Phase 6 feature.

### `novanet-observability`
Structured events emitted by the transport layer. In-process subscriber + Prometheus exporter +
optional pcap-compatible trace writer. Built on `tracing` crate.

### `novanet-cli`
Command-line tool: packet inspector, session status viewer, metrics exporter, manual packet
injection for testing.

### `novanet-sim`
Simulation utilities: `SimulatedLink` that adds configurable packet loss, delay, jitter, and
reordering. Used by integration tests and the loss-jitter-lab experiment.

---

## 6. Deployment Architecture

### Phase 1: Userspace Library + UDP

```
Client App  ---[NovaNet API]---  NovaNet Transport  ---[UDP socket]---  Linux IP Stack  ---  Network
Server App  ---[NovaNet API]---  NovaNet Transport  ---[UDP socket]---  Linux IP Stack  ---  Network
```

No kernel changes. No special privileges (unless port < 1024). Runs anywhere.

### Phase 2: TUN/TAP Overlay

```
App  ---[TUN interface]---  NovaNet Forwarding Daemon  ---[UDP encap]---  Network
```

Allows existing TCP/IP applications to use NovaNet as a transparent tunnel. Requires `CAP_NET_ADMIN`.

### Phase 3: eBPF/XDP Acceleration (Research)

Some packet processing (ACK generation, path quality measurement) can be offloaded to XDP programs
attached to NICs, reducing kernel-userspace crossing cost.

### Phase 4: Kernel Module (Research)

Full kernel integration would allow NovaNet sessions to be visible as file descriptors in the
standard socket API. Requires kernel module development, out of scope for Phase 1.

---

## 7. Wire Transport Choice

**Why UDP?**

- No kernel changes needed.
- Passes through most firewalls and NATs (QUIC proved this).
- Full control over packet framing.
- Middleboxes cannot interpret or modify NovaNet headers.
- Userspace implementation can evolve independently.
- Can implement custom reliability on top.

**Why not raw sockets?**

- Requires `CAP_NET_RAW` (root).
- Does not pass through NAT (no UDP/TCP header for NAT to translate).
- Not needed for Phase 1; TUN/TAP covers the overlay case better.

**Why not TCP as the carrier?**

- TCP head-of-line blocking would contaminate NovaNet's own reliability layer.
- QUIC already does this and it is a known trade-off.

---

## 8. Security Architecture

Security is not a layer. It is a property of the entire system.

### Non-negotiables
- All session data is encrypted with ChaCha20-Poly1305 (authenticated encryption).
- Session keys are derived from an X25519 Diffie-Hellman key exchange.
- Node identities are Ed25519 public keys.
- Replay protection: monotonically increasing packet numbers, tracked per-path.
- Forward secrecy: ephemeral keys per session (long-term keys only for authentication).
- Downgrade protection: version negotiation is covered by the authentication tag.

### Minimal Metadata Exposure
- The unencrypted header carries only: version, packet type, SessionID, PathID, and PacketNumber.
- Source and destination NodeIDs are encrypted (inside the handshake or data payload).
- Payload length is visible (unavoidable for UDP; padding is supported to obscure it).

---

## 9. Implementation Constraints

### Safe Rust Required
No `unsafe` code in the core protocol crates (`novanet-wire`, `novanet-core`, `novanet-crypto`,
`novanet-transport`). If `unsafe` becomes necessary (e.g., for zero-copy buffer management in a
future high-performance path), it must be isolated in a clearly marked module with a detailed
safety justification comment.

### No Invented Crypto
All cryptographic primitives come from vetted crates: `ring`, `chacha20poly1305`, `x25519-dalek`,
`ed25519-dalek`, `hkdf`, `sha2`. Never implement AEAD, key exchange, or signature schemes from
scratch.

### Fuzz-First Packet Parsing
`novanet-wire` must have cargo-fuzz targets before any integration code depends on it.

### Property-Based Tests
State machines (handshake, migration, reliability) must have `proptest` property tests that
verify invariants hold under arbitrary input sequences.

---

## 10. What Is Realistic vs. Research

| Capability | Realistic Now | Requires Infrastructure | Research Only |
|---|---|---|---|
| UDP overlay transport | Yes | - | - |
| Cryptographic session identity | Yes | - | - |
| Stream multiplexing | Yes | - | - |
| Native multipath (2 paths) | Yes (Phase 6) | - | - |
| Observability / Prometheus | Yes | - | - |
| TUN/TAP overlay | Yes | - | - |
| Service-level routing | Partial (local) | Trust domain infra | - |
| eBPF/XDP acceleration | Prototype | NIC/kernel version | - |
| Browser support | - | Browser vendors | - |
| OS kernel integration | - | OS vendors | Long-term |
| Router/BGP integration | - | ISP/router vendors | Long-term |
| NIC offload | - | NIC vendors | Long-term |
| Replacing global Internet IP | Never in this form | - | - |

The global Internet runs on entrenched infrastructure. NovaNet's value is in controlled
environments: CDNs, datacenters, service meshes, IoT networks, and mobile applications — the same
environments where QUIC first proved itself before browser adoption.
