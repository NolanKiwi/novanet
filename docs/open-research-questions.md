# NovaNet Open Research Questions

Version: 0.1-draft

These are questions that the NovaNet research program does not yet answer. Each is a potential
direction for future work, ranging from practical implementation decisions to deep research problems.

---

## 1. Protocol Design Questions

### 1.1 SessionID Rotation
**Question**: When should SessionIDs be rotated to prevent long-term linkability?
**Tension**: Rotating too frequently breaks in-flight packets. Too infrequently enables tracking.
**Known approach**: QUIC has Connection Migration with new Connection IDs; NovaNet can do similar.
**Open**: What is the right rotation policy? Should it be application-triggered or automatic?

### 1.2 Zero-RTT Replay Safety
**Question**: How do we bound 0-RTT replay risk without a large server-side bloom filter?
**Tension**: A bloom filter large enough to cover all possible replays is expensive. Time-bounded
tokens reduce this but require clock synchronization.
**Reference**: QUIC's 0-RTT anti-replay uses an anti-replay window; same tradeoffs apply.

### 1.3 Service-Level Addressing
**Question**: How should ServiceIDs be resolved to NodeIDs (and thus to IP addresses)?
**Options**: DNS TXT records, DHT, centralized directory, certificate transparency log.
**Tension**: Decentralized resolution is more resilient but harder to revoke.
**Phase**: 5+.

### 1.4 Capability Token Design
**Question**: What should capability tokens look like? How are they authorized and revoked?
**Reference**: SPIFFE/SPIRE, Macaroons, UCAN, zcap-ld.
**Tension**: Fine-grained capability tokens add protocol complexity; coarse tokens are less useful.

### 1.5 Multipath Bandwidth Aggregation Safety
**Question**: Is it safe to send the same application data over two paths with different exit IPs?
**Problem**: If the two paths share a bottleneck, aggregating causes congestion collapse.
**Known approach**: Coupled congestion control (MPTCP's LIA algorithm). Is LIA applicable here?

### 1.6 Optimal ACK Delay
**Question**: What is the optimal ACK delay for NovaNet's 1200-byte packet limit?
**Tension**: Larger ACK delay allows coalescing (fewer ACK packets) but inflates RTT estimates.
**TCP**: ACK delay is 40ms. QUIC: 25ms. What is right for NovaNet's use cases?

### 1.7 Flow Control Interaction with Multipath
**Question**: Should flow control windows be per-path or per-session?
**Per-session**: Simpler. But blocks path 0 if path 1 is fast (unfair).
**Per-path**: Correct but complex; requires scheduler awareness.

---

## 2. Security Research Questions

### 2.1 Traffic Analysis Resistance
**Question**: Can NovaNet provide meaningful traffic analysis resistance without Tor-like onion routing?
**Known approaches**: Constant-rate padding, shape-oblivious padding (QUIC's PADDING frames).
**Open**: Is session-level shape normalization sufficient for most threat models?

### 2.2 Post-Quantum Transition
**Question**: How to add ML-KEM (Kyber) without breaking backward compatibility?
**Reference**: TLS 1.3 hybrid key exchange (X25519+Kyber draft).
**Approach**: Add Kyber ephemeral key to HELLO alongside X25519; both must succeed.
**Phase**: 7+.

### 2.3 Amplification Factor Analysis
**Question**: What is the worst-case amplification factor for a NovaNet server?
**Current spec**: 3× per HELLO. But what about HANDSHAKE responses?
**Open**: Should HANDSHAKE responses also be bounded? What is the server → client ratio for a full handshake?

### 2.4 Replay Window Size
**Question**: What replay window size is sufficient?
**Current spec**: 2048 packets. Is this enough for multipath with significant RTT differential?
**Problem**: Path 0 (5ms) and Path 1 (200ms) may have 39ms × throughput worth of reorder distance.
**Open**: Should the replay window be per-path, and if so, how are duplicates detected across paths?

### 2.5 Side-Channel Resistance of Packet Number Exposure
**Question**: Does exposing packet numbers in plaintext enable traffic analysis attacks beyond what IP timing already enables?
**Known**: QUIC exposes packet numbers too. DTLS does not.
**Open**: Is this a real threat for NovaNet's target deployment environments?

---

## 3. Congestion Control Research Questions

### 3.1 Fairness with CUBIC and BBR
**Question**: What is the steady-state bandwidth ratio of NovaNet AIMD vs. TCP CUBIC and TCP BBR on a shared bottleneck?
**Known**: AIMD is TCP-fair by construction. But CUBIC beats AIMD on HBH paths. Does NovaNet AIMD starve when CUBIC flows are present?
**Experiment needed**: Section 3.8 of benchmark-plan.md.

### 3.2 ECN Support
**Question**: Should NovaNet support ECN (Explicit Congestion Notification)?
**ECN**: Routers mark packets instead of dropping them; reduces induced loss significantly.
**Challenge**: ECN bits are in the IP header; NovaNet over UDP can use IP ECN bits but must map them to session-level signals.
**Reference**: QUIC has ECN support (RFC 9000 §13.4).

### 3.3 Congestion Control for Datagrams
**Question**: Should UnreliableDatagram frames be subject to congestion control?
**Arguments for**: Sending unlimited datagrams could saturate the link.
**Arguments against**: Application already limits datagram rate; congestion control adds latency.
**Current spec**: Datagrams bypass stream flow control but not congestion window.
**Open**: Is the congestion window the right place to rate-limit datagrams?

### 3.4 Multipath Congestion Control Coupling
**Question**: Should per-path congestion controllers be entirely independent, or should they share information?
**Independent**: Simple; but a flow may over-subscribe the bottleneck if multiple paths share it.
**Coupled**: MPTCP's coupled CC; correct but complex.
**Open**: Is coupling necessary for NovaNet's primary use cases?

---

## 4. Performance Research Questions

### 4.1 Zero-Copy Packet Processing
**Question**: Can NovaNet achieve zero-copy data transfer from application buffer to NIC?
**Current state**: `bytes::Bytes` provides reference-counted zero-copy between layers. The final `sendmsg()` still copies.
**Approach**: `io_uring` with registered buffers allows kernel-to-userspace zero-copy.
**Phase**: 8+ (io_uring integration).

### 4.2 Session Table Scalability
**Question**: What is the maximum number of concurrent sessions a single process can handle?
**Bottleneck**: HashMap lookup per packet is O(1) but has cache locality issues at 100K+ sessions.
**Approach**: Cuckoo hashing, SIMD-accelerated hash tables, or partitioned session tables.
**Open**: What is the practical limit for the research prototype?

### 4.3 Batching
**Question**: How much benefit does packet batching provide?
**`recvmmsg`**: Receive multiple UDP packets in one syscall.
**`sendmmsg`**: Send multiple UDP packets in one syscall.
**`io_uring`**: Submit and complete multiple I/O operations without context switches.
**Open**: At what throughput does batching become necessary?

### 4.4 Crypto Overhead
**Question**: What fraction of CPU time is AEAD encryption/decryption for NovaNet?
**Reference**: For QUIC, AES-GCM with AES-NI is ~1–2% CPU at 1 Gbps. ChaCha20 is ~3–5% without hardware.
**Open**: Is ChaCha20-Poly1305 fast enough for the target throughput in Phase 1?

---

## 5. Deployment Research Questions

### 5.1 Middlebox Compatibility
**Question**: Which middleboxes will interfere with NovaNet?
**Known**: NovaNet over UDP port 443 should have similar middlebox compatibility as QUIC.
**Unknown**: Deep packet inspection that blocks non-QUIC UDP on port 443.
**Experiment**: Test NovaNet through common corporate firewalls and NATs.

### 5.2 IPv6 Support
**Question**: Does NovaNet work correctly over IPv6?
**Expected**: Yes — the IP addressing layer is opaque to NovaNet.
**Detail**: IPv6 minimum MTU is 1280 bytes; NovaNet's 1200-byte limit is safe.
**Open**: Is there a benefit to detecting IPv6 and using a larger MTU?

### 5.3 PMTUD (Path MTU Discovery)
**Question**: Should NovaNet implement proactive Path MTU Discovery?
**Current spec**: Fixed 1200-byte limit (conservative).
**Benefit**: Larger packets (up to ~8900 bytes on Ethernet) = less header overhead.
**Risk**: ICMP Fragmentation Needed messages may be blocked; PMTUD blackholes.
**Reference**: QUIC performs PMTUD (RFC 8899).

### 5.4 NAT Traversal for New Paths
**Question**: How do new multipath paths work when both endpoints are behind NAT?
**Problem**: Path 1's local address (10.0.2.8:22222) is not reachable from the server.
**Solution**: STUN-like hole punching via a rendezvous server.
**Open**: Is a built-in STUN mechanism warranted, or should this be an application concern?

---

## 6. Formalization Questions

### 6.1 Handshake State Machine Correctness
**Question**: Can the NovaNet handshake be formally verified to be free of authentication bypasses?
**Tools**: TLA+, ProVerif, Tamarin Prover.
**Reference**: QUIC's TLS 1.3 integration has been analyzed with ProVerif.
**Phase**: 9+.

### 6.2 Congestion Control Liveness
**Question**: Does the congestion controller always make progress, or can it deadlock?
**Potential issue**: If cwnd falls to MIN_CWND and RTO fires continuously, does the session ever recover?
**Phase**: 5 (property-based tests should cover this).

### 6.3 Multipath Migration Correctness
**Question**: Can the path migration state machine reach an inconsistent state where both endpoints disagree on the active path?
**Phase**: 6 (invariant tests in proptest).

---

## 7. Comparison Research Questions

### 7.1 vs. MPTCP
**Question**: For multipath TCP workloads, is NovaNet better or worse than MPTCP?
**Known**: MPTCP has OS support (Linux 5.6+) and thus kernel-level performance. NovaNet is userspace.
**Open**: Is NovaNet's simpler design (no subflow concept, session-level CC) sufficient?

### 7.2 vs. SCTP
**Question**: SCTP already has multi-homing and multiple delivery modes. Why not extend SCTP?
**Answer**: SCTP is blocked by most firewalls and NATs (no SCTP support in NAT firmware). It requires kernel support. NovaNet is userspace over UDP.
**Open**: Is SCTP's multi-homing the right model for NovaNet's multipath, or is QUIC's path migration model better?

### 7.3 vs. WebTransport
**Question**: For browser-based deployments, is NovaNet better than WebTransport (QUIC over HTTP/3)?
**Known**: WebTransport is already deployed and browser-native. NovaNet requires WASM.
**Open**: What does NovaNet offer that WebTransport does not, for browser use cases?
