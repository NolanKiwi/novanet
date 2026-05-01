# NovaNet Implementation Roadmap

---

## Phase 0 — Research and Design ✓ COMPLETE

**Goal**: Produce complete documentation before writing significant code.

**Deliverables**:
- [x] README.md
- [x] docs/architecture.md
- [x] docs/protocol-spec.md
- [x] docs/packet-format.md
- [x] docs/threat-model.md
- [x] docs/benchmark-plan.md
- [x] docs/handshake.md
- [x] docs/reliability.md
- [x] docs/congestion-control.md
- [x] docs/multipath-mobility.md
- [x] docs/security-model.md
- [x] docs/observability.md
- [x] docs/deployment-model.md
- [x] docs/open-research-questions.md
- [x] ROADMAP.md

**Resolved**:
- Wire encoding: hand-rolled (full control, no parser combinator dependency)
- Async runtime: tokio (largest UDP ecosystem support)
- Crypto library: ring (Phase 4), stubs in place
- ACK delay: 0ms for Phase 2 (immediate ACK); coalescing is a Phase 3 optimization

---

## Phase 1 — Minimal Wire Protocol ✓ COMPLETE

**Goal**: A Rust crate that can encode and decode all NovaNet packet types. No I/O. No crypto.

**Deliverables**:
- [x] Rust workspace (`Cargo.toml` with workspace members)
- [x] `novanet-core` crate: `SessionId`, `NodeId`, `PathId`, `PacketType`, error types
- [x] `novanet-wire` crate: packet structs, `encode()`, `decode()` functions
- [x] All 13 packet types with full field encoding/decoding
- [x] All frame types (STREAM, ACK, DATAGRAM, PADDING, MAX_DATA, etc.)
- [x] Unit tests for round-trip encoding (encode → decode → compare) — 34 tests
- [x] Unit tests for malformed/truncated packets (should return Error, not panic)
- [x] `novanet-cli` MVP: `novanet inspect <hex>` to pretty-print a packet
- [x] Proptest property-based tests (7 properties × 256 iterations each)
- [x] Criterion benchmark skeleton (`benches/packet_codec.rs`)

**Milestone**: ✓ `cargo test --workspace` passes (93 total tests, 0 failures).

---

## Phase 2 — Minimal UDP Transport ✓ COMPLETE

**Goal**: A client and server that can exchange packets over UDP. No crypto yet.

**Deliverables**:
- [x] `novanet-transport` crate: UDP socket, session table, I/O loop (tokio)
- [x] HELLO packet exchange (unauthenticated, no encryption in Phase 2)
- [x] DATA packet with stream frames
- [x] ACK generation and processing
- [x] CLOSE packet
- [x] Session state machine (INITIAL → HANDSHAKING → ESTABLISHED → CLOSED)
- [x] `examples/echo-server`: listens and echoes all received stream data
- [x] `examples/echo-client`: connects, sends a message, prints echoed response
- [x] Structured tracing logs (`tracing` crate) at debug and info levels
- [x] Basic session metrics: packets sent/received, bytes, RTT estimate

**Milestone**: ✓ `./scripts/run-echo-demo.sh` completes in < 100ms.

---

## Phase 3 — Basic Reliability ✓ COMPLETE

**Goal**: Loss recovery. Retransmission. Out-of-order handling.

**Deliverables**:
- [x] Packet number tracking (send side and receive side) — sliding window bitmap in session.rs
- [x] ACK range generation from received packet set — endpoint.rs
- [x] ACK processing: remove from retransmission queue, RTT sample — endpoint.rs handle_ack
- [x] Retransmission queue (ordered by send time) — retransmit.rs (15 tests)
- [x] RTO estimator (RFC 6298 Karn/Jacobson) — session.rs (3 tests)
- [x] Retransmit queue wired into send path — endpoint.rs send_stream_data
- [x] RTO timer background task (`run_rto_loop`) — 50ms tick, scans all sessions
- [x] Fast retransmit (3 duplicate ACKs triggers immediate retransmit) — endpoint.rs handle_ack
- [x] Out-of-order receive buffer (bounded, configurable size) — recv_buffer.rs (9 tests)
- [x] Stream-level reassembly (deliver in-order to application) — recv_buffer.rs
- [x] Loss simulation integration test — tests/loss_recovery.rs (4 tests via novanet-sim)

**Milestone**: ✓ `cargo test --workspace` passes (97 total tests, 0 failures).

---

## Phase 4 — Security Layer

**Goal**: Full cryptographic handshake and encrypted sessions.

**Deliverables**:
- [ ] `novanet-crypto` crate: X25519 key exchange, Ed25519 sign/verify, HKDF, ChaCha20-Poly1305
- [ ] HELLO packet with encrypted identity payload
- [ ] HANDSHAKE packet exchange (server ephemeral PK + signature)
- [ ] HANDSHAKE_DONE signal
- [ ] Derived session keys (write key + IV per direction)
- [ ] AEAD encryption/decryption on all DATA/ACK/CLOSE packets
- [ ] Replay protection (sliding window bitmap)
- [ ] Forward secrecy verification: deleting ephemeral keys after handshake
- [ ] Stateless RETRY token (server-signed, expiring)
- [ ] Anti-amplification enforcement
- [ ] Integration test: MitM intercept attempt must cause auth failure
- [ ] KEY_UPDATE packet (optional, can be triggered manually)

**Milestone**: Two NovaNet instances on different localhost ports complete a secure handshake and
exchange encrypted data. Wireshark shows no readable payload.

---

## Phase 5 — Congestion Control

**Goal**: Realistic congestion control. Pluggable architecture.

**Deliverables**:
- [ ] `novanet-congestion` crate with `CongestionController` trait
- [ ] `AimdController`: simple AIMD (slow start + congestion avoidance + fast recovery)
- [ ] Congestion window enforcement in send path
- [ ] Bytes-in-flight tracking
- [ ] RTT-based RTO recalculation
- [ ] Loss event detection from ACK gaps
- [ ] `novanet-sim` loss simulation integration
- [ ] Benchmark: throughput under 0%, 1%, 2%, 5% packet loss
- [ ] Fairness test: NovaNet vs. TCP on shared simulated bottleneck

**Milestone**: NovaNet sustains > 50% of TCP throughput under 1% loss on a lan preset.

---

## Phase 6 — Multipath and Mobility

**Goal**: Sessions survive IP/port changes. Multiple paths active simultaneously.

**Deliverables**:
- [ ] `novanet-multipath` crate: `PathState`, path metrics, scheduler
- [ ] PathID field active in packet header
- [ ] PATH_CHALLENGE / PATH_RESPONSE exchange
- [ ] Path validation state machine
- [ ] MIGRATE packet (client-initiated migration)
- [ ] Server-side migration detection (packet from new source → PATH_CHALLENGE)
- [ ] Per-path RTT/loss/cwnd tracking
- [ ] Redundant-send packet scheduler (for 2-path scenario)
- [ ] `/experiments/multipath-lab/`: veth topology with two paths, one fails mid-transfer
- [ ] Mobility demo: session continues after simulated IP address change

**Milestone**: A 10 MB transfer completes without interruption when the client's "IP changes"
(simulated by `ip addr` command mid-transfer in a netns).

---

## Phase 7 — TUN/TAP Lab

**Goal**: NovaNet as a transparent overlay. Existing TCP/IP apps can use it.

**Deliverables**:
- [ ] TUN/TAP interface creation and management
- [ ] Packet forwarding: TUN device → NovaNet encapsulation → UDP → decapsulation → TUN device
- [ ] `novanet-cli tunnel` subcommand
- [ ] `/experiments/tun-tap-lab/` scripts
- [ ] Demo: `curl http://server` through a NovaNet tunnel

**Milestone**: `curl` through a NovaNet TUN/TAP tunnel works. pcap shows only UDP packets.

---

## Phase 8 — Benchmarking

**Goal**: Quantified performance claims. Documented comparison with TCP and UDP baselines.

**Deliverables**:
- [ ] Criterion benchmarks for packet encoding/decoding throughput
- [ ] Handshake latency benchmark (p50/p95/p99)
- [ ] Message RTT benchmark under all network presets
- [ ] Throughput benchmark (single stream, 10 streams)
- [ ] Loss recovery benchmark (dip + recovery time)
- [ ] CPU and memory profiling (`perf`, `heaptrack`)
- [ ] Results stored in `/benches/results/` with system metadata
- [ ] Comparison report vs. TCP baseline

**Milestone**: Benchmark report published showing honest comparison. Results do not overclaim.

---

## Phase 9 — Fuzzing and Formalization

**Goal**: Protocol correctness under adversarial input. Formal invariants.

**Deliverables**:
- [ ] `cargo-fuzz` target: packet decoder (all packet types)
- [ ] `cargo-fuzz` target: handshake state machine
- [ ] `proptest` tests: ACK range encoding/decoding invariants
- [ ] `proptest` tests: handshake state machine never panics on arbitrary input sequence
- [ ] `proptest` tests: congestion window is always positive
- [ ] Protocol spec cleanup based on implementation lessons
- [ ] Open research questions documented in `docs/open-research-questions.md`

**Milestone**: 1 billion fuzz iterations without crash or panic in packet decoder.

---

## Long-Term Research (Phase 10+)

These are research-only directions, not committed deliverables:

- **eBPF/XDP acceleration**: Offload ACK generation and path quality measurement to XDP.
- **Kernel module**: Expose NovaNet sessions as file descriptors in the Linux socket API.
- **DPDK datapath**: Kernel-bypass for line-rate packet processing.
- **Post-quantum key exchange**: Replace X25519 with ML-KEM (Kyber).
- **Service-level routing**: A local trust domain resolves ServiceIDs to NodeIDs.
- **Capability tokens**: Bearer tokens carried in the protocol header authorize service access.
- **Protocol-level CDN support**: Content-addressed delivery frames.
- **Browser/WASM implementation**: NovaNet over WebTransport.
- **Formal verification**: TLA+ or Lean model of the handshake and state machines.
- **Hardware offload**: NIC firmware support for SessionID-based classification.

---

## Design Decisions Log

| Decision | Chosen | Alternatives | Reason |
|---|---|---|---|
| Implementation language | Rust | Go, C, C++ | Memory safety, async support, fuzz tooling |
| Carrier protocol | UDP | Raw socket, TCP, SCTP | No kernel changes; QUIC proved it works |
| AEAD algorithm | ChaCha20-Poly1305 | AES-GCM | No timing side channels without hardware |
| Key exchange | X25519 | P-256, P-384 | Fast, side-channel resistant, modern |
| Signature scheme | Ed25519 | ECDSA P-256 | Fast, simple API, no nonce required |
| Async runtime | tokio | async-std, smol | Largest ecosystem, best UDP socket support |
| Packet number width | 64-bit | 32-bit, variable | Avoids wrap-around issues; ample for research |
| ACK format | Range-based | Bitmap | Compact for large windows; same as QUIC |
| Max UDP payload | 1200 bytes | 1500, variable | Safe for IPv4 + IPv6 + most NATs |
