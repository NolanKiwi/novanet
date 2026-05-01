# NovaNet

**An experimental next-generation network protocol stack.**

NovaNet is to TCP/IP what Rust is to C: it preserves the strengths — performance, low-level
control, universality — while addressing the structural weaknesses — bolted-on security, lack of
native identity, poor mobility, limited observability, and protocol ossification.

---

## Mission

The global Internet runs on TCP/IP, which is remarkable, reliable, and battle-tested. It is also
structurally limited in ways that cannot be patched away:

- IP addresses conflate location and identity, making mobility hard.
- TCP connection state is tied to the 4-tuple (src IP, src port, dst IP, dst port), so any
  network change tears down the connection.
- Security is layered on top (TLS, IPsec) rather than built in.
- There is no native authentication, identity, or capability model.
- Observability requires external tooling and is not a first-class protocol feature.
- TCP is ossified: middleboxes make it nearly impossible to evolve on-wire behavior.

QUIC (RFC 9000) solved several of these problems: it runs over UDP, encrypts by default, uses
connection IDs independent of the 4-tuple, multiplexes streams, and is deployable from userspace.
But QUIC is still fundamentally a transport protocol layered over IP addressing.

NovaNet is a research vehicle for exploring what lies beyond:

- **Cryptographic session identity** decoupled from IP addresses.
- **Native multipath** as a first-class primitive, not a bolted-on extension.
- **Observability** built into the protocol itself, not scraped from logs.
- **Pluggable congestion control** via a well-defined Rust trait.
- **Multiple delivery semantics** in a single session (reliable stream, reliable messages,
  unreliable datagrams, priority control plane).
- **Capability-based addressing**: connect to a service identity, not an IP:port.
- **Formal threat model** and safe-Rust implementation throughout.

---

## Status

**Phase 0 — Research and Design** (current)

The protocol specification, packet format, threat model, and architecture are being drafted.
The Rust workspace skeleton and initial wire-format crate are being built.

See [ROADMAP.md](ROADMAP.md) for the full phased plan.

---

## Deployment Reality

NovaNet does **not** aim to replace the global Internet in the short term.

The first prototype runs entirely in userspace over UDP and targets:

- localhost
- Linux network namespaces
- Docker containers
- Virtual machines
- TUN/TAP overlay interfaces
- Private lab networks

This is realistic. QUIC took this same path. WireGuard started as a userspace prototype.

---

## Repository Layout

```
novanet/
  docs/               Protocol specifications and design documents
  crates/
    novanet-core      Shared types, errors, identities, session IDs
    novanet-wire      Binary packet encoder/decoder (no crypto)
    novanet-crypto    Cryptographic primitives and key exchange
    novanet-transport UDP transport, session management, I/O loop
    novanet-congestion Pluggable congestion control algorithms
    novanet-multipath  Path tracking, path validation, migration
    novanet-observability Metrics, tracing, Prometheus exporter
    novanet-cli       CLI inspection and diagnostic tool
    novanet-sim       Simulation utilities for packet loss, delay, jitter
  examples/           Runnable demos
  experiments/        Network namespace and TUN/TAP lab scripts
  benches/            Criterion benchmarks
  fuzz/               Packet parser fuzzing targets
  scripts/            Lab setup and test runner scripts
```

---

## Quick Start (Phase 1 — not yet available)

```sh
# Build the workspace
cargo build --workspace

# Run unit tests
cargo test --workspace

# Run the echo demo (Phase 2)
./scripts/run-echo-demo.sh
```

---

## Safety Scope

This project is for:
- Defensive protocol research
- Reliability and performance engineering
- Controlled lab experimentation

This project does **not** implement:
- Port scanning or host discovery against unauthorized targets
- Flood or DDoS tools
- Stealth or evasion mechanisms
- Exploit payloads
- Unauthorized packet injection

All experiments run on localhost, containers, VMs, network namespaces, or explicitly authorized
private networks.

---

## Documents

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System architecture and design philosophy |
| [docs/protocol-spec.md](docs/protocol-spec.md) | Full protocol specification |
| [docs/packet-format.md](docs/packet-format.md) | Binary wire format |
| [docs/handshake.md](docs/handshake.md) | Handshake design |
| [docs/reliability.md](docs/reliability.md) | Reliability and flow control |
| [docs/congestion-control.md](docs/congestion-control.md) | Congestion control design |
| [docs/multipath-mobility.md](docs/multipath-mobility.md) | Multipath and mobility |
| [docs/security-model.md](docs/security-model.md) | Security model |
| [docs/threat-model.md](docs/threat-model.md) | Threat model and mitigations |
| [docs/observability.md](docs/observability.md) | Observability design |
| [docs/deployment-model.md](docs/deployment-model.md) | Deployment phases |
| [docs/benchmark-plan.md](docs/benchmark-plan.md) | Benchmarking methodology |
| [docs/open-research-questions.md](docs/open-research-questions.md) | Open questions |
| [ROADMAP.md](ROADMAP.md) | Phased implementation roadmap |

---

## Comparison

| Feature | TCP+TLS | QUIC | NovaNet (goal) |
|---|---|---|---|
| Encryption by default | No (TLS optional) | Yes | Yes |
| Auth by default | No | No | Yes (session identity) |
| Mobility | No | Partial (conn ID) | Yes (crypto session ID) |
| Multipath | No (MPTCP optional) | No | First-class |
| Stream multiplexing | No | Yes | Yes |
| Head-of-line blocking | Yes | No | No |
| Deployable from userspace | No | Yes | Yes |
| Native observability | No | Partial | First-class |
| Pluggable congestion control | No | Partial | Yes (trait-based) |
| Service-level addressing | No | No | Yes (goal) |
| Kernel bypass path | No | Partial | Roadmap |

---

## License

Research prototype. See LICENSE.
