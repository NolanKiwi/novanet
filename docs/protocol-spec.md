# NovaNet Protocol Specification

Version: 0.1-draft  
Status: Experimental — not for production use

---

## 1. Overview

NovaNet is a connection-oriented, multiplexed, encrypted, multipath-capable transport protocol
running over UDP. It provides multiple delivery semantics within a single cryptographic session.

---

## 2. Goals

1. Encryption and authentication by default.
2. Session identity decoupled from IP addresses.
3. Mobility: session survives IP/port/interface changes.
4. Multipath: multiple active paths per session.
5. Multiplexing: reliable streams, reliable messages, unreliable datagrams in one session.
6. Observability: RTT, loss, throughput, and congestion metrics are protocol-visible.
7. Deployable over UDP from userspace with no kernel changes.

---

## 3. Session Model

A NovaNet **session** is a bidirectional communication context between two endpoints.

### 3.1 Session Lifecycle

```
INITIAL → HANDSHAKING → ESTABLISHED → MIGRATING → ESTABLISHED
                                     ↘ DRAINING → CLOSED
```

| State | Description |
|---|---|
| INITIAL | No session exists; ready to send HELLO |
| HANDSHAKING | HELLO sent or received; key exchange in progress |
| ESTABLISHED | Handshake complete; data can flow |
| MIGRATING | A path migration is in progress |
| DRAINING | CLOSE sent; draining unacknowledged data |
| CLOSED | Session is fully closed |

### 3.2 Session Identity

Every session has a **SessionID**: a 128-bit cryptographically random value chosen by the client
during the handshake. This SessionID is the primary key for all session state on both endpoints.

The SessionID is **not** derived from IP addresses or ports. It survives any network change.

### 3.3 Node Identity

A node may have a long-term **NodeID** (SHA-256 of an Ed25519 public key). This is used during
the handshake for mutual authentication. It is encrypted and not visible in packet headers.

Unauthenticated sessions (Phase 1 only, for testing) use a zero NodeID and skip signature
verification.

---

## 4. Channel Types

Within a single session, NovaNet supports four channel types:

| Type | Identifier | Description |
|---|---|---|
| STREAM | stream_id (u32) | Reliable, ordered byte stream (like TCP) |
| MESSAGE | message_id (u32) | Reliable, ordered discrete messages |
| DATAGRAM | — | Unreliable, unordered datagrams |
| CONTROL | — | Reserved for protocol control messages |

A session can have up to 2^31 client-initiated streams (even stream_ids) and 2^31 server-initiated
streams (odd stream_ids), following QUIC convention.

---

## 5. Packet Types

| Type ID | Name | Direction | Description |
|---|---|---|---|
| 0x01 | HELLO | C→S | Initiate a session; contains ephemeral public key |
| 0x02 | RETRY | S→C | Stateless retry with token (anti-amplification) |
| 0x03 | HANDSHAKE | C↔S | Carry handshake crypto messages |
| 0x04 | HANDSHAKE_DONE | S→C | Signal handshake completion |
| 0x10 | DATA | C↔S | Carry stream/message/datagram payload |
| 0x11 | ACK | C↔S | Acknowledge received packets |
| 0x12 | NACK | C↔S | Negative acknowledgment (informational) |
| 0x20 | PATH_CHALLENGE | C↔S | Validate a new path |
| 0x21 | PATH_RESPONSE | C↔S | Respond to PATH_CHALLENGE |
| 0x22 | MIGRATE | C→S | Announce path migration |
| 0x30 | KEY_UPDATE | C↔S | Trigger key rotation |
| 0x40 | CLOSE | C↔S | Begin graceful session close |
| 0x41 | ERROR | C↔S | Report a fatal error |
| 0xFF | PADDING | C↔S | Pad packet to a target size |

---

## 6. Encryption Model

### 6.1 Key Hierarchy

```
Long-term identity keys (Ed25519):
  client_static_sk / client_static_pk
  server_static_sk / server_static_pk

Per-session ephemeral keys (X25519):
  client_ephemeral_sk / client_ephemeral_pk   (generated per HELLO)
  server_ephemeral_sk / server_ephemeral_pk   (generated per HELLO response)

Shared secret:
  dh_secret = X25519(client_ephemeral_sk, server_ephemeral_pk)
           == X25519(server_ephemeral_sk, client_ephemeral_pk)

Session keys (derived via HKDF-SHA256):
  handshake_secret = HKDF-Extract(salt=session_id, ikm=dh_secret)

  client_write_key = HKDF-Expand(handshake_secret, "novanet v0 client write", 32)
  server_write_key = HKDF-Expand(handshake_secret, "novanet v0 server write", 32)
  client_write_iv  = HKDF-Expand(handshake_secret, "novanet v0 client iv",    12)
  server_write_iv  = HKDF-Expand(handshake_secret, "novanet v0 server iv",    12)

After HANDSHAKE_DONE, traffic keys are derived:
  traffic_secret_0 = HKDF-Expand(handshake_secret, "novanet v0 traffic", 32)
  (subsequent key updates derive traffic_secret_N from traffic_secret_{N-1})
```

### 6.2 AEAD

Algorithm: **ChaCha20-Poly1305** (RFC 8439).

- 256-bit key
- 96-bit nonce = IV XOR (PacketNumber padded to 12 bytes)
- 128-bit authentication tag appended to ciphertext
- Additional authenticated data (AAD) = the unencrypted packet header

### 6.3 What Is Encrypted

```
HELLO packet:
  Unencrypted: version, packet_type, session_id, client_ephemeral_pk
  Encrypted:   client_node_id, client_service_id, extensions, retry_token (if present)

HANDSHAKE packet:
  Unencrypted: version, packet_type, session_id, path_id, packet_number
  Encrypted:   server_ephemeral_pk, server_node_id, signature, extensions

DATA / ACK / CLOSE / etc.:
  Unencrypted: version, packet_type, session_id, path_id, packet_number
  Encrypted:   all payload frames
```

### 6.4 Nonce Construction

```
nonce[0..12] = write_iv XOR (packet_number as u64, zero-padded to 12 bytes, big-endian)
```

Packet number must never repeat for a given key. Key rotation (KEY_UPDATE) resets the nonce space.

### 6.5 Key Update

After any 2^62 packets or on explicit request, a KEY_UPDATE packet triggers:
```
new_traffic_secret = HKDF-Expand(current_traffic_secret, "novanet v0 key update", 32)
new_write_key      = HKDF-Expand(new_traffic_secret, "novanet v0 write key", 32)
new_write_iv       = HKDF-Expand(new_traffic_secret, "novanet v0 write iv",  12)
```

---

## 7. Handshake Protocol

### 7.1 Overview (1-RTT)

```
Client                                      Server
  |                                           |
  |-- HELLO (session_id, client_ephem_pk) --> |
  |                                           | (generate server_ephem_pk)
  |                                           | (derive handshake keys)
  |                                           | (issue stateless retry if needed)
  |                                           |
  |<-- HANDSHAKE (server_ephem_pk, sig) ----- |
  |                                           |
  | (derive shared secret)                    |
  | (verify server signature)                 |
  |                                           |
  |-- HANDSHAKE (client sig, extensions) ---> |
  |                                           |
  |<--- HANDSHAKE_DONE ---------------------- |
  |                                           |
  |<===== DATA flows both ways =============> |
```

Total latency: **1 RTT** before data can flow (client can send in HANDSHAKE packet in some modes).

### 7.2 Stateless Retry

Before completing the handshake, the server may send a RETRY packet containing a server-generated
token. The client must include this token in its second HELLO. This proves the client's address is
reachable, preventing amplification attacks.

The retry token is encrypted with a server-local key and contains:
- Client IP + port
- Session ID
- Expiry timestamp

### 7.3 0-RTT Mode (Optional, Phase 4+)

Using a stored session ticket from a prior session, a client may send application data in the
first HELLO packet. 0-RTT data is:
- Not forward-secret (uses a pre-shared key from the prior session).
- Replay-vulnerable (the server must limit 0-RTT data acceptance using a bloom filter or cache).
- Only safe for idempotent requests.

0-RTT is disabled by default and must be explicitly enabled by the application.

### 7.4 Anti-Amplification

Before address validation, the server limits its response to 3x the size of the incoming data.
After receiving a HANDSHAKE packet from the client, the address is considered validated and this
limit is lifted.

---

## 8. Reliability

### 8.1 Packet Numbers

Every DATA, ACK, CLOSE, ERROR, and PATH_* packet carries a monotonically increasing **PacketNumber**
(u64) scoped to a (session_id, path_id) pair.

PacketNumbers are never reused. KeyUpdate resets the nonce space but not the packet number
sequence (packet numbers continue increasing across key updates).

### 8.2 ACK Ranges

ACK packets carry a list of (first, last) inclusive ranges of received packet numbers, ordered
from largest to smallest. This is equivalent to QUIC's ACK frame format.

Maximum ACK ranges per packet: 255.

### 8.3 Retransmission

Lost packets are detected by:
1. **RTO (Retransmission Timeout)**: Based on RTT estimator. If no ACK arrives within the RTO,
   retransmit the earliest unacknowledged packet.
2. **Fast Retransmit**: If an ACK gap is detected (packets N and N+2 are acknowledged but N+1 is
   not), retransmit N+1 immediately (threshold: 3 ACKs for packets after the gap).

Retransmitted packets carry the **original** payload but a **new** PacketNumber. This is critical:
never reuse PacketNumbers.

### 8.4 Flow Control

Two levels:

1. **Stream-level**: Each stream has a send window and receive window. Credits are advertised in
   ACK packets via `max_stream_data` fields.
2. **Connection-level**: A connection-level receive window limits total bytes in flight. Advertised
   via `max_data` in ACK packets.

Initial window sizes are negotiated in HANDSHAKE extensions.

---

## 9. Path Management

### 9.1 Path Lifecycle

```
PROBING → VALIDATING → ACTIVE → DEGRADED → FAILED
                      ↘ STANDBY (backup path)
```

### 9.2 Path Validation

A new path is validated by sending a PATH_CHALLENGE with a random 64-bit nonce. The remote
endpoint must echo the nonce in a PATH_RESPONSE. Until validated, data cannot be sent on the
new path.

### 9.3 Path Migration

When the client's IP or port changes (detected by the server receiving a packet from a new
address), the server sends a PATH_CHALLENGE on the new address. Once validated, the session is
migrated to the new path.

The client may also proactively send a MIGRATE packet before changing networks.

### 9.4 Path Quality Metrics

Per-path metrics maintained by the implementation:
- RTT (smoothed + variance, RFC 6298 style)
- Packet loss rate (per packet window)
- Throughput estimate
- Congestion window

---

## 10. Congestion Control

### 10.1 Default Algorithm (Phase 1)

Simple AIMD:
- Starts with a small congestion window (initial_cwnd = 10 * max_datagram_size).
- On each ACK: cwnd += max_datagram_size * (acked_bytes / cwnd)  [additive increase]
- On loss event: cwnd = max(cwnd / 2, min_cwnd)  [multiplicative decrease]
- Slow start phase until cwnd > ssthresh.

### 10.2 Pluggable Interface

```rust
pub trait CongestionController: Send + Sync {
    fn on_ack(&mut self, acked_bytes: usize, rtt: Duration);
    fn on_loss(&mut self, lost_bytes: usize);
    fn congestion_window(&self) -> usize;
    fn can_send(&self, bytes_in_flight: usize, packet_size: usize) -> bool;
}
```

Later phases add CUBIC-like and BBR-like implementations.

---

## 11. Error Handling

### 11.1 ERROR Packet

Fatal errors terminate the session. The ERROR packet carries:
- Error code (u16): protocol-level error codes defined in this specification.
- Error string (encrypted, up to 255 bytes): human-readable message.
- Frame type that triggered the error (u8): optional.

### 11.2 Error Codes

| Code | Name | Description |
|---|---|---|
| 0x0000 | NO_ERROR | Graceful close |
| 0x0001 | INTERNAL_ERROR | Implementation error |
| 0x0002 | PROTOCOL_VIOLATION | Peer sent invalid packet |
| 0x0003 | CRYPTO_ERROR | AEAD decryption failed |
| 0x0004 | STREAM_LIMIT_EXCEEDED | Too many streams opened |
| 0x0005 | FLOW_CONTROL_VIOLATION | Exceeded flow control window |
| 0x0006 | HANDSHAKE_FAILED | Handshake could not complete |
| 0x0007 | VERSION_NEGOTIATION | No common version found |
| 0x0008 | REPLAY_DETECTED | Duplicate packet number |
| 0x0009 | ADDRESS_VALIDATION_FAILED | PATH_RESPONSE did not match |
| 0x000A | RESOURCE_LIMIT | Too many sessions or streams |

---

## 12. Version Negotiation

The first byte of every NovaNet packet is the version byte. Current version: `0x01`.

If a server does not support the client's version, it sends a VERSION_NEGOTIATE packet listing
supported versions. The client then restarts the handshake with a supported version.

The version field is part of the AEAD Additional Authenticated Data (AAD), so a downgrade attack
(stripping the version) causes authentication failure.

---

## 13. Padding

PADDING packets (0xFF) can be sent at any time to:
- Pad a handshake packet to a minimum size (obfuscating which messages were sent).
- Satisfy PMTUD probing.
- Prevent traffic analysis based on packet sizes.

PADDING bytes must be ignored by the receiver. A PADDING packet that exceeds the current anti-
amplification budget is silently dropped.

---

## 14. Protocol Constants (Phase 1 Defaults)

| Constant | Value | Description |
|---|---|---|
| MAX_UDP_PAYLOAD | 1200 bytes | Conservative MTU |
| INITIAL_CWND | 12000 bytes | ~10 packets |
| MIN_CWND | 2400 bytes | 2 packets |
| INITIAL_RTT_ESTIMATE | 333 ms | Conservative initial RTT |
| MAX_ACK_RANGES | 255 | ACK ranges per packet |
| MAX_STREAMS | 2^31 | Per direction |
| MAX_SESSION_IDLE | 60 seconds | Idle timeout before CLOSE |
| HANDSHAKE_TIMEOUT | 10 seconds | Full handshake timeout |
| PATH_CHALLENGE_TIMEOUT | 3 seconds | Per path validation |
| RETRY_TOKEN_LIFETIME | 15 seconds | Server retry token expiry |
| ANTI_AMPL_FACTOR | 3 | Server response / client bytes |

---

## 15. Observability Contract

The protocol emits the following observable events:

| Event | When | Data |
|---|---|---|
| session.created | Handshake initiated | session_id, local_addr, remote_addr |
| session.established | HANDSHAKE_DONE received | session_id, rtt_ms |
| session.closed | CLOSE sent/received | session_id, reason |
| session.error | ERROR sent/received | session_id, error_code |
| path.validated | PATH_RESPONSE received | session_id, path_id, rtt_ms |
| path.failed | Path validation timeout | session_id, path_id |
| path.migrated | Session migrated | session_id, old_path_id, new_path_id |
| packet.sent | Any packet sent | session_id, path_id, packet_number, size |
| packet.received | Any packet received | session_id, path_id, packet_number, size |
| packet.lost | Loss detected | session_id, path_id, packet_number |
| packet.retransmitted | Retransmission | session_id, path_id, new_packet_number |
| ack.received | ACK processed | session_id, acked_count, rtt_sample_ms |
| congestion.updated | cwnd changed | session_id, cwnd, bytes_in_flight |
| stream.opened | New stream | session_id, stream_id, direction |
| stream.closed | Stream finished | session_id, stream_id, bytes_transferred |
| crypto.key_updated | Key rotation | session_id, generation |

All events are emitted via the `tracing` crate with structured fields. A subscriber can forward
them to Prometheus, JSON logs, or a binary trace file.
