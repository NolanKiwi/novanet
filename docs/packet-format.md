# NovaNet Packet Format

Version: 0.1-draft

---

## 1. Design Principles

- **Fixed-size short header** for routing (session ID, path ID, packet number) — visible to
  protocol machinery but not to the application.
- **All application data is encrypted** (ChaCha20-Poly1305 AEAD).
- **Payload is a sequence of frames** (like QUIC), enabling multiplexing of streams, ACKs,
  datagrams, and control messages in one UDP packet.
- **No IP-level semantics** in the NovaNet header; IP is treated as an opaque carrier.
- **Extensible via extension headers** (future-proofing).

---

## 2. Common Packet Header

Every NovaNet packet starts with this header. It is **unencrypted** (needed for routing and
decryption key lookup). It is included as **AEAD Additional Authenticated Data (AAD)** so any
tampering causes authentication failure.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |   Pkt Type    |     Flags     |  Header Len   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        Session ID (128 bits / 16 bytes)       |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Path ID     |
+-+-+-+-+-+-+-+-+
```

**Total fixed header: 21 bytes.**

| Field | Size | Description |
|---|---|---|
| Version | 1 byte | Protocol version. Currently 0x01. |
| Pkt Type | 1 byte | Packet type (see §5). |
| Flags | 1 byte | Type-specific flags (see §6). |
| Header Len | 1 byte | Total header length in bytes (allows extension headers). |
| Session ID | 16 bytes | 128-bit session identifier. Not derived from IP/port. |
| Path ID | 1 byte | Path identifier within session. 0x00 = initial path. |

---

## 3. Packet Number (DATA and post-handshake packets only)

Appended after the common header for all DATA, ACK, CLOSE, ERROR, PATH_*, KEY_UPDATE packets.

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Packet Number (64 bits)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|---|---|---|
| Packet Number | 8 bytes | Monotonically increasing u64. Never repeats per (session, path). |

**Note**: HELLO and RETRY packets do not carry a packet number (session not yet established).

---

## 4. Extension Headers

If `Header Len > 29` (fixed header + packet number), the bytes between the end of the packet
number and the start of the encrypted payload are extension headers.

Extension header format:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Ext Type    |  Ext Length   |       Extension Data ...      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Unknown extension headers must be silently skipped (Type & 0x80 == 0) or cause a fatal error
(Type & 0x80 == 1). This follows the TLV convention.

---

## 5. Encrypted Payload

After the header (and packet number for DATA packets), the remainder of the UDP payload is:

```
+---------------------------------------------------+
| AEAD Ciphertext (variable, at least 16 bytes)     |
| (plaintext = sequence of frames, defined in §7)   |
+---------------------------------------------------+
| AEAD Authentication Tag (16 bytes)                |
+---------------------------------------------------+
```

AAD for AEAD = all header bytes (from Version through the last extension header byte).

---

## 6. Packet Types and Formats

### 6.1 HELLO (0x01)

Sent by client to initiate a session.

**Unencrypted portion** (common header):
- Version, Pkt Type = 0x01, Flags, Header Len, Session ID (chosen by client), Path ID = 0x00

**No packet number** (session not established).

**Encrypted payload** (encrypted with a HELLO-specific derived key — see §6.1.1):

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Client Ephemeral Public Key (32 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Client Node ID (32 bytes)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Desired Service ID (32 bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Retry Token Length (2 bytes)  |  Retry Token (0–255 bytes) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Supported Versions Length     |  Versions (N x 1 byte)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Extensions ...                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**6.1.1 HELLO encryption key:**

Since the session key is not yet derived (we don't have the server ephemeral key), the HELLO
payload is encrypted with a well-known protocol key derived from the session ID:

```
hello_key = HKDF-Expand(HKDF-Extract(salt=0, ikm=session_id), "novanet v0 hello key", 32)
hello_iv  = HKDF-Expand(HKDF-Extract(salt=0, ikm=session_id), "novanet v0 hello iv",  12)
```

This provides confidentiality against passive observers even before key exchange completes.
It does **not** provide authentication (the server does not yet know the client's identity).

**HELLO Flags:**
| Bit | Name | Description |
|---|---|---|
| 0 | HAS_RETRY_TOKEN | Retry token is present in payload |
| 1 | HAS_0RTT_DATA | 0-RTT data follows (Phase 4+) |
| 2–7 | Reserved | Must be zero |

---

### 6.2 RETRY (0x02)

Sent by server before completing the handshake. Does not establish session state.

**Unencrypted** (common header + retry token, no encryption):

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Common Header (21 bytes, Session ID mirrors client's)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Retry Token Length (2 bytes) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Retry Token (variable, server-encrypted, max 255 bytes)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Retry Integrity Tag (16 bytes, over entire RETRY packet)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Retry Integrity Tag prevents a network attacker from injecting a fake RETRY.
It is computed with a server-local key (not derived from session ID).

---

### 6.3 HANDSHAKE (0x03)

Used to carry the server's ephemeral public key and mutual authentication.

**Unencrypted** (common header only):

**Encrypted payload frames:**
- CRYPTO frame: contains raw handshake bytes (server ephemeral PK, server node ID, signature,
  extensions).

The CRYPTO frame is a sequence of bytes, similar to QUIC's CRYPTO frame, used to carry TLS-like
messages at specific encryption levels.

---

### 6.4 HANDSHAKE_DONE (0x04)

Sent by server to signal handshake completion. Encrypted with handshake keys.

**Encrypted payload**: empty or PADDING frames only.

---

### 6.5 DATA (0x10)

The primary packet type for established sessions.

**Header**: Common header + 8-byte Packet Number.

**Encrypted payload**: A sequence of **frames** (see §7).

---

### 6.6 ACK (0x11)

**Header**: Common header + 8-byte Packet Number.

**Encrypted payload**: ACK frame (see §7.2).

ACK packets may also contain other frames (e.g., MAX_DATA for flow control, or PADDING).

---

### 6.7 PATH_CHALLENGE (0x20) and PATH_RESPONSE (0x21)

**Header**: Common header + 8-byte Packet Number.

**Encrypted payload**:
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Challenge Data (8 bytes)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

PATH_RESPONSE echoes the same 8 bytes from the most recent PATH_CHALLENGE on that path.

---

### 6.8 CLOSE (0x40)

**Header**: Common header + 8-byte Packet Number.

**Encrypted payload**:
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Error Code (2 bytes)  |  Frame Type (1 byte)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Reason Length (1 byte) | Reason String (0–255 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

### 6.9 ERROR (0x41)

Same format as CLOSE. Used for fatal protocol errors that require immediate termination (as
opposed to a graceful CLOSE).

---

## 7. Frame Types (inside encrypted payload)

DATA packets carry a sequence of frames. Each frame begins with a 1-byte type.

| Frame Type | ID | Description |
|---|---|---|
| PADDING | 0x00 | One byte of padding. Can repeat. |
| ACK | 0x01 | Acknowledge received packets |
| CRYPTO | 0x02 | Handshake crypto data |
| STREAM | 0x10 | Stream data |
| STREAM_RESET | 0x11 | Reset a stream |
| STREAM_STOP | 0x12 | Stop sending on a stream |
| DATAGRAM | 0x20 | Unreliable datagram |
| MAX_DATA | 0x30 | Connection-level flow control credit |
| MAX_STREAM_DATA | 0x31 | Stream-level flow control credit |
| DATA_BLOCKED | 0x32 | Sender is blocked on connection limit |
| STREAM_DATA_BLOCKED | 0x33 | Sender is blocked on stream limit |
| NEW_PATH | 0x40 | Announce a new local address |
| PATH_STATUS | 0x41 | Report path quality metrics |
| KEY_PHASE | 0x50 | Key update signal |
| CLOSE_STREAM | 0x60 | Gracefully close a stream |

### 7.1 STREAM Frame

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Frame Type   |  Flags        |     Stream ID (4 bytes)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Offset (8 bytes)                         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Data Length (2 bytes)     |   Stream Data (variable)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**STREAM Flags:**
| Bit | Description |
|---|---|
| 0 | FIN: last data on this stream |
| 1 | Priority: 0=normal, 1=high |
| 2–7 | Reserved |

### 7.2 ACK Frame

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Frame Type   |  Range Count  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Largest Acked (8 bytes)                             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           ACK Delay (4 bytes, microseconds)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| For each range (count = Range Count):                         |
|   Gap (4 bytes)   |   Ack Length (4 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

ACK ranges are encoded as (Gap, AckLength) pairs relative to the previous range, exactly like
QUIC. Gap = number of un-acked packets before this range. AckLength = number of acked packets.

### 7.3 DATAGRAM Frame

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Frame Type   |   Datagram Length (2 bytes)   |  Data ...    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Datagrams are not retransmitted. The receiver may deliver them out of order or drop them silently.

---

## 8. Packet Size Limits

- Minimum NovaNet packet: 21 bytes (header only, e.g., PADDING packet).
- Maximum NovaNet payload: 1200 bytes (conservative IPv4/IPv6 MTU, avoiding fragmentation).
- HELLO packets: must be at most 1200 bytes (anti-amplification).
- RETRY packets: must be at most 1200 bytes.
- PMTUD probing (Phase 3+): PATH_CHALLENGE packets of increasing sizes test the actual path MTU.

---

## 9. Full Packet Layout Summary

```
[UDP Header (8 bytes)]
[NovaNet Header (21 bytes)]
  version (1) | type (1) | flags (1) | header_len (1) | session_id (16) | path_id (1)
[Packet Number (8 bytes)] — DATA and post-handshake only
[Extension Headers (variable)] — if header_len > 29
[AEAD Ciphertext (variable)]
[AEAD Tag (16 bytes)]
```

For a minimal DATA packet carrying a small payload on a single stream:
```
UDP:     8 bytes
Header: 21 bytes
PktNum:  8 bytes
Frame type:  1 byte
STREAM frame: ~20 bytes of payload data
AEAD tag:   16 bytes
Total: ~74 bytes minimum overhead for a 20-byte payload
```

This is more overhead than raw TCP (~40 bytes for TCP+IP) but comparable to QUIC+TLS (~40–60
bytes), and justified by the additional features provided.

---

## 10. Metadata Leakage Analysis

| Information | Visible? | Mitigation |
|---|---|---|
| Session exists | Yes (SessionID in header) | Use ephemeral SessionIDs |
| Source/dest identity | No | Encrypted in payload |
| Service being accessed | No | Encrypted in payload |
| Payload size | Yes (UDP length) | PADDING frame support |
| Connection duration | Yes (timing) | No mitigation at protocol level |
| Path used | Yes (Path ID in header) | Intentional; needed for routing |
| Packet number | Yes (plain text) | Required for nonce/replay detection |
| Number of streams | No | Encrypted |
| Content type | No | Encrypted |

The SessionID is visible in all packets. This is a trade-off: it is needed to route packets to
the correct session handler on the receiver without requiring per-IP state. Applications requiring
unlinkability should rotate SessionIDs periodically (Phase 4+ feature).
