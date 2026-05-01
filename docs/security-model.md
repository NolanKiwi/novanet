# NovaNet Security Model

Version: 0.1-draft

---

## 1. Security Properties

NovaNet provides the following security properties by design (not by configuration):

| Property | Guarantee |
|---|---|
| Confidentiality | All session data is encrypted. Passive observers see only session ID, path ID, packet numbers, and sizes. |
| Integrity | All packets carry a 16-byte AEAD authentication tag. Tampered packets are rejected. |
| Authenticity | Both endpoints can be bound to Ed25519 NodeIDs. Signatures cover the key exchange transcript. |
| Forward Secrecy | Session keys are derived from ephemeral X25519 keys. Compromising long-term keys does not reveal past traffic. |
| Replay Protection | Per-path packet number windows prevent any packet from being accepted twice. |
| Anti-Amplification | Server limits response bytes to 3× client bytes before address validation. |
| Anti-Downgrade | Version and algorithm negotiation is covered by AEAD authentication; modification causes failure. |

---

## 2. What Is and Is Not Encrypted

### Visible to a network observer:

```
UDP header:    src_ip, src_port, dst_ip, dst_port, length
NovaNet header: version, packet_type, flags, header_len, session_id, path_id
Packet number:  u64 (for data-phase packets)
```

- The **session_id** is visible. This is unavoidable (needed to route to the correct session).
- The **packet_type** is visible. This reveals session lifecycle (HELLO, CLOSE visible).
- The **packet_number** is visible. This reveals total packet count per session.

### Not visible (encrypted):

```
Source and destination NodeIDs
Service identity
Stream IDs, offsets, and data
ACK ranges (inside encrypted payload)
Flow control credits
Error reasons
All application data
```

### Metadata leakage:

1. **Traffic volume**: packet sizes and inter-packet timing are visible. PADDING can equalize sizes.
2. **Session existence**: SessionID linkability — a long-lived session is visible as a sequence of packets with the same SessionID. SessionID rotation is a Phase 4+ feature.
3. **Number of paths**: number of distinct PathIDs visible in headers.
4. **Session duration**: time from first HELLO to last CLOSE.

---

## 3. Identity Model

### 3.1 NodeID

A 32-byte value = SHA-256(Ed25519_public_key).

NodeIDs are stable identifiers. They survive IP changes, reboots, and network migrations. A NodeID can be pinned by the peer (like SSH known_hosts) to prevent TOFU attacks after the first connection.

### 3.2 Trust on First Use (TOFU)

The first connection to a server with an unknown NodeID cannot be authenticated without a pre-established trust anchor. Mitigations:
- Publish NodeIDs in DNS (similar to TLSA/DANE).
- Use an out-of-band verification (QR code, manual key exchange).
- Use a certificate authority (CA) model within a trust domain.

Phase 5+ will define a lightweight CA/transparency log model for trust domains.

### 3.3 Key Revocation

If a long-term key is compromised:
1. The operator generates a new long-term keypair (new NodeID).
2. All session tickets issued with the old key are invalidated.
3. Peers must re-pin the new NodeID.
4. The compromise does not affect past session confidentiality (forward secrecy).

A revocation list (CRL equivalent) for a trust domain is a Phase 5+ research item.

### 3.4 Unauthenticated Sessions

Phase 1 supports unauthenticated sessions (NodeID = all zeros). This is explicitly labeled and:
- Still encrypted (ChaCha20-Poly1305 with session-derived keys).
- Still provides forward secrecy (ephemeral X25519).
- Does NOT provide mutual authentication.

Use case: testing, diagnostics, connections to public services that do not require client authentication.

---

## 4. Key Management

### 4.1 Ephemeral Keys

- One fresh X25519 keypair generated per session handshake.
- Private key is deleted immediately after the DH computation.
- Public key is transmitted in the HELLO/HANDSHAKE packet.
- Compromise of this key affects only the active session, not past or future sessions.

### 4.2 Long-Term Keys

- Ed25519 keypairs are node-level keys.
- Private key is stored securely (ideally in an HSM or kernel keyring).
- Public key is distributed out-of-band or via trust domain infrastructure.
- Used only for signing the handshake transcript; not for encryption.

### 4.3 Traffic Keys

- Derived from the ephemeral DH secret via HKDF-SHA256.
- Separate keys for client→server and server→client directions.
- Rotated on KEY_UPDATE packet (mandatory before nonce exhaustion).
- Deleted when the session is closed.

### 4.4 Key Storage Requirements

In production deployments, long-term private keys must:
- Never be stored in plaintext on disk.
- Be hardware-protected where available (TPM, HSM, secure enclave).
- Have a maximum lifetime before rotation (recommended: 1 year).

In the research prototype: keys are generated in memory and not persisted. Restart generates new keys. This is acceptable for Phase 1–4.

---

## 5. Cryptographic Algorithm Choices

| Component | Algorithm | Rationale |
|---|---|---|
| Key exchange | X25519 (ECDH) | Fast, side-channel resistant, widely reviewed |
| Signatures | Ed25519 | No nonce required, fast, deterministic |
| Key derivation | HKDF-SHA256 | RFC 5869, well-analyzed, widely used |
| AEAD | ChaCha20-Poly1305 | RFC 8439, no timing side channel without AES-NI |
| Hash | SHA-256 | NodeID derivation only |
| CSPRNG | OS entropy (getrandom) | Kernel-provided, platform-specific best practice |

**Why ChaCha20-Poly1305 over AES-GCM?**

AES-GCM requires hardware AES acceleration to be timing-safe. On systems without AES-NI (some embedded devices, older ARM), a software AES implementation has timing side channels that can leak the key. ChaCha20-Poly1305 is timing-safe in software on all platforms. For servers with AES-NI, performance is comparable.

**Why X25519 over P-256?**

X25519 has a simpler API (no cofactor handling, no point validation), faster computation, and is widely considered more resistant to implementation errors. NIST P-256 is acceptable but X25519 is preferred for new protocols.

**No post-quantum algorithms yet.** X25519 is broken by a sufficiently powerful quantum computer. Post-quantum key exchange (ML-KEM/Kyber) will be added in Phase 7+. The protocol is designed to support algorithm agility (negotiated in HELLO extensions), so PQ algorithms can be added without a new version.

---

## 6. Forbidden Operations in the Implementation

The following are implementation-level security requirements:

1. **No secret-dependent branches** in any cryptographic code path. Use constant-time comparisons from the `ring` or `subtle` crates.
2. **No key material in log output**. All tracing events must explicitly exclude secret keys, IVs, and plaintexts.
3. **No unsafe code** in protocol crates (`novanet-core`, `novanet-wire`, `novanet-crypto`, `novanet-transport`).
4. **No panic in packet parsing**. All panics in `novanet-wire` are bugs; fuzz testing catches them.
5. **No use of `rand::random()` or `thread_rng()` for security-sensitive randomness**. Use `ring::rand::SystemRandom` or `getrandom` directly.
6. **No session resumption of revoked sessions**. When a session ticket is issued, include a revocation check slot in the ticket (Phase 5+).
7. **No 0-RTT data for non-idempotent requests** (application responsibility, documented).

---

## 7. Security Properties by Phase

| Phase | Property |
|---|---|
| 1 (wire format) | Safe parsing (no crashes on malformed input); no crypto |
| 2 (UDP transport) | Session isolation; no crypto (Phase 2 is plaintext testing only) |
| 3 (reliability) | Packet number tracking; replay window (no auth yet) |
| 4 (security layer) | Full AEAD encryption; mutual auth; replay protection; anti-amplification |
| 5 (congestion) | No new security properties |
| 6 (multipath) | Path validation prevents path hijacking |
| 7 (TUN/TAP) | Encrypted overlay; existing app traffic protected |
| 8 (benchmarks) | No new security properties |
| 9 (fuzzing) | Parser hardening; invariant verification |
| 10+ (PQ crypto) | Quantum resistance |

Phases 1–3 are **not for production**. They are research and testing infrastructure. Phase 4 is the minimum for any real deployment.
