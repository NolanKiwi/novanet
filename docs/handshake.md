# NovaNet Handshake Design

Version: 0.1-draft

---

## 1. Goals

The handshake must:
1. Establish a shared secret between client and server using ephemeral key exchange.
2. Authenticate both endpoints against their long-term NodeIDs (mutual auth).
3. Prevent replay attacks across sessions.
4. Prevent amplification attacks before address validation.
5. Protect against downgrade attacks on version and parameters.
6. Complete in 1 RTT for new sessions, with optional 0-RTT for resumption.
7. Support stateless retry when the server is under load.

---

## 2. Comparison with Prior Art

| Property | TCP+TLS 1.3 | QUIC | WireGuard | NovaNet |
|---|---|---|---|---|
| RTT to first data | 2 RTT (TCP) + 1 RTT (TLS) | 1 RTT (0-RTT possible) | 1 RTT | 1 RTT |
| Encryption during handshake | Partial (TLS record) | Yes (TLS 1.3 built in) | Yes | Yes |
| Mutual auth | Optional (cert-based) | Optional (cert-based) | Yes (public keys) | Yes (Ed25519 NodeID) |
| Forward secrecy | Yes | Yes | Yes | Yes |
| Stateless retry | No | Yes | No | Yes |
| Anti-amplification | No | Yes (3x limit) | No | Yes (3x limit) |
| Connection migration | No | Yes (conn ID) | No | Yes (session ID) |
| 0-RTT | No | Yes (with caveats) | No | Phase 4+ |

**What NovaNet copies from QUIC**: stateless retry token, anti-amplification factor, connection ID concept (mapped to SessionID), 1-RTT design.

**What NovaNet modifies**: NodeID is a public-key hash (not a TLS certificate), identity verification is simpler (Ed25519 signature over the ephemeral key), the crypto is explicitly ChaCha20-Poly1305+X25519+HKDF rather than TLS 1.3 (which requires a TLS implementation dependency).

**What NovaNet improves**: The identity model is richer (NodeID, ServiceID); the handshake is self-contained without a separate TLS record layer.

---

## 3. Cryptographic Primitives

| Role | Algorithm | Crate |
|---|---|---|
| Key exchange | X25519 ECDH | `x25519-dalek` or `ring` |
| Node authentication | Ed25519 | `ed25519-dalek` or `ring` |
| Key derivation | HKDF-SHA256 | `hkdf` + `sha2` |
| AEAD encryption | ChaCha20-Poly1305 | `chacha20poly1305` or `ring` |
| CSPRNG | OS entropy | `ring::rand::SystemRandom` |

---

## 4. Full 1-RTT Handshake

### 4.1 Packet Flow

```
Client                                                      Server
  |                                                           |
  | -- HELLO (session_id, c_ephem_pk, c_node_id_enc) ------> |
  |    [encrypted with hello_key derived from session_id]     |
  |                                                           |
  |    [server: checks retry, anti-ampl, derives keys]        |
  |                                                           |
  | <-- HANDSHAKE (s_ephem_pk, s_node_id_enc, sig) ---------- |
  |    [encrypted with handshake_key]                         |
  |                                                           |
  | [client: verify sig, derive traffic keys]                 |
  |                                                           |
  | -- HANDSHAKE (c_node_id_enc, c_sig, extensions) -------> |
  |    [encrypted with handshake_key]                         |
  |                                                           |
  | <-- HANDSHAKE_DONE ----------------------------------------|
  |    [encrypted with handshake_key]                         |
  |                                                           |
  | <===== DATA (traffic keys) =============================> |
```

Total: **1 RTT** before both sides can send application data.

The client may begin sending DATA packets after receiving the server's HANDSHAKE (before HANDSHAKE_DONE arrives), reducing effective latency to < 1 RTT in practice.

### 4.2 HELLO Packet Construction

The client generates:
```
session_id = random 128-bit value
c_ephem_sk, c_ephem_pk = X25519 keypair (generated fresh for this session)

hello_key = HKDF-Expand(
    HKDF-Extract(salt=0x00*32, ikm=session_id),
    label="novanet v1 hello key", length=32
)
hello_iv = HKDF-Expand(
    HKDF-Extract(salt=0x00*32, ikm=session_id),
    label="novanet v1 hello iv", length=12
)
```

HELLO plaintext payload:
```
c_ephem_pk (32)        -- X25519 ephemeral public key
c_node_id  (32)        -- Ed25519 public key (or zero for unauthenticated)
desired_service_id (32) -- target service
retry_token_len (1)     -- 0 if no retry token
retry_token (variable)  -- server-issued retry token
versions_len (1)        -- number of supported versions
versions (variable)     -- [0x01] for Version 1
```

HELLO ciphertext = ChaCha20-Poly1305-Encrypt(key=hello_key, nonce=hello_iv, aad=header, pt=plaintext)

The nonce does not include a packet number (HELLO has no packet number). The session_id acts as the nonce uniquifier — since session_ids are random, two HELLOs will have different hello_keys.

### 4.3 Server Receives HELLO

The server:
1. Decodes the common header, extracts session_id.
2. If under load and no retry token present: sends RETRY (stateless).
3. Computes hello_key from session_id, decrypts HELLO payload.
4. Generates: `s_ephem_sk, s_ephem_pk = X25519 keypair`.
5. Computes shared secret: `dh_secret = X25519(s_ephem_sk, c_ephem_pk)`.
6. Derives handshake keys:
```
handshake_secret = HKDF-Extract(salt=session_id, ikm=dh_secret)
c_hs_key = HKDF-Expand(handshake_secret, "novanet v1 client hs key", 32)
s_hs_key = HKDF-Expand(handshake_secret, "novanet v1 server hs key", 32)
c_hs_iv  = HKDF-Expand(handshake_secret, "novanet v1 client hs iv",  12)
s_hs_iv  = HKDF-Expand(handshake_secret, "novanet v1 server hs iv",  12)
```
7. Signs: `s_sig = Ed25519-Sign(s_static_sk, session_id || c_ephem_pk || s_ephem_pk)`.
8. Encrypts and sends HANDSHAKE with (s_ephem_pk, s_node_id, s_sig, extensions).

### 4.4 Client Receives Server HANDSHAKE

The client:
1. Decrypts with c_hs_key (which it can derive from dh_secret = X25519(c_ephem_sk, s_ephem_pk)).
2. Verifies: `Ed25519-Verify(s_static_pk, session_id || c_ephem_pk || s_ephem_pk, s_sig)`.
3. If server_node_id is pinned: reject if s_node_id doesn't match.
4. Signs: `c_sig = Ed25519-Sign(c_static_sk, session_id || c_ephem_pk || s_ephem_pk)`.
5. Sends HANDSHAKE with (c_node_id, c_sig, extensions) encrypted with c_hs_key.
6. Derives traffic keys (same derivation as server, see §4.5).
7. May start sending DATA packets now.

### 4.5 Traffic Key Derivation

```
traffic_secret_0 = HKDF-Expand(handshake_secret, "novanet v1 traffic 0", 48)
c_write_key = HKDF-Expand(traffic_secret_0, "novanet v1 client write key", 32)
s_write_key = HKDF-Expand(traffic_secret_0, "novanet v1 server write key", 32)
c_write_iv  = HKDF-Expand(traffic_secret_0, "novanet v1 client write iv",  12)
s_write_iv  = HKDF-Expand(traffic_secret_0, "novanet v1 server write iv",  12)
```

After deriving traffic keys, handshake keys are deleted (forward secrecy for the handshake phase).

### 4.6 Server Sends HANDSHAKE_DONE

After receiving and verifying the client's HANDSHAKE:
1. Server derives traffic keys (same formula).
2. Server sends HANDSHAKE_DONE (encrypted with s_hs_key, packet_number=0).
3. Server discards handshake keys.

---

## 5. Stateless Retry

When the server is under load (session table near capacity, or HELLO rate exceeded), it sends a RETRY instead of completing the handshake.

### 5.1 Retry Token Construction

```
token_plaintext = client_ip_bytes(16) || client_port(2) || session_id(16) || expiry_timestamp(8)
retry_key = HKDF-Expand(server_local_secret, "novanet v1 retry key", 32)
retry_iv  = HKDF-Expand(server_local_secret, "novanet v1 retry iv",  12) XOR timestamp_bytes
retry_token = ChaCha20-Poly1305-Encrypt(retry_key, retry_iv, aad=session_id, pt=token_plaintext)
```

The server_local_secret is rotated every RETRY_TOKEN_LIFETIME (15 seconds). Old tokens remain valid during a brief grace period (one rotation window).

### 5.2 Client Retries

The client includes the full retry_token in its second HELLO. The server decrypts the token, verifies:
- Token has not expired.
- Token source IP matches current packet source IP.
- SessionID in token matches packet SessionID.

If valid, the server proceeds with the handshake without another RETRY.

### 5.3 Anti-Amplification

Before address validation:
- Server sends at most `ANTI_AMPL_FACTOR * bytes_received` bytes total.
- With ANTI_AMPL_FACTOR=3 and a 1200-byte HELLO: server may send ≤ 3600 bytes.
- RETRY token is ≤ 300 bytes, so a single RETRY fits within the limit.
- After receiving a HANDSHAKE from the client (proving reachability), the limit is lifted.

---

## 6. Key Update (KEY_UPDATE)

After establishing the session, either endpoint may trigger a key update:

1. Sender sets key_phase flag and sends KEY_UPDATE packet.
2. New keys are derived:
```
traffic_secret_N+1 = HKDF-Expand(traffic_secret_N, "novanet v1 key update", 48)
new_write_key = HKDF-Expand(traffic_secret_N+1, "novanet v1 client write key", 32)
...
```
3. Sender continues using new keys for subsequent packets.
4. Receiver detects the key_phase change, derives the same new keys, switches to new keys for decryption.
5. Old keys are retained briefly to decrypt in-flight packets from before the update, then deleted.

Mandatory key update: must occur before packet_number reaches 2^62 (nonce exhaustion).

---

## 7. Session Resumption (0-RTT, Phase 4+)

A server may issue a session ticket after HANDSHAKE_DONE:

```
ticket_key = HKDF-Expand(traffic_secret_0, "novanet v1 0rtt ticket", 32)
ticket_payload = client_node_id(32) || server_node_id(32) || traffic_secret_0(48) || expiry(8)
ticket_ciphertext = ChaCha20-Poly1305-Encrypt(ticket_key, ...)
```

On resumption, the client includes the ticket in HELLO and may send 0-RTT DATA before completing the handshake. 0-RTT data:
- Is not forward-secret (uses ticket-derived key).
- Is replay-vulnerable (server must use bloom filter to detect replay).
- Must be limited to idempotent requests (application's responsibility).

0-RTT is disabled by default.

---

## 8. Handshake State Machine

```
Client:                         Server:
INITIAL                         INITIAL
  → send HELLO                    → receive HELLO
HELLO_SENT                      HELLO_RECEIVED
  → receive HANDSHAKE               → if retry needed: send RETRY → RETRY_SENT
HANDSHAKE_RECEIVED                  → else: send HANDSHAKE
  → verify server sig             HANDSHAKE_SENT
  → send HANDSHAKE (client auth)    → receive client HANDSHAKE
  → derive traffic keys             → verify client sig
  → may send DATA                   → derive traffic keys
ESTABLISHED (can send/receive)      → send HANDSHAKE_DONE
  → receive HANDSHAKE_DONE        ESTABLISHED
```

Timeout: any state that does not complete within HANDSHAKE_TIMEOUT (10s) transitions to CLOSED with error HANDSHAKE_FAILED.

---

## 9. Handshake Transcript and Downgrade Protection

The server signature covers `session_id || c_ephem_pk || s_ephem_pk`. This binding:
- Prevents an attacker from substituting a different ephemeral key.
- Binds the signature to the specific session (prevents cross-session replay).
- session_id includes the client's proposed version (in the HELLO payload), so version downgrade causes signature mismatch.

The AEAD AAD for all handshake packets includes the version byte, so modifying the version in the header causes authentication failure at the packet level before the signature is even checked.
