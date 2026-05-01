# NovaNet Multipath and Mobility

Version: 0.1-draft

---

## 1. Core Idea

In TCP, a connection is a 4-tuple: (src_ip, src_port, dst_ip, dst_port). When any element changes — IP address, port, or interface — the connection breaks. The application must reconnect, triggering a full handshake.

In NovaNet, a session is identified by a 128-bit SessionID chosen at handshake time. The underlying (src_addr, dst_addr) pair is a **Path** — a property of the session, not its identity. Sessions can have multiple paths simultaneously (multipath) and survive the loss of all current paths (mobility).

This is similar to QUIC's Connection ID mechanism, but NovaNet makes multipath a first-class primitive rather than an optional extension.

---

## 2. Path Concepts

```
Session (SessionID = 128-bit random)
  └── Path 0 (PathID=0): Wi-Fi (192.168.1.5:54321 → 203.0.113.7:9999)   [ACTIVE]
  └── Path 1 (PathID=1): LTE  (10.0.2.8:22222  → 203.0.113.7:9999)    [STANDBY]
  └── Path 2 (PathID=2): VPN  (172.16.0.3:38000 → 203.0.113.7:9999)   [PROBING]
```

**PathID** is a 1-byte identifier scoped to a session. The packet header carries PathID so each side knows which path delivered a packet.

---

## 3. Path Lifecycle

```
PROBING → VALIDATING → ACTIVE → DEGRADED → FAILED
                       │
                       └──────── STANDBY (backup, not primary)
```

| State | Description |
|---|---|
| PROBING | Local address announced; PATH_CHALLENGE not yet sent |
| VALIDATING | PATH_CHALLENGE sent; waiting for PATH_RESPONSE |
| ACTIVE | Validated, in use for data transmission |
| DEGRADED | Active but showing high loss or RTT |
| FAILED | Validation timed out or path marked unusable |
| STANDBY | Validated but held as a backup |

Paths transition: PROBING → VALIDATING on PATH_CHALLENGE send, VALIDATING → ACTIVE on PATH_RESPONSE receipt.

---

## 4. Path Validation

Path validation ensures the peer can actually reach the claimed address (anti-spoofing).

### 4.1 PATH_CHALLENGE

When a new path needs validation:
1. Generate 8 random bytes: `challenge = random_bytes(8)`.
2. Store `(path_id, challenge, send_time)` in local state.
3. Send a PATH_CHALLENGE packet on the new path (new source address).

### 4.2 PATH_RESPONSE

On receiving PATH_CHALLENGE:
1. Echo the 8 bytes back in a PATH_RESPONSE on the same path.
2. PATH_RESPONSE is authenticated (AEAD); only the session peer can generate a valid one.

### 4.3 Validation Completion

On receiving PATH_RESPONSE:
1. Look up the stored challenge for the (path_id, challenge_data) pair.
2. If matched: transition to ACTIVE, record RTT = now - send_time.
3. If not matched: silently discard (possible stale response).
4. If PATH_CHALLENGE_TIMEOUT (3s) elapses without response: mark path FAILED.

---

## 5. NAT Rebinding Detection

NAT devices may remap a port without client notification. The server detects this when it receives a packet for a known SessionID from a new source address.

### 5.1 Server-Side Detection

```
1. Server receives DATA packet with known session_id but new (src_ip, src_port).
2. Server does NOT immediately migrate the session.
3. Server sends PATH_CHALLENGE on the new address.
4. Server continues using the old path until PATH_RESPONSE is received.
5. On validated PATH_RESPONSE: promote new path to ACTIVE.
```

This prevents an attacker from hijacking a session by sending packets from a spoofed address: the AEAD authentication ensures the data packet came from the real session peer, but the path validation separately confirms reachability.

### 5.2 Client-Side NAT Rebinding

The client can proactively handle NAT rebinding by:
1. Detecting that no ACKs are arriving on the current path (timeout).
2. Probing alternative paths (if available) or re-probing the current endpoint from a new socket.

---

## 6. Active Path Migration

The client may migrate proactively (e.g., before switching from Wi-Fi to LTE):

1. Client opens a new socket on the LTE interface.
2. Client sends NEW_PATH frame in a DATA packet (advertising the new local address).
3. Server sends PATH_CHALLENGE to the new address.
4. Client responds with PATH_RESPONSE on the new path.
5. Client sends MIGRATE packet: `{ preferred_path_id: new_path_id }`.
6. Server acknowledges by sending DATA on the new path.
7. Old path enters STANDBY state (kept for a short time, then closed).

### 6.1 Graceful Migration State Machine

```
Client:
  [established, path_0 active]
  → send NEW_PATH(new_addr) on path_0
  [wait for PATH_CHALLENGE on new_addr]
  → receive PATH_CHALLENGE on path_1
  → send PATH_RESPONSE on path_1
  → send MIGRATE(preferred=path_1)
  [path_1 active, path_0 draining]

Server:
  [established, path_0 active]
  → receive NEW_PATH(new_addr)
  → send PATH_CHALLENGE to new_addr
  [wait for PATH_RESPONSE on new_addr]
  → receive PATH_RESPONSE on path_1
  → validate, mark path_1 ACTIVE
  → receive MIGRATE(preferred=path_1)
  → switch primary path to path_1
  → send ACK on path_1
```

---

## 7. Multipath Packet Scheduling

When multiple paths are ACTIVE simultaneously, the scheduler chooses which path to use for each packet.

### 7.1 Scheduling Policies

**Redundant Send (for low latency)**:
- Send the same packet on multiple paths.
- The first arriving copy is delivered; duplicates are discarded.
- Doubles bandwidth usage; reduces tail latency significantly.
- Suitable for small high-priority packets (handshake, control).

**Round-Robin (for throughput)**:
- Alternate between active paths.
- Suboptimal if paths have different RTTs (reordering at receiver).
- Simple, fair.

**Lowest-RTT-First (balanced)**:
- Send on the path with the lowest smoothed RTT.
- If the chosen path's cwnd is full, fall back to the next-lowest RTT path.
- Handles path quality differences automatically.

**Weighted Bandwidth Split (for aggregation)**:
- Assign traffic to paths proportional to their estimated bandwidth.
- Complex to implement correctly; Phase 6 research item.

Phase 6 default: Lowest-RTT-First for data, Redundant Send for PATH_CHALLENGE/HANDSHAKE.

### 7.2 Reorder Management

Multipath inherently causes reordering when paths have different RTTs. The stream reassembly layer handles this using the offset-based buffer (see reliability.md). The out-of-order receive window must be large enough to absorb RTT differential:

```
reorder_window = max_path_rtt_difference × throughput
```

Example: Path 0 = 5ms, Path 1 = 50ms, throughput = 10 Mbps → window = 45ms × 10Mbps ÷ 8 ≈ 56 KB.

---

## 8. Per-Path Metrics

Each PathState records:

| Metric | Description |
|---|---|
| smoothed_rtt | RFC 6298 SRTT |
| rtt_variance | RFC 6298 RTTVAR |
| rto | Current RTO |
| loss_rate | Estimated packet loss rate |
| bytes_sent | Total bytes sent on this path |
| bytes_received | Total bytes received on this path |
| last_validated | Timestamp of last successful path validation |
| congestion_window | Per-path cwnd (from per-path CC controller) |

---

## 9. Wi-Fi → LTE Migration Scenario

This is the canonical mobility scenario:

```
t=0s:   Client is on Wi-Fi (192.168.1.5) connected to server (203.0.113.7)
        SessionID = 0xABC...
        PathID=0 ACTIVE: (192.168.1.5:54321 → 203.0.113.7:9999)
        Data streaming at 5 Mbps.

t=5s:   Client moves to edge of Wi-Fi coverage.
        LTE interface comes up: 10.0.2.8/32.
        Client detects new interface.
        Client sends NEW_PATH frame on Path 0 advertising (10.0.2.8, new_port).

t=5.05s: Server receives NEW_PATH.
         Server sends PATH_CHALLENGE to (10.0.2.8, new_port) on PathID=1.

t=5.1s:  Client receives PATH_CHALLENGE on LTE interface.
         Client sends PATH_RESPONSE on PathID=1.

t=5.15s: Server receives PATH_RESPONSE.
         Server marks PathID=1 ACTIVE.
         Server RTT for Path 1 = 50ms.

t=5.2s:  Client sends MIGRATE(preferred_path=1).
         Client starts sending DATA on Path 1.

t=5.25s: Wi-Fi signal drops. Path 0 starts dropping packets.
         Server sends PATH_CHALLENGE on Path 0 to verify (no response).

t=8.25s: PATH_CHALLENGE_TIMEOUT on Path 0. Path 0 marked FAILED.
         Only Path 1 active.

Result:  Session continued uninterrupted. From the application perspective:
         - Brief throughput dip at t=5.2–5.25s as scheduler switches.
         - No reconnection. No new handshake. No data loss on Path 1.
```

Total migration time: ~200ms (one RTT for path validation).
Compare to TCP: 0ms (session dies) + full reconnect time (1.5–2 RTT handshake + TLS) = ~500ms.

---

## 10. What Multipath Does NOT Provide

- **Bandwidth aggregation across all network types**: Aggregating LTE + Wi-Fi for additive bandwidth works only when both paths connect to the same server endpoint (same IP). If paths use different exit IPs (common with LTE), the server sees different source addresses but the same session. Aggregation works, but congestion control must account for each path independently.

- **Anonymity**: Multipath reveals more addresses to the server, not fewer.

- **Link-layer reliability**: NovaNet multipath operates at the session layer. A physical Wi-Fi disconnection takes tens to hundreds of milliseconds to detect, during which queued packets are lost. The reliability layer retransmits them on the surviving path.

- **NAT traversal for new paths**: If the new path requires STUN/TURN hole punching to reach the server, NovaNet does not provide this. A rendezvous server is needed for NAT traversal. This is a research item (Phase 8+).
