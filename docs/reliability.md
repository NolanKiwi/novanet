# NovaNet Reliability Design

Version: 0.1-draft

---

## 1. Delivery Semantics

NovaNet supports four delivery modes in one session:

| Mode | Retransmit | Ordered | Use Case |
|---|---|---|---|
| ReliableStream | Yes | Yes | File transfer, HTTP-like |
| ReliableMessage | Yes | Yes | RPC, framed protocols |
| UnreliableDatagram | No | No | Latency-sensitive media, games |
| PartiallyReliable | Limited | Yes | Live video with bounded retransmit |

Streams carry ReliableStream and ReliableMessage. Datagrams are UnreliableDatagram. All share one session's congestion controller and packet-number space.

---

## 2. Packet Numbers

Every DATA, ACK, CLOSE, PATH_*, and HANDSHAKE_DONE packet carries a monotonically increasing **PacketNumber** (u64) scoped to the (session_id, path_id) pair.

Properties:
- PacketNumbers start at 0 and never wrap (u64 max = 1.8 × 10^19 packets).
- PacketNumbers are never reused, even for retransmissions.
- PacketNumbers are included in the AEAD nonce (nonce = write_iv XOR packet_number_big_endian_padded).
- A key update resets the nonce space (new keys) but does NOT reset the packet number sequence.

---

## 3. Acknowledgments

### 3.1 ACK Frame Format

ACK frames encode received ranges as (gap, ack_length) pairs, ordered largest to smallest:

```
largest_acked    -- largest packet number received
ack_delay_us     -- time delta between receiving largest_acked and sending this ACK
range_count      -- number of (gap, ack_length) pairs
[gap, ack_len]*  -- relative encoding (same as QUIC ACK frames)
```

Decoding:
```
end = largest_acked
for each (gap, ack_len) pair:
    end = end - gap
    start = end - ack_len
    range = [start, end]
    end = start - 1
```

### 3.2 ACK Generation Policy

- ACK every second received packet (like TCP).
- ACK immediately if a gap is detected (a packet was received out of order).
- ACK immediately if the receive buffer is filling up (flow control urgency).
- ACK delay: up to ACK_DELAY_MAX (25ms) to allow coalescing.
- ACK delay is reported in the ack_delay_us field so the sender can correct the RTT sample.

### 3.3 ACK Receiver Side State

The receiver maintains:
- `largest_received: u64` — the largest PacketNumber received.
- `received_set: BitSet` — a sliding window of received/not-received status.
- Window size: 2048 packets (256 bytes of bitmap).
- Packets earlier than `largest_received - 2048` are outside the window and presumed old; they are silently dropped (replay protection also catches these).

---

## 4. Loss Detection

### 4.1 RTO (Retransmission Timeout)

Based on RFC 6298 with modifications:

```
initial SRTT = 333ms (INITIAL_RTT_MS constant)
initial RTTVAR = 167ms

On each RTT sample (rtt_sample):
    if first sample:
        SRTT = rtt_sample
        RTTVAR = rtt_sample / 2
    else:
        RTTVAR = 0.75 * RTTVAR + 0.25 * |SRTT - rtt_sample|
        SRTT   = 0.875 * SRTT  + 0.125 * rtt_sample

RTO = max(SRTT + 4 * RTTVAR, 200ms)
```

RTT sample = (current_time - send_time_of_acked_packet) - ack_delay_us.

The ack_delay correction prevents ACK coalescing from inflating RTT estimates.

### 4.2 RTO Expiry

When the RTO timer fires:
1. Mark the earliest unacknowledged packet as lost.
2. Place it in the retransmission queue.
3. Double the RTO (exponential backoff): `RTO = min(RTO * 2, MAX_RTO)` where MAX_RTO = 60s.
4. Notify the congestion controller of a loss event.

RTO timer is reset on every ACK that acknowledges at least one new packet.

### 4.3 Fast Retransmit

When the sender receives 3 or more ACKs for packets after a gap (i.e., packets N+1, N+2, N+3 are acked but N is not):
1. Immediately retransmit packet N.
2. Notify the congestion controller.
3. Do not wait for RTO.

This is the same mechanism as TCP fast retransmit.

### 4.4 Packet Reordering Tolerance

Out-of-order delivery is increasingly common in networks with ECMP and link aggregation. NovaNet tolerates reordering before declaring loss:

- A packet is not declared lost merely because a later packet was acknowledged.
- Loss is declared only after 3 ACKs for later packets (fast retransmit threshold), or RTO expiry.
- Reorder tolerance window: 3 packets. Can be tuned upward if the network has high reorder rates.

---

## 5. Retransmission Queue

The sender maintains a `RetransmitQueue`:

```
struct UnackedPacket {
    packet_number: u64,
    send_time: Instant,
    payload_frames: Vec<Frame>,    // frames to retransmit (not the original packet)
    byte_count: usize,
}
```

On ACK: remove all packets in the ACK range from the queue. For each removed packet, produce an RTT sample (largest_acked only, not all acked packets).

On retransmission: create a new packet with a **new** PacketNumber containing the same frames. Remove the old entry. Add the new entry. This is critical: never reuse a PacketNumber.

Queue bound: configurable maximum in-flight bytes. Default: 4× INITIAL_CWND. If the queue is full, the sender blocks (backpressure to the application).

---

## 6. Stream-Level Ordering and Reassembly

### 6.1 Stream Send Side

Each stream has:
- `next_offset: u64` — the byte offset of the next byte to send.
- A send buffer: bytes written by the application, not yet acknowledged.
- `max_stream_data: u64` — flow control limit from the peer.

STREAM frames carry (stream_id, offset, data, fin). Multiple frames can cover overlapping ranges (retransmit). The receiver uses offset to reassemble.

### 6.2 Stream Receive Side

Each stream has:
- `next_expected_offset: u64` — next byte to deliver to application.
- `reorder_buffer: BTreeMap<u64, Bytes>` — out-of-order received segments.
- `max_offset_received: u64` — for flow control credit accounting.

On receiving a STREAM frame:
1. If `offset < next_expected_offset`: already delivered, ignore (but send ACK).
2. If `offset == next_expected_offset`: deliver directly, advance next_expected_offset, drain reorder_buffer.
3. If `offset > next_expected_offset`: insert into reorder_buffer, wait.

Reorder buffer limit: configurable (default 64 KB per stream). If exceeded, send STREAM_DATA_BLOCKED and pause the stream.

### 6.3 FIN Handling

The FIN flag in a STREAM frame marks the last byte of the stream. The stream is considered fully received when:
- All bytes up to and including the FIN byte offset have been delivered.
- The FIN byte itself has been received.

Only then is the stream closed (application receives EOF).

---

## 7. Flow Control

### 7.1 Stream-Level Flow Control

Each stream has a receive window (`max_stream_data`). The sender must not send past this limit.

The receiver sends MAX_STREAM_DATA frames to advance the window as data is consumed by the application:
```
new_max = next_expected_offset + initial_stream_window
```

Initial stream window: 256 KB (negotiated in HANDSHAKE extensions). Default.

### 7.2 Connection-Level Flow Control

A connection-level window (`max_data`) limits the total bytes in flight across all streams.

The receiver sends MAX_DATA frames to advance the connection window. Typical policy: send MAX_DATA when the consumed bytes exceed 50% of the current window.

Initial connection window: 1 MB. Default.

### 7.3 Blocking

If the sender is blocked by flow control (peer's window exhausted):
- Stop sending STREAM frames for that stream.
- Send a STREAM_DATA_BLOCKED (or DATA_BLOCKED) frame to notify the peer.
- Resume when the peer sends MAX_STREAM_DATA or MAX_DATA.

Flow control blocking must not block the send path for other streams (multiplexing benefit).

---

## 8. Priority Scheduling

When multiple streams have data ready to send and the congestion window allows, the scheduler picks which stream to send from. Policy:

- **High priority** (STREAM frame high_priority flag set): send first.
- **Round-robin** among normal-priority streams.
- **LIFO for control frames**: CLOSE, ERROR, ACK always ahead of data.

Phase 1: simple round-robin with high-priority override. Phase 5+: weighted fair queuing.

---

## 9. Cancellation

### 9.1 STREAM_RESET

Either endpoint may cancel a stream mid-flight with a STREAM_RESET frame:
- Sender: stops sending, discards unsent data.
- Receiver: discards buffered data, delivers cancellation to application.

### 9.2 STREAM_STOP

Receiver signals it no longer wants data on a stream:
- Sender: may stop sending on this stream (saves bandwidth).
- Sender: must still acknowledge any buffered data to allow proper accounting.

---

## 10. Unreliable Datagram Delivery

DATAGRAM frames:
- Are sent in DATA packets with packet numbers (for AEAD; they need a nonce).
- Are NOT retransmitted if the containing packet is lost.
- Are not flow-controlled (they bypass stream flow control).
- Are bounded by the packet size minus overhead.
- Are delivered to the application at most once, unordered.

Maximum datagram payload: `MAX_UDP_PAYLOAD - DATA_HEADER_SIZE - AEAD_TAG_SIZE - 3` (3 = frame type + length field) ≈ 1151 bytes.

---

## 11. RTT Estimator Summary

The RTT estimator is maintained per path (PathState). Only the largest_acked packet in each ACK contributes an RTT sample (to avoid using duplicate ACKs for RTT measurement):

```
rtt_sample = now - send_time[largest_acked] - ack_delay_us
if rtt_sample > 0:
    update_rtt(rtt_sample)
```

The corrected RTT sample must always be > 0; if `ack_delay_us > rtt_sample`, clamp at 1µs.
