# NovaNet Observability Design

Version: 0.1-draft

---

## 1. Philosophy

Observability in TCP/IP is an afterthought: you scrape `/proc/net/tcp`, parse `ss -s`, or run `tcpdump`. There is no structured, machine-readable protocol-level telemetry. Operators infer protocol state from indirect signals.

NovaNet makes observability a first-class feature. Every significant protocol event emits a structured log record. Metrics are collected and exportable. No external tools are required to understand session state.

---

## 2. Layers of Observability

### 2.1 Structured Event Logs

Every protocol event emits a `tracing` event with structured fields. Events are machine-readable (JSON subscriber available) and human-readable (default text format).

All events use the namespace prefix `novanet.` for filtering:
```
RUST_LOG=novanet=debug cargo run --example echo-server
```

### 2.2 Session Timeline

The `novanet-cli` tool can reconstruct a session timeline from structured log output:
```
novanet trace --session <session_id> --log session.jsonl
```

Output shows the sequence of state transitions, packet exchanges, RTT samples, and congestion window changes for a session.

### 2.3 Prometheus Metrics

The `novanet-observability` crate provides a Prometheus exporter that exposes:
- Session counts (active, handshaking, closed).
- Per-session RTT, cwnd, bytes_in_flight.
- Aggregate packet/byte counters.
- Loss and retransmission rates.

Available at: `http://localhost:9898/metrics` (configurable port).

### 2.4 pcap-Compatible Export

For Wireshark analysis, the transport layer can emit a pcap-format trace of all NovaNet packets (headers only, no payload since it is encrypted). This allows existing network analysis tools to be used for debugging.

---

## 3. Event Catalog

All events emitted by the NovaNet implementation, with their `tracing` levels and structured fields.

### 3.1 Session Events

| Event | Level | Fields |
|---|---|---|
| `session.created` | INFO | session_id, local_addr, remote_addr, initiator |
| `session.established` | INFO | session_id, rtt_ms, server_node_id |
| `session.closed` | INFO | session_id, reason, duration_ms, bytes_sent, bytes_received |
| `session.error` | WARN | session_id, error_code, error_description |
| `session.idle_timeout` | INFO | session_id, idle_secs |
| `session.handshake_timeout` | WARN | session_id |
| `session.retry_sent` | DEBUG | session_id, client_addr |
| `session.retry_received` | DEBUG | session_id |

### 3.2 Path Events

| Event | Level | Fields |
|---|---|---|
| `path.created` | DEBUG | session_id, path_id, local_addr, remote_addr |
| `path.challenge_sent` | DEBUG | session_id, path_id, challenge_hex |
| `path.challenge_received` | DEBUG | session_id, path_id |
| `path.validated` | INFO | session_id, path_id, rtt_ms |
| `path.validation_timeout` | WARN | session_id, path_id |
| `path.migrated` | INFO | session_id, old_path_id, new_path_id |
| `path.failed` | WARN | session_id, path_id, reason |
| `path.degraded` | DEBUG | session_id, path_id, loss_rate |

### 3.3 Packet Events

| Event | Level | Fields |
|---|---|---|
| `packet.sent` | TRACE | session_id, path_id, packet_number, type, size_bytes |
| `packet.received` | TRACE | session_id, path_id, packet_number, type, size_bytes |
| `packet.lost` | DEBUG | session_id, path_id, packet_number, detection_method |
| `packet.retransmitted` | DEBUG | session_id, path_id, original_pn, new_pn |
| `packet.duplicate` | DEBUG | session_id, path_id, packet_number |
| `packet.decrypt_failed` | WARN | session_id, path_id, packet_number |

### 3.4 Reliability Events

| Event | Level | Fields |
|---|---|---|
| `ack.sent` | TRACE | session_id, path_id, largest_acked, range_count |
| `ack.received` | TRACE | session_id, path_id, largest_acked, acked_count, rtt_sample_ms |
| `rto.fired` | DEBUG | session_id, path_id, rto_ms, packets_in_flight |
| `fast_retransmit.triggered` | DEBUG | session_id, path_id, missing_pn |
| `stream.opened` | INFO | session_id, stream_id, direction |
| `stream.closed` | INFO | session_id, stream_id, bytes_transferred |
| `stream.reset` | WARN | session_id, stream_id, error_code |
| `flow_control.blocked` | DEBUG | session_id, stream_id, window_bytes |
| `flow_control.updated` | TRACE | session_id, stream_id, new_max_bytes |

### 3.5 Congestion Events

| Event | Level | Fields |
|---|---|---|
| `congestion.updated` | TRACE | session_id, path_id, cwnd, ssthresh, bytes_in_flight |
| `congestion.loss_event` | DEBUG | session_id, path_id, cwnd_before, cwnd_after |
| `congestion.slow_start_exit` | DEBUG | session_id, path_id, cwnd, ssthresh |
| `congestion.key_update` | INFO | session_id, generation |

### 3.6 Crypto Events

| Event | Level | Fields |
|---|---|---|
| `crypto.handshake_started` | DEBUG | session_id |
| `crypto.handshake_complete` | INFO | session_id, cipher_suite, auth_result |
| `crypto.key_update` | INFO | session_id, generation |
| `crypto.error` | WARN | session_id, detail (no key material) |

---

## 4. Prometheus Metrics

All metrics use the prefix `novanet_`.

### 4.1 Session Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `novanet_sessions_total` | Counter | state | Total sessions by final state |
| `novanet_sessions_active` | Gauge | — | Currently active sessions |
| `novanet_sessions_handshaking` | Gauge | — | Sessions in handshake |
| `novanet_handshake_duration_ms` | Histogram | — | Handshake completion time |

### 4.2 Packet Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `novanet_packets_sent_total` | Counter | type | Packets sent by packet_type |
| `novanet_packets_received_total` | Counter | type | Packets received by packet_type |
| `novanet_packets_lost_total` | Counter | detection | Packets lost by detection method |
| `novanet_bytes_sent_total` | Counter | — | Total bytes sent |
| `novanet_bytes_received_total` | Counter | — | Total bytes received |

### 4.3 RTT and Latency Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `novanet_rtt_smoothed_us` | Histogram | — | SRTT samples in microseconds |
| `novanet_rtt_variance_us` | Histogram | — | RTTVAR samples |
| `novanet_rto_ms` | Histogram | — | RTO values at time of use |

### 4.4 Congestion Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `novanet_cwnd_bytes` | Histogram | — | Congestion window observations |
| `novanet_bytes_in_flight` | Gauge | — | Current bytes in flight (all sessions) |
| `novanet_loss_events_total` | Counter | — | Total congestion loss events |
| `novanet_retransmissions_total` | Counter | — | Total retransmitted packets |

### 4.5 Stream Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `novanet_streams_opened_total` | Counter | direction | Streams opened |
| `novanet_streams_closed_total` | Counter | direction, reason | Streams closed |
| `novanet_stream_bytes_total` | Counter | direction | Application bytes on streams |

---

## 5. CLI Inspection Tool

The `novanet` CLI provides real-time and offline inspection.

### 5.1 Packet Inspection

```
novanet inspect <hex>
```

Decodes and pretty-prints a hex-encoded NovaNet packet. Useful for debugging captured packets.

### 5.2 Session Status

```
novanet session list   [--json]
novanet session show <session_id>
```

Connects to a running NovaNet process's Unix socket and displays:
- Current session state.
- Active paths with RTT and loss rate.
- Stream table.
- Congestion window.
- Retransmission queue depth.

### 5.3 Live Metrics

```
novanet metrics [--interval 1s]
```

Displays a live dashboard of aggregate metrics from the running process.

### 5.4 Packet Trace

```
novanet trace start --output session.pcap
novanet trace stop
```

Starts a pcap-format capture of NovaNet packet headers (no payload).

---

## 6. Implementation in the Crate

The `novanet-observability` crate is a thin wrapper over `tracing`. It provides:

1. **Typed event functions** (session_created, packet_lost, etc.) that callers invoke instead of raw `tracing::info!()`. This ensures consistent field names across the codebase.

2. **Metrics registry** (Phase 3+): a `Metrics` struct holding `AtomicU64` counters and atomic histograms. Updated directly from the hot path.

3. **Prometheus exporter** (Phase 3+): an HTTP handler that serializes the registry in Prometheus text format.

4. **pcap writer** (Phase 7+): a `PcapWriter` that emits packets in libpcap format on a background thread.

---

## 7. Observability in the Packet Format

Some protocol-level observability data is included in the wire format itself, allowing tools that can see network traffic to extract it:

- **Packet numbers**: visible in unencrypted header. Allows passive monitoring of retransmissions (gaps in sequence).
- **ACK ranges**: visible only to the session peers (encrypted). A session participant can log ACK state.
- **RTT samples**: computed from packet timestamps by both endpoints; not on the wire.
- **Congestion window**: not on the wire; local to the sender's congestion controller.

This is a deliberate design: enough information to debug without exposing application data to passive observers.
