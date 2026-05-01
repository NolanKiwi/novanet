# NovaNet Congestion Control

Version: 0.1-draft

---

## 1. Design Goals

1. **Pluggable**: Different algorithms for different network environments. Rust trait boundary.
2. **Fair**: Must not starve TCP flows sharing the same bottleneck.
3. **Safe**: Conservative default to avoid harming shared infrastructure.
4. **Measurable**: All state visible to the observability layer.
5. **Evolvable**: New algorithms can be added without touching the transport layer.

---

## 2. The CongestionController Trait

```rust
pub trait CongestionController: Send + Sync {
    fn on_ack(&mut self, acked_bytes: usize, rtt: Duration);
    fn on_loss(&mut self, lost_bytes: usize);
    fn congestion_window(&self) -> usize;
    fn can_send(&self, bytes_in_flight: usize, packet_size: usize) -> bool {
        bytes_in_flight + packet_size <= self.congestion_window()
    }
}
```

The transport layer calls these methods and consults `congestion_window()` before sending each packet. The controller is otherwise opaque.

---

## 3. Phase 1: AIMD Controller

### 3.1 Algorithm

**Slow Start**:
- Initial `cwnd = INITIAL_CWND = 12000` bytes (10 × 1200).
- Initial `ssthresh = usize::MAX` (no threshold until first loss).
- On each ACK: `cwnd += max_datagram_size` (one packet per ACK).
- Continue until `cwnd >= ssthresh`.

**Congestion Avoidance**:
- On each ACK: `cwnd += max_datagram_size² / cwnd × (acked_bytes / cwnd)`.
- Simplified: `cwnd += max(1, max_datagram_size × acked_bytes / cwnd)`.
- Grows by approximately one max_datagram_size per RTT (additive increase).

**Loss Event** (RTO or fast retransmit):
- `ssthresh = max(cwnd / 2, MIN_CWND)`.
- `cwnd = ssthresh`.
- Exit slow start.

**Recovery**: After loss, re-enter congestion avoidance at the new ssthresh.

### 3.2 Constants

```
INITIAL_CWND = 10 × MAX_UDP_PAYLOAD = 12000 bytes
MIN_CWND     = 2  × MAX_UDP_PAYLOAD = 2400  bytes
MAX_UDP_PAYLOAD                      = 1200  bytes
```

### 3.3 Behavior Analysis

| Scenario | Behavior |
|---|---|
| Clean network | Slow start doubles cwnd per RTT until ssthresh, then linear |
| 1% packet loss | Loss event reduces cwnd by 50%; recovers in ~10 RTTs |
| 10% packet loss | Frequent loss events keep cwnd near MIN_CWND |
| Jitter without loss | No cwnd change; pure timing variation |
| Idle then burst | RTO may fire; treated as loss; cwnd resets to ssthresh |
| Long fat pipe | Slow start takes O(log(BDP/initial_cwnd)) RTTs to fill |

---

## 4. Phase 2: CUBIC-Like Controller

### 4.1 Motivation

AIMD is too conservative on high-bandwidth, high-latency (HBH) paths. CUBIC uses a cubic function to probe for bandwidth more aggressively after a loss event.

### 4.2 Algorithm Sketch

```
K = cubic_root(W_max * (1 - β) / C)
W(t) = C * (t - K)³ + W_max

where:
  W_max = cwnd at last loss event
  β = 0.7 (CUBIC β, more aggressive than AIMD's 0.5)
  C = 0.4 (CUBIC scaling constant)
  t = time since last loss event
```

On ACK:
- Compute W(t_now).
- If W(t_now) > cwnd: increase toward W(t_now).
- If cwnd > W_max: CUBIC probes above the previous max.

On loss:
- W_max = cwnd.
- cwnd = cwnd × β.
- Reset t=0.

CUBIC is TCP-friendly: it matches AIMD throughput at low RTTs and outperforms AIMD on high-RTT paths.

---

## 5. Phase 2: BBR-Like Controller

### 5.1 Motivation

BBR (Bottleneck Bandwidth and RTT) avoids filling the buffer. AIMD and CUBIC run until packet loss triggers a reaction. BBR tries to measure the actual bottleneck bandwidth and min RTT, then send at that rate without exceeding the bandwidth-delay product.

### 5.2 Algorithm Sketch

BBR measures:
- `btlbw` = maximum observed delivery rate over the last 10 RTTs.
- `rt_prop` = minimum observed RTT over the last 10 seconds.

Sending rate target: `pacing_rate = pacing_gain × btlbw`.
Window: `cwnd = cwnd_gain × btlbw × rt_prop`.

BBR cycles through phases:
- **STARTUP**: pacing_gain=2.89 (like slow start), continues until btlbw plateaus.
- **DRAIN**: pacing_gain=1/2.89, drain the buffer filled during startup.
- **PROBE_BW**: cycles through gain values [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0] to probe for more bandwidth.
- **PROBE_RTT**: briefly reduces cwnd to 4 packets to re-measure min RTT.

BBR is significantly more complex than CUBIC. Phase 2 will implement a simplified version first.

---

## 6. Path-Specific Congestion State (Multipath)

Each path (PathID) has its own congestion controller instance. This is essential for multipath:
- Path 0 may be congested (Wi-Fi) while Path 1 is not (LTE).
- Sending on Path 0 should not affect the cwnd of Path 1.

The packet scheduler (novanet-multipath) decides which path to use for each packet, consulting each path's `can_send()` independently.

---

## 7. Fairness with TCP and QUIC

### 7.1 Why Fairness Matters

NovaNet flows share bottleneck links with TCP flows. If NovaNet is too aggressive, TCP flows starve. If too conservative, NovaNet underperforms unnecessarily.

### 7.2 AIMD Fairness

AIMD is provably TCP-fair (same algorithm). A NovaNet AIMD flow sharing a bottleneck with TCP AIMD flows will converge to equal bandwidth share. This is the Phase 1 guarantee.

### 7.3 CUBIC Fairness

CUBIC has TCP-Friendly mode: when CUBIC's cubic probe would yield less than AIMD would, it falls back to AIMD-equivalent behavior. This ensures CUBIC doesn't starve AIMD flows.

### 7.4 BBR Fairness

BBR does not react to loss, which can cause it to fill buffers more aggressively than CUBIC or AIMD. BBR fairness with CUBIC/AIMD is an active research area. The NovaNet BBR implementation will include an explicit bandwidth share cap to prevent dominating TCP flows.

---

## 8. Special Network Modes

### 8.1 Datacenter Mode

In datacenters:
- RTT is < 1ms.
- Packet loss is rare and typically indicates severe congestion.
- Bandwidth is high (10–100 Gbps links).

Tuning: small initial RTT estimate, aggressive slow start, DCTCP-like ECN reaction (cut cwnd by ECN fraction, not by 50%).

### 8.2 Media Streaming Mode

For latency-sensitive streams (voice, video):
- cwnd should be larger than strict bandwidth requirement to maintain a small buffer.
- Loss should trigger probing, not halving cwnd.
- Use a separate low-latency queue for media frames (high_priority=true STREAM frames).

### 8.3 Satellite Mode

On high-latency links (600ms+ RTT):
- Slow start takes 20+ RTTs to fill a 100Mbps pipe. Use larger initial cwnd.
- RTO should be at least 2× RTT (1.2 seconds for 600ms RTT).
- CUBIC outperforms AIMD significantly in this regime.

---

## 9. Behavior Under Network Conditions

| Condition | AIMD | CUBIC | BBR |
|---|---|---|---|
| 0% loss, low RTT | Good | Good | Best (no buffer waste) |
| 0% loss, high RTT (300ms) | Poor (slow) | Better | Best |
| 1% random loss | Good | Good | Moderate (ignores loss) |
| 2% loss | Poor | OK | Moderate |
| 5% loss | Very poor | Poor | Moderate |
| Bufferbloat | Poor (fills buffer) | Poor | Best (avoids it) |
| Wireless jitter | Overreacts to jitter-loss | Overreacts | Best |
| ECN-enabled path | Moderate | Moderate | Best with ECN |

NovaNet Phase 1 ships AIMD only (safe default). Phase 2 adds CUBIC and BBR as options.

---

## 10. Observable Congestion State

The following metrics are exported by every congestion controller via the observability layer:

| Metric | Type | Description |
|---|---|---|
| cwnd | Gauge | Current congestion window in bytes |
| ssthresh | Gauge | Slow start threshold |
| bytes_in_flight | Gauge | Total unacknowledged bytes |
| smoothed_rtt | Gauge | SRTT in microseconds |
| rtt_variance | Gauge | RTTVAR in microseconds |
| rto | Gauge | Current RTO in milliseconds |
| retransmit_count | Counter | Total retransmissions |
| loss_event_count | Counter | Total loss events |
| ack_count | Counter | Total ACKs processed |
