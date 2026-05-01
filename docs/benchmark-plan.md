# NovaNet Benchmarking Plan

Version: 0.1-draft

---

## 1. Principles

- All benchmarks run on **localhost or local network namespaces only**. No external targets.
- No flooding, scanning, or DoS-simulation tools.
- Baselines are TCP (via `iperf3`) and UDP (raw and QUIC where available).
- Benchmarks must be **reproducible**: fixed random seeds, pinned CPU affinity, documented
  kernel parameters, and network emulation settings.
- All results are stored in `/benches/results/` as JSON with the commit hash and system info.

---

## 2. Environment Setup

### 2.1 Hardware

- Minimum: single Linux machine, localhost loopback only.
- Better: two machines connected by a physical Ethernet link (eliminates loopback shortcuts).
- Lab: Linux network namespaces with `veth` pairs and `tc netem` for emulation.

### 2.2 Kernel Parameters

```bash
# Increase socket buffers for high-throughput tests
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
sysctl -w net.core.rmem_default=1048576
sysctl -w net.core.wmem_default=1048576

# Disable Nagle for TCP baseline (fair comparison)
# Set in iperf3 with --no-delay

# CPU frequency scaling: set to performance mode
cpupower frequency-set -g performance
```

### 2.3 Network Namespace Lab

```bash
# See /experiments/netns-lab/ for setup scripts
# Creates: ns-client (veth0) <----> (veth1) ns-server
# Applies: tc netem delay/loss/jitter

ip netns add ns-client
ip netns add ns-server
ip link add veth0 type veth peer name veth1
ip link set veth0 netns ns-client
ip link set veth1 netns ns-server
ip netns exec ns-client ip addr add 10.99.0.1/24 dev veth0
ip netns exec ns-server ip addr add 10.99.0.2/24 dev veth1
ip netns exec ns-client ip link set veth0 up
ip netns exec ns-server ip link set veth1 up
```

### 2.4 Network Condition Presets

Using `tc netem`:

| Preset Name | Delay | Loss | Jitter | Reorder |
|---|---|---|---|---|
| loopback | 0ms | 0% | 0ms | 0% |
| lan | 1ms | 0.01% | 0.5ms | 0% |
| wan | 40ms | 0.1% | 5ms | 0.1% |
| lossy | 40ms | 2% | 5ms | 0% |
| very-lossy | 80ms | 5% | 10ms | 1% |
| satellite | 600ms | 0.5% | 20ms | 0% |
| mobile | 50ms | 1% | 15ms | 0.5% |
| datacenter | 0.5ms | 0.001% | 0.1ms | 0% |

```bash
# Apply a preset to the veth interface:
tc qdisc add dev veth0 root netem delay 40ms 5ms loss 0.1% reorder 0.1% 25%
```

---

## 3. Benchmarks

### 3.1 Handshake Latency

**What**: Time from first byte sent by client to first application byte receivable (1-RTT).

**Method**:
1. Server listens on localhost:7777.
2. Client opens 10,000 sequential sessions, each sends 1 byte and receives 1 byte echo, then
   closes.
3. Measure p50/p95/p99/max handshake time.

**Baselines**:
- TCP + TLS 1.3 (1-RTT): `openssl s_client` timing.
- TCP raw (no TLS): `nc` timing.
- QUIC (if available): `quiche` or `quinn` echo benchmark.

**Expected NovaNet result**: Similar to QUIC (1-RTT). Should be measurably faster than TCP+TLS
(no separate TLS handshake after TCP handshake).

**Tooling**: Rust criterion benchmark in `/benches/handshake_latency_bench.rs`.

---

### 3.2 Message Round-Trip Latency

**What**: RTT for a single 1-byte request/response after session establishment.

**Method**:
1. Establish a single session.
2. Send 100,000 single-byte pings, measure round-trip time per ping.
3. Report p50/p95/p99/max.

**Network presets**: loopback, lan, wan.

**Baselines**: TCP ping-pong, UDP ping-pong.

**Tooling**: Rust criterion benchmark in `/benches/rtt_bench.rs`.

---

### 3.3 Throughput (Single Stream)

**What**: Maximum sustained throughput on a single reliable stream.

**Method**:
1. Client sends 1 GB of data on a single stream to server.
2. Server counts bytes received and confirms checksum.
3. Measure wall-clock throughput (bytes/second).

**Network presets**: loopback, lan, datacenter.

**Baselines**:
- `iperf3 -t 10 -c 127.0.0.1` (TCP)
- `iperf3 -u -b 0 -c 127.0.0.1` (UDP)

**Tooling**: Rust criterion benchmark + shell script baseline.

---

### 3.4 Throughput (Multi-Stream)

**What**: Aggregate throughput when 10 parallel streams are open.

**Method**: 10 goroutine-equivalent tokio tasks each send 100 MB on their own stream to the
server simultaneously. Measure aggregate bytes/second.

**Expected**: Should exceed TCP because NovaNet avoids head-of-line blocking across streams.

---

### 3.5 Loss Recovery Time

**What**: How quickly a stream recovers after a packet loss event.

**Method**:
1. Establish session, start streaming.
2. At t=1s, inject a 5% packet loss burst using `tc netem` for 100ms.
3. Measure the throughput dip and recovery time (time to return to 90% of pre-loss throughput).
4. Count retransmissions (from observability metrics).

**Baselines**: TCP under same loss scenario.

**Tooling**: `/experiments/loss-jitter-lab/` scripts + NovaNet metrics exporter.

---

### 3.6 Retransmission Overhead

**What**: What fraction of total packets sent are retransmissions?

**Method**: Run a 60-second throughput test under 1% packet loss. Count total packets sent and
retransmissions via NovaNet metrics.

**Metric**: retransmission_count / total_packets_sent.

---

### 3.7 Packet Header Overhead

**What**: What is the per-byte overhead of NovaNet vs. TCP and UDP?

**Method**: Send N application bytes and measure total bytes on the wire (via `tcpdump` counting).

**Formula**: overhead = (wire_bytes - app_bytes) / app_bytes

**Expected**:
- TCP (no TLS): ~3–5% overhead on large transfers (segment coalescing).
- UDP raw: 0% overhead beyond fixed UDP header.
- NovaNet: higher per-packet overhead (29+ bytes header vs. 20 TCP + 20 IP), but may coalesce
  multiple frames per packet, reducing effective overhead.

---

### 3.8 Congestion Fairness

**What**: When a NovaNet flow and a TCP flow compete on the same bottleneck link, what fraction
of bandwidth does each get?

**Method**:
1. Create a netns topology: client1 (NovaNet), client2 (TCP), server, bottleneck link 100Mbps.
2. Run both flows for 60 seconds simultaneously.
3. Measure bandwidth share.

**Target**: NovaNet should not starve TCP (and vice versa). Rough fairness within 2:1 ratio is
acceptable for Phase 1.

---

### 3.9 CPU and Memory Usage

**What**: CPU and memory overhead of the NovaNet transport vs. TCP.

**Method**:
1. Run throughput test at 1 Gbps (loopback).
2. Measure CPU usage via `perf stat` and memory via `/proc/[pid]/status`.
3. Compare to equivalent TCP server.

**Expected**: NovaNet will use more CPU than kernel TCP (userspace vs. kernel). This is the cost
of the research prototype. The goal is to keep overhead reasonable (< 2x TCP CPU for single stream).

---

### 3.10 Mobility Recovery Time

**What**: How long does a session take to resume after a simulated IP address change?

**Method**:
1. Client establishes a session, begins streaming.
2. Script changes the client's IP address (simulated by changing netns veth IP and routing).
3. Measure the time from IP change to resumed data delivery.

**Expected**: < 1 RTT additional latency for pre-migrated path, < 3 RTT for reactive migration.

**Baselines**: TCP (sessions drop on IP change — recovery = reconnect + TLS renegotiation).

---

## 4. Benchmark Infrastructure

### 4.1 Criterion Setup

`/benches/Cargo.toml`:
```toml
[[bench]]
name = "packet_codec"
harness = false

[[bench]]
name = "throughput"
harness = false

[[bench]]
name = "retransmission"
harness = false
```

### 4.2 Results Storage

Each benchmark run produces:
```
/benches/results/
  {git_commit_short}_{date}_{preset}/
    handshake_latency.json
    rtt.json
    throughput.json
    loss_recovery.json
    cpu_memory.json
    system_info.json   # kernel version, CPU, RAM, NovaNet config
```

### 4.3 Comparison Script

`/scripts/run-benchmarks.sh` runs all benchmarks and produces a comparison report in Markdown.

---

## 5. What Benchmarks Cannot Tell Us

- **Real-world performance**: Localhost and netns avoid real network heterogeneity. Performance
  on the open Internet will differ significantly.
- **Scalability beyond one machine**: NovaNet's session table performance under 100K simultaneous
  sessions has not been tested in Phase 1.
- **Long-running stability**: Phase 1 benchmarks run for minutes, not days. Memory leaks and
  long-term performance degradation require extended soak tests.
- **Kernel TCP vs. userspace NovaNet fairness**: The comparison is not entirely fair because TCP
  benefits from kernel-level optimization (zero-copy, checksum offload, TSO). NovaNet is userspace
  only in Phase 1.

These limitations are acknowledged and will be addressed in later phases.
