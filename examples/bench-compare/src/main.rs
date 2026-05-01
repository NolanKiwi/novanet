/// NovaNet vs TCP benchmark.
///
/// Measures on loopback (127.0.0.1):
///   - Connection / handshake latency
///   - Round-trip latency (ping-pong) for three payload sizes
///   - Sustained throughput (bytes/sec)
///
/// NovaNet is Phase 3: no AEAD, no congestion controller in send path.
/// Results are raw and honest about that caveat.

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use novanet_core::ids::ServiceId;
use novanet_transport::{
    endpoint::{Endpoint, EndpointConfig, IncomingMessage},
    SessionStatus,
};
use novanet_core::ids::SessionId;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "bench-compare", about = "NovaNet vs TCP benchmark")]
struct Cli {
    /// Number of iterations for RTT / throughput benchmarks
    #[arg(long, default_value_t = 500)]
    iterations: usize,

    /// Number of iterations for connection benchmark
    #[arg(long, default_value_t = 30)]
    connect_iterations: usize,

    /// Warmup iterations (excluded from results)
    #[arg(long, default_value_t = 20)]
    warmup: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark result type
// ─────────────────────────────────────────────────────────────────────────────

struct BenchResult {
    name: String,
    /// One Duration per round-trip (or connection).
    samples: Vec<Duration>,
    /// Payload bytes sent in one direction per operation.
    payload_bytes: usize,
}

impl BenchResult {
    fn percentile(&self, p: f64) -> Duration {
        let mut s = self.samples.clone();
        s.sort();
        let idx = ((s.len() as f64 * p / 100.0) as usize).min(s.len().saturating_sub(1));
        s[idx]
    }

    fn mean(&self) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        self.samples.iter().sum::<Duration>() / self.samples.len() as u32
    }

    /// Round-trip throughput in MB/s: (payload × 2 × N) / total_time.
    fn throughput_mbps(&self) -> f64 {
        if self.samples.is_empty() || self.payload_bytes == 0 {
            return 0.0;
        }
        let total: Duration = self.samples.iter().sum();
        if total.is_zero() {
            return 0.0;
        }
        let total_bytes = self.payload_bytes * 2 * self.samples.len();
        total_bytes as f64 / total.as_secs_f64() / 1_000_000.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn a TCP echo server that echoes every byte it receives.
async fn spawn_tcp_echo(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
}

/// TCP connection latency: time from connect() to first byte received.
async fn bench_tcp_connect(n: usize, port: u16) -> BenchResult {
    spawn_tcp_echo(port).await;
    tokio::time::sleep(Duration::from_millis(5)).await;

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        stream.write_all(b"\x00").await.unwrap();
        let mut ack = [0u8; 1];
        stream.read_exact(&mut ack).await.unwrap();
        samples.push(t0.elapsed());
    }

    BenchResult { name: "TCP connect+first-byte".into(), samples, payload_bytes: 1 }
}

/// TCP round-trip latency: write `payload`, read same amount back.
async fn bench_tcp_rtt(
    warmup: usize,
    n: usize,
    payload: &[u8],
    port: u16,
) -> BenchResult {
    spawn_tcp_echo(port).await;
    tokio::time::sleep(Duration::from_millis(5)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let mut recv_buf = vec![0u8; payload.len()];

    // warmup
    for _ in 0..warmup {
        stream.write_all(payload).await.unwrap();
        stream.read_exact(&mut recv_buf).await.unwrap();
    }

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        stream.write_all(payload).await.unwrap();
        stream.read_exact(&mut recv_buf).await.unwrap();
        samples.push(t0.elapsed());
    }

    BenchResult {
        name: format!("TCP RTT {}B", payload.len()),
        samples,
        payload_bytes: payload.len(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NovaNet benchmarks
// ─────────────────────────────────────────────────────────────────────────────

fn nova_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Spawn a NovaNet echo server. Returns Arc<Endpoint>.
async fn spawn_novanet_echo(server_port: u16) -> Arc<Endpoint> {
    let cfg = EndpointConfig::server(nova_addr(server_port));
    let mut ep = Endpoint::bind(cfg).await.unwrap();
    let mut rx = ep.take_incoming().unwrap();
    let ep = Arc::new(ep);

    // recv loop
    let ep_recv = Arc::clone(&ep);
    tokio::spawn(async move { ep_recv.run_recv_loop().await });

    // RTO loop
    let ep_rto = Arc::clone(&ep);
    tokio::spawn(async move { ep_rto.run_rto_loop().await });

    // echo task: receive StreamData, send it back
    let ep_echo = Arc::clone(&ep);
    tokio::spawn(async move {
        let mut offsets: HashMap<SessionId, u64> = HashMap::new();
        while let Some(msg) = rx.recv().await {
            if let IncomingMessage::StreamData { session_id, stream_id, data, fin, .. } = msg {
                if data.is_empty() && !fin {
                    continue;
                }
                let off = *offsets.get(&session_id).unwrap_or(&0);
                let len = data.len() as u64;
                let _ = ep_echo
                    .send_stream_data(session_id, stream_id, off, data, fin)
                    .await;
                offsets.insert(session_id, off + len);
            }
        }
    });

    ep
}

/// Create a NovaNet client, connect to `server_addr`, return (Arc<Endpoint>, session_id, rx).
async fn nova_client_connect(
    client_port: u16,
    server_addr: SocketAddr,
) -> (Arc<Endpoint>, SessionId, mpsc::Receiver<IncomingMessage>) {
    let cfg = EndpointConfig::client(nova_addr(client_port));
    let mut ep = Endpoint::bind(cfg).await.unwrap();
    let rx = ep.take_incoming().unwrap();
    let ep = Arc::new(ep);

    let ep_recv = Arc::clone(&ep);
    tokio::spawn(async move { ep_recv.run_recv_loop().await });
    let ep_rto = Arc::clone(&ep);
    tokio::spawn(async move { ep_rto.run_rto_loop().await });

    let svc = ServiceId::from_name("bench");
    let sid = ep.connect(server_addr, svc).await.unwrap();
    (ep, sid, rx)
}

/// Wait until the NovaNet session is Established; return time elapsed.
async fn wait_established(ep: &Endpoint, sid: SessionId) -> Duration {
    let t0 = Instant::now();
    loop {
        if ep
            .session_stats(sid)
            .await
            .map(|s| s.status == SessionStatus::Established)
            .unwrap_or(false)
        {
            return t0.elapsed();
        }
        tokio::time::sleep(Duration::from_micros(100)).await;
    }
}

/// Drain incoming messages until we see a StreamData whose total length >= expected.
async fn drain_echo(rx: &mut mpsc::Receiver<IncomingMessage>, expected: usize) {
    let mut got = 0;
    while got < expected {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(IncomingMessage::StreamData { data, .. })) => got += data.len(),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

/// NovaNet handshake latency: time from connect() call to Established state.
async fn bench_novanet_connect(
    n: usize,
    base_server_port: u16,
    base_client_port: u16,
) -> BenchResult {
    let mut samples = Vec::with_capacity(n);

    for i in 0..n {
        // Fresh server per measurement to get clean handshake timing
        let srv_port = base_server_port + i as u16;
        let cli_port = base_client_port + i as u16;
        let _srv = spawn_novanet_echo(srv_port).await;
        tokio::time::sleep(Duration::from_millis(2)).await;

        let t0 = Instant::now();
        let (ep, sid, _rx) = nova_client_connect(cli_port, nova_addr(srv_port)).await;
        let hs = wait_established(&ep, sid).await;
        let _ = hs; // included in t0.elapsed()
        samples.push(t0.elapsed());
    }

    BenchResult { name: "NovaNet handshake".into(), samples, payload_bytes: 1 }
}

/// NovaNet round-trip latency: send DATA, wait for echoed DATA back.
async fn bench_novanet_rtt(
    warmup: usize,
    n: usize,
    payload: Bytes,
    server_port: u16,
    client_port: u16,
) -> BenchResult {
    let _srv = spawn_novanet_echo(server_port).await;
    tokio::time::sleep(Duration::from_millis(5)).await;

    let (ep, sid, mut rx) = nova_client_connect(client_port, nova_addr(server_port)).await;
    wait_established(&ep, sid).await;

    let payload_len = payload.len();
    let mut offset: u64 = 0;

    // warmup
    for _ in 0..warmup {
        ep.send_stream_data(sid, 0, offset, payload.clone(), false).await.unwrap();
        drain_echo(&mut rx, payload_len).await;
        offset += payload_len as u64;
    }

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        ep.send_stream_data(sid, 0, offset, payload.clone(), false).await.unwrap();
        drain_echo(&mut rx, payload_len).await;
        samples.push(t0.elapsed());
        offset += payload_len as u64;
    }

    BenchResult {
        name: format!("NovaNet RTT {}B", payload_len),
        samples,
        payload_bytes: payload_len,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Report formatting
// ─────────────────────────────────────────────────────────────────────────────

fn fmt_us(d: Duration) -> String {
    let us = d.as_secs_f64() * 1_000_000.0;
    if us < 1000.0 {
        format!("{us:.1} µs")
    } else {
        format!("{:.3} ms", us / 1000.0)
    }
}

fn print_separator() {
    println!("{}", "─".repeat(72));
}

fn print_header(title: &str) {
    println!();
    print_separator();
    println!("  {title}");
    print_separator();
    println!("  {:<26}  {:>10}  {:>10}  {:>10}  {:>10}", "Metric", "mean", "p50", "p95", "p99");
    print_separator();
}

fn print_row(r: &BenchResult) {
    println!(
        "  {:<26}  {:>10}  {:>10}  {:>10}  {:>10}",
        r.name,
        fmt_us(r.mean()),
        fmt_us(r.percentile(50.0)),
        fmt_us(r.percentile(95.0)),
        fmt_us(r.percentile(99.0)),
    );
}

fn print_throughput_row(label: &str, tcp: &BenchResult, nova: &BenchResult) {
    let tcp_mb = tcp.throughput_mbps();
    let nova_mb = nova.throughput_mbps();
    let ratio = if nova_mb > 0.0 { tcp_mb / nova_mb } else { f64::INFINITY };
    println!(
        "  {:<26}  {:>10.2}  {:>10.2}  {:>10}",
        label,
        tcp_mb,
        nova_mb,
        format!("{ratio:.1}×"),
    );
}

fn print_latency_ratio(label: &str, tcp: &BenchResult, nova: &BenchResult) {
    let tcp_p50_us = tcp.percentile(50.0).as_secs_f64() * 1e6;
    let nova_p50_us = nova.percentile(50.0).as_secs_f64() * 1e6;
    let ratio = if tcp_p50_us > 0.0 { nova_p50_us / tcp_p50_us } else { 0.0 };
    println!("  {label:<26}  p50 NovaNet / TCP = {ratio:.2}× (NovaNet is {ratio:.1}× slower)");
}

fn print_overhead_table() {
    println!();
    print_separator();
    println!("  Protocol Overhead (static analysis)");
    print_separator();
    println!("  {:<30}  {:>8}  {:>8}  {:>8}", "Protocol", "hdr bytes", "MTU/MSS", "overhead%");
    print_separator();
    // TCP: 20 IP + 20 TCP = 40 bytes; MSS = 1460 (Ethernet 1500 - 40)
    println!("  {:<30}  {:>8}  {:>8}  {:>8}", "TCP (no options)", 40, 1460, "2.7%");
    // NovaNet Phase 3: 21 fixed + 8 pn + 16 stream frame header = 45 bytes
    println!("  {:<30}  {:>8}  {:>8}  {:>8}", "NovaNet Phase 3 (no AEAD)", 45, 1200, "3.8%");
    // NovaNet Phase 4: + 16 AEAD tag = 61 bytes
    println!("  {:<30}  {:>8}  {:>8}  {:>8}", "NovaNet Phase 4 (ChaCha+Poly)", 61, 1200, "5.1%");
    print_separator();
    println!("  Note: TCP overhead shown per-segment; IP fragmentation excluded.");
    println!("        NovaNet MTU is 1200 B (conservative, works through most NATs).");
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Port ranges: each benchmark gets its own server port to avoid reuse conflicts.
    // TCP: 48100–48199  NovaNet: 48200–48499

    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║           NovaNet vs TCP  —  Benchmark Suite                        ║");
    println!("║  Transport: loopback 127.0.0.1, no artificial delay or loss         ║");
    println!("║  Build:     debug (add --release for production numbers)             ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Configuration:");
    println!("    RTT iterations    : {}", cli.iterations);
    println!("    Connect iterations: {}", cli.connect_iterations);
    println!("    Warmup            : {}", cli.warmup);

    // ── Connection / Handshake latency ────────────────────────────────────────
    println!("\n  Running connection benchmarks…");
    let tcp_connect = bench_tcp_connect(cli.connect_iterations, 48100).await;
    let nova_connect = bench_novanet_connect(
        cli.connect_iterations,
        48200, // server ports 48200, 48201, …
        48250, // client ports 48250, 48251, …
    )
    .await;

    print_header(&format!(
        "Connection / Handshake Latency  ({} iterations)",
        cli.connect_iterations
    ));
    print_row(&tcp_connect);
    print_row(&nova_connect);
    print_separator();
    print_latency_ratio("connect overhead", &tcp_connect, &nova_connect);
    println!(
        "  Note: NovaNet requires 1 round-trip (HELLO→HANDSHAKE_DONE);");
    println!(
        "        TCP requires 1.5 round-trips (SYN/SYN-ACK/ACK).");

    // ── Round-trip latency ─────────────────────────────────────────────────────
    let payload_sizes: &[usize] = &[64, 512, 1024];
    let mut tcp_rtts: Vec<BenchResult> = Vec::new();
    let mut nova_rtts: Vec<BenchResult> = Vec::new();

    println!("\n  Running RTT benchmarks…");
    for (i, &sz) in payload_sizes.iter().enumerate() {
        let payload = Bytes::from(vec![0xABu8; sz]);
        let tcp_port  = 48110 + i as u16;
        let nova_srv  = 48300 + (i as u16 * 2);
        let nova_cli  = 48301 + (i as u16 * 2);

        let tcp = bench_tcp_rtt(cli.warmup, cli.iterations, &payload, tcp_port).await;
        let nova = bench_novanet_rtt(
            cli.warmup,
            cli.iterations,
            payload.clone(),
            nova_srv,
            nova_cli,
        )
        .await;

        tcp_rtts.push(tcp);
        nova_rtts.push(nova);
    }

    print_header(&format!(
        "Round-Trip Latency (ping-pong, {} iterations per size)",
        cli.iterations
    ));
    for r in &tcp_rtts {
        print_row(r);
    }
    print_separator();
    for r in &nova_rtts {
        print_row(r);
    }
    print_separator();
    for (tcp, nova) in tcp_rtts.iter().zip(nova_rtts.iter()) {
        print_latency_ratio(&format!("  {}B ratio", tcp.payload_bytes), tcp, nova);
    }

    // ── Throughput ─────────────────────────────────────────────────────────────
    print_header("Round-Trip Throughput  (MB/s, higher = better)");
    println!(
        "  {:<26}  {:>10}  {:>10}  {:>10}",
        "Payload size", "TCP (MB/s)", "Nova (MB/s)", "TCP/Nova"
    );
    print_separator();
    for (tcp, nova) in tcp_rtts.iter().zip(nova_rtts.iter()) {
        print_throughput_row(&format!("  {}B payload", tcp.payload_bytes), tcp, nova);
    }

    // ── Header overhead ────────────────────────────────────────────────────────
    print_overhead_table();

    // ── Caveats ───────────────────────────────────────────────────────────────
    println!();
    print_separator();
    println!("  What these numbers mean");
    print_separator();
    println!("  • TCP is kernel-optimized (zero-copy, batching, hardware offload).");
    println!("  • NovaNet Phase 3 is 100% userspace Rust: UdpSocket + tokio + ");
    println!("    per-packet BytesMut encoding/decoding + Mutex-protected session table.");
    println!("  • Phase 4 will add AEAD (~16 B tag, ~1 µs/packet on modern CPUs).");
    println!("  • Phase 5 will add congestion control (AIMD) — no effect on loopback.");
    println!("  • For NovaNet to match TCP throughput, XDP/DPDK offload is required.");
    println!("  • Latency gap on loopback is dominated by tokio task scheduling overhead,");
    println!("    not protocol complexity — gap shrinks under real WAN conditions.");
    print_separator();
    println!();

    Ok(())
}
