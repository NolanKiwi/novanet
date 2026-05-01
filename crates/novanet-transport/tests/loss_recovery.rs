/// Integration tests for Phase 3 reliability: RTO retransmission and loss recovery.
///
/// Architecture: a "lossy proxy" UDP task sits between client and server.
///
///   Client ──fwd──▶ Proxy ──fwd──▶ Server
///          ◀──rev──         ◀──rev──
///
/// Each direction has its own filter: packets can be delivered or dropped.

use bytes::Bytes;
use novanet_core::ids::ServiceId;
use novanet_sim::{LinkConfig, PacketDecision, SimulatedLink};
use novanet_transport::endpoint::{Endpoint, EndpointConfig, IncomingMessage};
use std::{net::SocketAddr, sync::Arc};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::UdpSocket;
use std::time::Duration;

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Spawn a bidirectional proxy UDP task.
///
/// - Packets from *client* direction → filtered by `fwd` (true = forward, false = drop)
/// - Packets from *server* direction → filtered by `rev` (true = forward, false = drop)
///
/// The proxy learns the client address from the first non-server packet it receives.
async fn spawn_proxy(
    proxy_port: u16,
    server: SocketAddr,
    fwd: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    rev: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
) -> SocketAddr {
    let sock = UdpSocket::bind(addr(proxy_port)).await.unwrap();
    let proxy_bound = sock.local_addr().unwrap();
    let sock = Arc::new(sock);
    let fwd = Arc::new(fwd);
    let rev = Arc::new(rev);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1400];
        let mut client_addr: Option<SocketAddr> = None;

        loop {
            let Ok((len, from)) = sock.recv_from(&mut buf).await else { break };
            let pkt = &buf[..len];

            if from == server {
                // Server → client direction
                if rev(pkt) {
                    if let Some(ca) = client_addr {
                        let _ = sock.send_to(pkt, ca).await;
                    }
                }
            } else {
                // Client → server direction
                client_addr = Some(from);
                if fwd(pkt) {
                    let _ = sock.send_to(pkt, server).await;
                }
            }
        }
    });

    proxy_bound
}

// packet type byte positions
const PKT_TYPE_BYTE: usize = 1;
const DATA_TYPE:     u8 = 0x10;
const ACK_TYPE:      u8 = 0x11;

fn is_data(pkt: &[u8]) -> bool { pkt.get(PKT_TYPE_BYTE).copied() == Some(DATA_TYPE) }
fn is_ack(pkt: &[u8])  -> bool { pkt.get(PKT_TYPE_BYTE).copied() == Some(ACK_TYPE) }

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: RTO fires when ACKs are suppressed
//
// Proxy passes all DATA client→server but drops all ACK server→client.
// After 1 initial-RTO cycle (~1 s) the client must show retransmissions > 0.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn rto_fires_on_unacked_data() {
    let server_port = 39901u16;
    let proxy_port  = 39902u16;
    let client_port = 39903u16;

    // Real server (receives DATA, tries to ACK — but ACKs are dropped by proxy)
    let srv_cfg = EndpointConfig::server(addr(server_port));
    let mut server = Endpoint::bind(srv_cfg).await.unwrap();
    let _srv_rx = server.take_incoming().unwrap();
    let server = Arc::new(server);
    let srv_recv = Arc::clone(&server);
    tokio::spawn(async move { srv_recv.run_recv_loop().await });

    // Proxy: DATA goes through, ACKs from server are dropped
    let proxy_addr = spawn_proxy(
        proxy_port,
        addr(server_port),
        |pkt| { let _ = pkt; true },          // forward all client→server
        |pkt| !is_ack(pkt),                   // drop ACKs server→client
    ).await;

    // Client
    let cli_cfg = EndpointConfig::client(addr(client_port));
    let mut client = Endpoint::bind(cli_cfg).await.unwrap();
    let _cli_rx = client.take_incoming().unwrap();
    let client = Arc::new(client);

    let c_recv = Arc::clone(&client);
    tokio::spawn(async move { c_recv.run_recv_loop().await });
    let c_rto = Arc::clone(&client);
    tokio::spawn(async move { c_rto.run_rto_loop().await });

    // Connect through proxy (HELLO = 0x01, HANDSHAKE_DONE = 0x04 — both pass the ACK filter)
    let svc = ServiceId::from_name("rto-test");
    let session_id = client.connect(proxy_addr, svc).await.unwrap();

    // Wait for handshake to complete (~1 RTT over loopback)
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Send data — server receives it and sends ACK, but proxy drops the ACK
    client
        .send_stream_data(session_id, 0, 0, Bytes::from("rto test payload"), false)
        .await
        .unwrap();

    // Initial RTO ≈ srtt + 4·rttvar = 333ms + 4·166ms ≈ 997ms.
    // Wait 1 600ms — enough for at least one RTO cycle plus the 50ms timer tick.
    tokio::time::sleep(Duration::from_millis(1600)).await;

    let stats = client
        .session_stats(session_id)
        .await
        .expect("session must still exist");

    assert!(
        stats.retransmissions > 0,
        "expected ≥1 retransmission after 1.6 s with ACKs suppressed, got {}",
        stats.retransmissions
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: End-to-end loss recovery via RTO
//
// The proxy drops the first DATA packet from client to server. The client's RTO
// fires (~1 s), retransmits, and the data reaches the server. The server emits
// an IncomingMessage::StreamData that we must receive within the test timeout.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn proxy_loss_data_recovered() {
    let server_port = 39910u16;
    let proxy_port  = 39911u16;
    let client_port = 39912u16;

    // Server
    let srv_cfg = EndpointConfig::server(addr(server_port));
    let mut server = Endpoint::bind(srv_cfg).await.unwrap();
    let mut server_rx = server.take_incoming().unwrap();
    let server = Arc::new(server);
    let srv_recv = Arc::clone(&server);
    tokio::spawn(async move { srv_recv.run_recv_loop().await });

    // Proxy: drop the first DATA packet only; let everything else through both ways
    let drop_count = Arc::new(AtomicU32::new(1)); // drop 1 DATA packet
    let drop_count_clone = Arc::clone(&drop_count);

    let proxy_addr = spawn_proxy(
        proxy_port,
        addr(server_port),
        move |pkt| {
            if is_data(pkt) {
                let remaining = drop_count_clone.load(Ordering::Relaxed);
                if remaining > 0 {
                    drop_count_clone.fetch_sub(1, Ordering::Relaxed);
                    return false; // drop
                }
            }
            true // forward
        },
        |_pkt| true, // forward all server→client (ACKs pass through)
    ).await;

    // Client
    let cli_cfg = EndpointConfig::client(addr(client_port));
    let mut client = Endpoint::bind(cli_cfg).await.unwrap();
    let _cli_rx = client.take_incoming().unwrap();
    let client = Arc::new(client);

    let c_recv = Arc::clone(&client);
    tokio::spawn(async move { c_recv.run_recv_loop().await });
    let c_rto = Arc::clone(&client);
    tokio::spawn(async move { c_rto.run_rto_loop().await });

    // Handshake through proxy (HELLO / HANDSHAKE_DONE are not DATA, pass through)
    let svc = ServiceId::from_name("loss-recovery");
    let session_id = client.connect(proxy_addr, svc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Send payload — first attempt is dropped; RTO (~1 s) triggers retransmit
    let payload = Bytes::from("NovaNet loss recovery works");
    client
        .send_stream_data(session_id, 0, 0, payload.clone(), true)
        .await
        .unwrap();

    // Allow up to 3 s: 1 s initial RTO + 50ms timer granularity + loopback RTT
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match server_rx.recv().await {
                Some(IncomingMessage::StreamData { data, fin: true, .. }) => return Some(data),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await;

    let received = result
        .expect("timed out — data never arrived after RTO retransmit (check initial RTO vs timeout)")
        .expect("server channel closed unexpectedly");

    assert_eq!(
        received.as_ref(),
        payload.as_ref(),
        "payload must survive drop+retransmit intact"
    );

    let stats = client.session_stats(session_id).await.unwrap();
    assert!(
        stats.retransmissions > 0,
        "expected retransmissions counter > 0, got 0"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// novanet-sim unit tests: SimulatedLink behaviour
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sim_link_perfect_passes_all() {
    let link = SimulatedLink::new(LinkConfig::perfect());
    for _ in 0..200 {
        assert!(
            matches!(link.process_packet(), PacketDecision::Deliver { .. }),
            "perfect link must never drop"
        );
    }
}

#[test]
fn sim_link_lossy_drops_some() {
    let link = SimulatedLink::new(LinkConfig::lossy());
    let drops = (0..2000)
        .filter(|_| link.process_packet() == PacketDecision::Drop)
        .count();
    // lossy preset: 2% loss → expect 5–200 drops in 2000 trials (3σ headroom)
    assert!(drops > 0,   "expected some drops on lossy link, got {drops}");
    assert!(drops < 200, "expected most packets to pass on lossy link, got {drops} drops");
}
