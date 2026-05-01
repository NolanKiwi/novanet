/// Phase 4 integration tests: authenticated and encrypted sessions.
///
/// These tests verify:
///   - Full crypto handshake (X25519 + HKDF + Ed25519) completes
///   - DATA packets are AEAD-encrypted end-to-end
///   - A man-in-the-middle that tampers with data cannot forge valid packets
///   - Congestion control enforces the window (Phase 5)

use bytes::Bytes;
use novanet_core::ids::ServiceId;
use novanet_transport::endpoint::{Endpoint, EndpointConfig, IncomingMessage};
use std::{net::SocketAddr, sync::Arc};
use std::time::Duration;

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

async fn wait_established(client: &Arc<Endpoint>, session_id: novanet_core::ids::SessionId) {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if let Some(stats) = client.session_stats(session_id).await {
            if stats.status == novanet_transport::SessionStatus::Established {
                return;
            }
        }
    }
}

// ─── Test 1: Encrypted echo — end-to-end ─────────────────────────────────────
//
// Server has a static keypair → HANDSHAKE flow with real crypto.
// Client sends data; server receives it through the encrypted channel.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn encrypted_echo_end_to_end() {
    let server_port = 40001u16;
    let client_port = 40002u16;

    let srv_cfg = EndpointConfig::server_with_crypto(addr(server_port));
    let mut server = Endpoint::bind(srv_cfg).await.unwrap();
    let mut server_rx = server.take_incoming().unwrap();
    let server = Arc::new(server);
    let srv_recv = Arc::clone(&server);
    tokio::spawn(async move { srv_recv.run_recv_loop().await });

    let cli_cfg = EndpointConfig::client(addr(client_port));
    let mut client = Endpoint::bind(cli_cfg).await.unwrap();
    let _client_rx = client.take_incoming().unwrap();
    let client = Arc::new(client);
    let cli_recv = Arc::clone(&client);
    tokio::spawn(async move { cli_recv.run_recv_loop().await });

    let svc = ServiceId::from_name("encrypted-echo");
    let session_id = client.connect(addr(server_port), svc).await.unwrap();

    // Wait for crypto handshake to complete
    wait_established(&client, session_id).await;

    let stats = client.session_stats(session_id).await.expect("session must exist");
    assert_eq!(
        stats.status,
        novanet_transport::SessionStatus::Established,
        "client must be established"
    );
    assert!(stats.has_crypto, "session must have derived AEAD keys");

    // Send encrypted data
    let payload = Bytes::from_static(b"hello encrypted novanet world");
    client
        .send_stream_data(session_id, 0, 0, payload.clone(), true)
        .await
        .unwrap();

    // Wait for server to receive it
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match server_rx.recv().await {
                Some(IncomingMessage::StreamData { data, fin: true, .. }) => return Some(data),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .expect("timeout: server did not receive encrypted data")
    .expect("server channel closed");

    assert_eq!(
        received.as_ref(),
        payload.as_ref(),
        "decrypted payload must match original"
    );
}

// ─── Test 2: MitM data tampering is rejected ──────────────────────────────────
//
// A proxy flips a bit in every DATA packet from client to server.
// The server's AEAD tag check must fail → data is silently dropped.
// The server must NOT deliver any StreamData messages.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn mitm_tampered_data_is_rejected() {
    use tokio::net::UdpSocket;

    let server_port = 40010u16;
    let proxy_port  = 40011u16;
    let client_port = 40012u16;

    let srv_cfg = EndpointConfig::server_with_crypto(addr(server_port));
    let mut server = Endpoint::bind(srv_cfg).await.unwrap();
    let mut server_rx = server.take_incoming().unwrap();
    let server = Arc::new(server);
    let srv_recv = Arc::clone(&server);
    tokio::spawn(async move { srv_recv.run_recv_loop().await });

    // Proxy: forwards everything but flips a byte in DATA payloads (client→server)
    let proxy_sock = Arc::new(UdpSocket::bind(addr(proxy_port)).await.unwrap());
    let proxy_sock2 = Arc::clone(&proxy_sock);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        let mut client_addr: Option<SocketAddr> = None;
        loop {
            let Ok((len, from)) = proxy_sock2.recv_from(&mut buf).await else { break };
            let pkt = &mut buf[..len];

            if from == addr(server_port) {
                // Server → client: forward unchanged
                if let Some(ca) = client_addr {
                    let _ = proxy_sock2.send_to(pkt, ca).await;
                }
            } else {
                client_addr = Some(from);
                // Client → server: tamper with DATA packets (type byte 0x10)
                if pkt.len() > 30 && pkt[1] == 0x10 {
                    pkt[30] ^= 0xFF; // flip bits in the encrypted payload
                }
                let _ = proxy_sock2.send_to(pkt, addr(server_port)).await;
            }
        }
    });

    let cli_cfg = EndpointConfig::client(addr(client_port));
    let mut client = Endpoint::bind(cli_cfg).await.unwrap();
    let _cli_rx = client.take_incoming().unwrap();
    let client = Arc::new(client);
    let cli_recv = Arc::clone(&client);
    tokio::spawn(async move { cli_recv.run_recv_loop().await });

    let svc = ServiceId::from_name("mitm-test");
    let session_id = client.connect(addr(proxy_port), svc).await.unwrap();
    wait_established(&client, session_id).await;

    // Send through proxy (DATA will be tampered)
    client
        .send_stream_data(session_id, 0, 0, Bytes::from_static(b"tamper me"), false)
        .await
        .unwrap();

    // Give enough time for delivery; server must NOT receive valid data
    let result = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            match server_rx.recv().await {
                Some(IncomingMessage::StreamData { .. }) => return true, // unexpected!
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await;

    assert!(
        result.is_err(),
        "server must not receive data from tampered (AEAD-rejected) packets"
    );
}

// ─── Test 3: Congestion window enforcement ────────────────────────────────────
//
// With a brand-new session (no RTT updates), the AIMD controller starts with
// INITIAL_CWND = 10 × 1200 = 12 000 bytes.  Sending > 10 full-size packets
// without ACKs must trigger a ResourceLimit error.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn congestion_window_blocks_oversized_burst() {
    let server_port = 40020u16;
    let client_port = 40021u16;

    // Server with no-crypto so the handshake is just one RTT (faster test)
    let srv_cfg = EndpointConfig::server(addr(server_port));
    let mut server = Endpoint::bind(srv_cfg).await.unwrap();
    let _srv_rx = server.take_incoming().unwrap();
    let server = Arc::new(server);
    let srv_recv = Arc::clone(&server);
    tokio::spawn(async move { srv_recv.run_recv_loop().await });

    let cli_cfg = EndpointConfig::client(addr(client_port));
    let mut client = Endpoint::bind(cli_cfg).await.unwrap();
    let _cli_rx = client.take_incoming().unwrap();
    let client = Arc::new(client);
    let cli_recv = Arc::clone(&client);
    tokio::spawn(async move { cli_recv.run_recv_loop().await });

    let svc = ServiceId::from_name("cc-test");
    let session_id = client.connect(addr(server_port), svc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send packets up to and beyond the initial congestion window
    let payload = Bytes::from(vec![0u8; 1150]); // ~1164 bytes with frame header
    let mut congestion_hit = false;

    for i in 0..15u64 {
        match client
            .send_stream_data(session_id, 0, i * 1150, payload.clone(), false)
            .await
        {
            Ok(()) => {}
            Err(novanet_core::error::NovaError::ResourceLimit(_)) => {
                congestion_hit = true;
                break;
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert!(
        congestion_hit,
        "congestion window must eventually block further sends (INITIAL_CWND = 12 000 bytes)"
    );
}
