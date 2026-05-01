use anyhow::{bail, Result};
use bytes::Bytes;
use clap::Parser;
use novanet_core::ids::ServiceId;
use novanet_transport::endpoint::{Endpoint, EndpointConfig, IncomingMessage};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::timeout;
use tracing::{info, debug, warn};

#[derive(Parser, Debug)]
#[command(name = "echo-client", about = "NovaNet echo client — sends a message and prints the echo")]
struct Args {
    /// Remote server address
    #[arg(long, default_value = "127.0.0.1:9999")]
    server: SocketAddr,

    /// Local bind address
    #[arg(long, default_value = "127.0.0.1:0")]
    local: SocketAddr,

    /// Message to echo
    #[arg(long, default_value = "Hello from NovaNet!")]
    message: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log: String,

    /// Timeout in milliseconds waiting for echo response
    #[arg(long, default_value = "2000")]
    timeout_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(args.log.parse()?)
                .from_env_lossy(),
        )
        .init();

    info!(server = %args.server, "echo-client starting");

    let config = EndpointConfig::client(args.local);
    let mut endpoint = Endpoint::bind(config).await?;
    let mut incoming = endpoint.take_incoming().expect("incoming receiver");
    let endpoint = Arc::new(endpoint);

    // Spawn receive loop
    let recv_endpoint = Arc::clone(&endpoint);
    tokio::spawn(async move {
        recv_endpoint.run_recv_loop().await;
    });

    // Connect and send
    let svc = ServiceId::from_name("echo");
    let session_id = endpoint.connect(args.server, svc).await?;
    info!(%session_id, "session.initiated");

    // Wait briefly for handshake
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Check if established
    let stats = endpoint.session_stats(session_id).await;
    debug!(?stats, "session stats after handshake");

    // Send the message
    info!(message = %args.message, "sending message");
    endpoint
        .send_stream_data(
            session_id,
            0,         // stream_id 0
            0,         // offset 0
            Bytes::from(args.message.clone()),
            true,      // fin=true (single message stream)
        )
        .await?;

    // Wait for echo response
    let echo = timeout(
        Duration::from_millis(args.timeout_ms),
        wait_for_echo(&mut incoming, session_id),
    )
    .await;

    match echo {
        Ok(Ok(received)) => {
            let received_str = String::from_utf8_lossy(&received);
            println!("Echo received: {received_str}");
            if received == Bytes::from(args.message.clone()) {
                info!("✓ Echo matches sent message");
            } else {
                warn!("Echo does not match sent message!");
            }
        }
        Ok(Err(e)) => bail!("Error receiving echo: {e}"),
        Err(_) => bail!("Timeout waiting for echo after {}ms", args.timeout_ms),
    }

    endpoint.close_session(session_id, "done").await?;
    info!(%session_id, "session.closed");

    Ok(())
}

async fn wait_for_echo(
    incoming: &mut tokio::sync::mpsc::Receiver<IncomingMessage>,
    session_id: novanet_core::ids::SessionId,
) -> Result<Bytes> {
    let mut received_chunks: Vec<Bytes> = Vec::new();

    loop {
        match incoming.recv().await {
            None => bail!("incoming channel closed"),
            Some(IncomingMessage::StreamData { session_id: sid, data, fin, .. }) if sid == session_id => {
                received_chunks.push(data);
                if fin {
                    // Concatenate all chunks
                    let total: usize = received_chunks.iter().map(|b| b.len()).sum();
                    let mut out = bytes::BytesMut::with_capacity(total);
                    for chunk in received_chunks {
                        use bytes::BufMut;
                        out.put(chunk);
                    }
                    return Ok(out.freeze());
                }
            }
            Some(IncomingMessage::SessionClosed { session_id: sid, reason, .. }) if sid == session_id => {
                bail!("session closed by server: {reason}");
            }
            Some(_) => {
                // Other session events; keep waiting
            }
        }
    }
}
