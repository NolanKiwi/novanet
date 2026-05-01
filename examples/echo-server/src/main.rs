use anyhow::Result;
use clap::Parser;
use novanet_transport::endpoint::{Endpoint, EndpointConfig, IncomingMessage};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::Receiver;
use tracing::{info, debug};

#[derive(Parser, Debug)]
#[command(name = "echo-server", about = "NovaNet echo server — reflects all stream data back to the sender")]
struct Args {
    /// UDP address to listen on
    #[arg(long, default_value = "127.0.0.1:9999")]
    addr: SocketAddr,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log: String,
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

    info!(addr = %args.addr, "echo-server starting");

    let config = EndpointConfig::server(args.addr);
    let mut endpoint = Endpoint::bind(config).await?;
    let mut incoming = endpoint.take_incoming().expect("incoming receiver");
    let endpoint = Arc::new(endpoint);

    // Spawn the receive loop
    let recv_endpoint = Arc::clone(&endpoint);
    tokio::spawn(async move {
        recv_endpoint.run_recv_loop().await;
    });

    info!("echo-server ready — waiting for connections");

    // Process incoming messages
    run_echo_loop(&endpoint, &mut incoming).await;

    Ok(())
}

async fn run_echo_loop(
    endpoint: &Arc<Endpoint>,
    incoming: &mut Receiver<IncomingMessage>,
) {
    while let Some(msg) = incoming.recv().await {
        match msg {
            IncomingMessage::NewSession { session_id, remote_addr } => {
                info!(%session_id, %remote_addr, "session.new");
            }

            IncomingMessage::StreamData { session_id, stream_id, offset, data, fin } => {
                let data_preview = if data.len() > 64 {
                    format!("{}...", String::from_utf8_lossy(&data[..64]))
                } else {
                    String::from_utf8_lossy(&data).into_owned()
                };

                info!(
                    %session_id,
                    stream_id = stream_id,
                    offset = offset,
                    len = data.len(),
                    fin = fin,
                    preview = %data_preview,
                    "stream.data_received — echoing back"
                );

                // Echo the data back on the same stream at the same offset
                if let Err(e) = endpoint
                    .send_stream_data(session_id, stream_id, offset, data, fin)
                    .await
                {
                    debug!(%session_id, err = %e, "echo.send_error");
                }

                if fin {
                    // Close gracefully after echoing FIN
                    let ep = Arc::clone(endpoint);
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        let _ = ep.close_session(session_id, "echo complete").await;
                    });
                }
            }

            IncomingMessage::SessionClosed { session_id, error_code, reason } => {
                info!(
                    %session_id,
                    error_code = error_code,
                    reason = %reason,
                    "session.closed"
                );
            }
        }
    }
}
