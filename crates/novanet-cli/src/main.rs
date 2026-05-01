use anyhow::{bail, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use novanet_wire::codec::decode_packet;
use novanet_wire::packet::PacketPayload;
use novanet_wire::frame::Frame;

#[derive(Parser)]
#[command(name = "novanet", about = "NovaNet protocol CLI inspection tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode and pretty-print a NovaNet packet from hex bytes.
    Inspect {
        /// Hex-encoded packet bytes (e.g. "01101500...")
        hex: String,
    },
    /// Print protocol constants.
    Constants,
    /// Generate a new random session ID.
    NewSession,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("novanet=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { hex } => cmd_inspect(&hex)?,
        Commands::Constants => cmd_constants(),
        Commands::NewSession => cmd_new_session(),
    }

    Ok(())
}

fn cmd_inspect(hex: &str) -> Result<()> {
    let hex_clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_clean.len() % 2 != 0 {
        bail!("hex string has odd length");
    }

    let bytes_vec: Result<Vec<u8>, _> = (0..hex_clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_clean[i..i + 2], 16))
        .collect();
    let bytes_vec = bytes_vec.map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;

    let bytes = Bytes::from(bytes_vec);
    let packet = decode_packet(bytes).map_err(|e| anyhow::anyhow!("decode error: {}", e))?;

    println!("NovaNet Packet");
    println!("  version:     0x{:02X}", packet.header.version);
    println!("  type:        {} (0x{:02X})", packet.header.packet_type, packet.header.packet_type.as_byte());
    println!("  flags:       0x{:02X}", packet.header.flags);
    println!("  session_id:  {}", packet.header.session_id);
    println!("  path_id:     {}", packet.header.path_id);
    if let Some(pn) = packet.packet_number {
        println!("  packet_num:  {pn}");
    }

    match &packet.payload {
        PacketPayload::Hello(h) => {
            println!("  [HELLO]");
            println!("    node_id:    {}", h.client_node_id);
            println!("    service_id: {}", h.desired_service_id);
            println!("    versions:   {:?}", h.supported_versions);
            println!("    retry_tok:  {} bytes", h.retry_token.len());
        }
        PacketPayload::HandshakeDone => {
            println!("  [HANDSHAKE_DONE]");
        }
        PacketPayload::Data(frames) | PacketPayload::Ack(frames) => {
            println!("  [{}] {} frame(s):", packet.header.packet_type, frames.len());
            for frame in frames {
                print_frame(frame);
            }
        }
        PacketPayload::Close(c) => {
            println!("  [CLOSE] code=0x{:04X} reason={:?}",
                c.inner.error_code,
                String::from_utf8_lossy(&c.inner.reason));
        }
        PacketPayload::Error(e) => {
            println!("  [ERROR] code=0x{:04X} reason={:?}",
                e.inner.error_code,
                String::from_utf8_lossy(&e.inner.reason));
        }
        PacketPayload::PathChallenge(p) => {
            println!("  [PATH_CHALLENGE] data={:02X?}", p.data);
        }
        PacketPayload::PathResponse(p) => {
            println!("  [PATH_RESPONSE] data={:02X?}", p.data);
        }
        PacketPayload::Retry(r) => {
            println!("  [RETRY] token={} bytes", r.retry_token.len());
        }
        PacketPayload::Handshake(h) => {
            println!("  [HANDSHAKE] crypto_data={} bytes", h.crypto_data.len());
        }
        PacketPayload::Padding { count } => {
            println!("  [PADDING] {count} bytes");
        }
    }

    Ok(())
}

fn print_frame(frame: &Frame) {
    match frame {
        Frame::Stream(s) => {
            println!("    STREAM stream_id={} offset={} len={} fin={} prio={}",
                s.stream_id, s.offset, s.data.len(), s.fin, s.high_priority);
        }
        Frame::Ack(a) => {
            println!("    ACK largest={} delay={}us ranges={}",
                a.largest_acked, a.ack_delay_us, a.ranges.len());
        }
        Frame::Datagram(d) => {
            println!("    DATAGRAM len={}", d.data.len());
        }
        Frame::MaxData(m) => {
            println!("    MAX_DATA max={}", m.max_data);
        }
        Frame::MaxStreamData(m) => {
            println!("    MAX_STREAM_DATA stream={} max={}", m.stream_id, m.max_stream_data);
        }
        Frame::Padding => {
            println!("    PADDING");
        }
        Frame::PathChallenge(p) => {
            println!("    PATH_CHALLENGE data={:02X?}", p.data);
        }
        Frame::PathResponse(p) => {
            println!("    PATH_RESPONSE data={:02X?}", p.data);
        }
        Frame::Close(c) => {
            println!("    CLOSE code=0x{:04X}", c.error_code);
        }
        Frame::Error(e) => {
            println!("    ERROR code=0x{:04X}", e.error_code);
        }
    }
}

fn cmd_constants() {
    use novanet_core::constants::*;
    println!("NovaNet Protocol Constants");
    println!("  PROTOCOL_VERSION:         0x{PROTOCOL_VERSION:02X}");
    println!("  MAX_UDP_PAYLOAD:          {MAX_UDP_PAYLOAD} bytes");
    println!("  FIXED_HEADER_SIZE:        {FIXED_HEADER_SIZE} bytes");
    println!("  PACKET_NUMBER_SIZE:       {PACKET_NUMBER_SIZE} bytes");
    println!("  DATA_HEADER_SIZE:         {DATA_HEADER_SIZE} bytes");
    println!("  AEAD_TAG_SIZE:            {AEAD_TAG_SIZE} bytes");
    println!("  INITIAL_CWND:             {INITIAL_CWND} bytes ({} packets)",
        INITIAL_CWND / MAX_UDP_PAYLOAD);
    println!("  MIN_CWND:                 {MIN_CWND} bytes");
    println!("  INITIAL_RTT_MS:           {INITIAL_RTT_MS} ms");
    println!("  MAX_SESSION_IDLE:         {MAX_SESSION_IDLE_SECS} s");
    println!("  HANDSHAKE_TIMEOUT:        {HANDSHAKE_TIMEOUT_SECS} s");
    println!("  PATH_CHALLENGE_TIMEOUT:   {PATH_CHALLENGE_TIMEOUT_SECS} s");
    println!("  RETRY_TOKEN_LIFETIME:     {RETRY_TOKEN_LIFETIME_SECS} s");
    println!("  ANTI_AMPL_FACTOR:         {ANTI_AMPL_FACTOR}x");
}

fn cmd_new_session() {
    let id = novanet_core::SessionId::generate();
    println!("{id}");
}
