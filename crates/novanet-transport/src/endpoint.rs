use bytes::{Bytes, BytesMut};
use novanet_core::{
    constants::{FIXED_HEADER_SIZE, HANDSHAKE_TIMEOUT_SECS, MAX_UDP_PAYLOAD},
    error::{NovaError, NovaResult},
    ids::{PathId, ServiceId, SessionId},
    PacketType,
};
use novanet_wire::{
    codec::{decode_packet, encode_packet},
    frame::{AckFrame, AckRange, CloseFrame, Frame, StreamFrame},
    header::PacketHeader,
    packet::{ClosePayload, HelloPayload, NovaPacket, PacketPayload},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Mutex};
use tracing::{debug, info, warn};

use crate::retransmit::UnackedPacket;
use crate::session::{SessionState, SessionStatus};

/// Configuration for a NovaNet endpoint.
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// Bind address (e.g., "0.0.0.0:9999").
    pub bind_addr: SocketAddr,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
    /// Handshake timeout.
    pub handshake_timeout: Duration,
    /// Whether to act as a server (accept inbound sessions).
    pub is_server: bool,
}

impl EndpointConfig {
    pub fn server(addr: SocketAddr) -> Self {
        EndpointConfig {
            bind_addr: addr,
            max_sessions: 1024,
            handshake_timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            is_server: true,
        }
    }

    pub fn client(addr: SocketAddr) -> Self {
        EndpointConfig {
            bind_addr: addr,
            max_sessions: 64,
            handshake_timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            is_server: false,
        }
    }
}

/// A message delivered to the application from a NovaNet session.
#[derive(Debug)]
pub enum IncomingMessage {
    /// Stream data from a peer.
    StreamData {
        session_id: SessionId,
        stream_id: u32,
        offset: u64,
        data: Bytes,
        fin: bool,
    },
    /// A new session was established (server side).
    NewSession {
        session_id: SessionId,
        remote_addr: SocketAddr,
    },
    /// A session was closed.
    SessionClosed {
        session_id: SessionId,
        error_code: u16,
        reason: String,
    },
}

/// A shared session table protected by a tokio Mutex.
type SessionTable = Arc<Mutex<HashMap<SessionId, SessionState>>>;

/// A NovaNet UDP endpoint.
///
/// In Phase 2: handles HELLO, DATA (stream frames), ACK, CLOSE.
/// No encryption. Unauthenticated.
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    config: EndpointConfig,
    sessions: SessionTable,
    incoming_tx: tokio::sync::mpsc::Sender<IncomingMessage>,
    incoming_rx: Option<tokio::sync::mpsc::Receiver<IncomingMessage>>,
}

impl Endpoint {
    /// Create a new endpoint bound to the address in config.
    pub async fn bind(config: EndpointConfig) -> NovaResult<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        info!(
            addr = %config.bind_addr,
            mode = if config.is_server { "server" } else { "client" },
            "endpoint.bound"
        );

        let (tx, rx) = tokio::sync::mpsc::channel(256);

        Ok(Endpoint {
            socket: Arc::new(socket),
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            incoming_tx: tx,
            incoming_rx: Some(rx),
        })
    }

    /// Take the incoming message receiver. Can only be called once.
    pub fn take_incoming(&mut self) -> Option<tokio::sync::mpsc::Receiver<IncomingMessage>> {
        self.incoming_rx.take()
    }

    /// Initiate a new session to a remote endpoint (client side).
    ///
    /// Returns the SessionId of the new session.
    pub async fn connect(&self, remote_addr: SocketAddr, service: ServiceId) -> NovaResult<SessionId> {
        let session_id = SessionId::generate();

        let mut session = SessionState::new(session_id);
        session.remote_addr = Some(remote_addr);
        session.transition(SessionStatus::Handshaking);

        let hello = self.build_hello_packet(session_id, service);
        let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD);
        encode_packet(&hello, &mut buf)?;
        let bytes = buf.freeze();

        self.socket.send_to(&bytes, remote_addr).await?;
        debug!(
            session_id = %session_id,
            remote_addr = %remote_addr,
            "session.hello_sent"
        );

        let mut table = self.sessions.lock().await;
        table.insert(session_id, session);

        Ok(session_id)
    }

    /// Send stream data to a session.
    pub async fn send_stream_data(
        &self,
        session_id: SessionId,
        stream_id: u32,
        offset: u64,
        data: Bytes,
        fin: bool,
    ) -> NovaResult<()> {
        let frame = Frame::Stream(StreamFrame {
            stream_id,
            offset,
            fin,
            high_priority: false,
            data: data.clone(),
        });
        let byte_count = data.len() + 14; // approximate stream frame header overhead

        let (remote_addr, pn) = {
            let mut table = self.sessions.lock().await;
            let session = table
                .get_mut(&session_id)
                .ok_or(NovaError::SessionNotFound)?;
            if !session.is_established() {
                return Err(NovaError::InvalidSessionState("not established"));
            }
            let pn = session.next_packet_number();
            session.bytes_sent += data.len() as u64;
            session.packets_sent += 1;
            session.touch();
            let remote_addr = session.remote_addr.ok_or(NovaError::SessionNotFound)?;
            let path_id = session.active_path;

            session.retransmit.push(UnackedPacket {
                packet_number: pn,
                path_id,
                send_time: Instant::now(),
                frames: vec![frame.clone()],
                byte_count,
            });

            (remote_addr, pn)
        };

        let packet = self.build_data_packet(session_id, pn, vec![frame]);
        let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD);
        encode_packet(&packet, &mut buf)?;
        self.socket.send_to(&buf, remote_addr).await?;

        debug!(
            session_id = %session_id,
            pn = pn,
            stream_id = stream_id,
            "packet.sent"
        );

        Ok(())
    }

    /// Close a session gracefully.
    pub async fn close_session(&self, session_id: SessionId, reason: &str) -> NovaResult<()> {
        let (remote_addr, pn) = {
            let mut table = self.sessions.lock().await;
            let session = table
                .get_mut(&session_id)
                .ok_or(NovaError::SessionNotFound)?;
            if session.is_closed() {
                return Ok(());
            }
            let pn = session.next_packet_number();
            session.transition(SessionStatus::Draining);
            (session.remote_addr.ok_or(NovaError::SessionNotFound)?, pn)
        };

        let packet = self.build_close_packet(session_id, pn, 0x0000, reason);
        let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD);
        encode_packet(&packet, &mut buf)?;
        self.socket.send_to(&buf, remote_addr).await?;

        let mut table = self.sessions.lock().await;
        if let Some(s) = table.get_mut(&session_id) {
            s.transition(SessionStatus::Closed);
        }

        info!(session_id = %session_id, reason = reason, "session.closed");
        Ok(())
    }

    /// Run the receive loop. This task runs indefinitely and processes incoming packets.
    /// Should be spawned with `tokio::spawn`.
    pub async fn run_recv_loop(&self) {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD + 8]; // +8 for UDP header

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, remote_addr)) => {
                    let data = Bytes::copy_from_slice(&buf[..len]);
                    if let Err(e) = self.handle_incoming(data, remote_addr).await {
                        warn!(err = %e, from = %remote_addr, "packet.handle_error");
                    }
                }
                Err(e) => {
                    warn!(err = %e, "socket.recv_error");
                    // Don't exit the loop on a receive error — the socket is still valid
                }
            }
        }
    }

    /// Process a single incoming UDP payload.
    async fn handle_incoming(&self, data: Bytes, remote_addr: SocketAddr) -> NovaResult<()> {
        if data.len() < FIXED_HEADER_SIZE {
            debug!(from = %remote_addr, len = data.len(), "packet.too_short");
            return Ok(());
        }

        let packet = match decode_packet(data) {
            Ok(p) => p,
            Err(e) => {
                debug!(from = %remote_addr, err = %e, "packet.decode_error");
                return Ok(());
            }
        };

        debug!(
            session_id = %packet.header.session_id,
            pkt_type = %packet.header.packet_type,
            from = %remote_addr,
            "packet.received"
        );

        match packet.header.packet_type {
            PacketType::Hello => {
                self.handle_hello(packet, remote_addr).await?;
            }
            PacketType::HandshakeDone => {
                self.handle_handshake_done(packet).await?;
            }
            PacketType::Data => {
                self.handle_data(packet, remote_addr).await?;
            }
            PacketType::Ack => {
                self.handle_ack(packet).await?;
            }
            PacketType::Close | PacketType::Error => {
                self.handle_close(packet).await?;
            }
            other => {
                debug!(pkt_type = %other, "packet.unhandled_type");
            }
        }

        Ok(())
    }

    async fn handle_hello(&self, packet: NovaPacket, remote_addr: SocketAddr) -> NovaResult<()> {
        if !self.config.is_server {
            debug!("client received HELLO — ignoring");
            return Ok(());
        }

        let session_id = packet.header.session_id;

        {
            let table = self.sessions.lock().await;
            if table.len() >= self.config.max_sessions {
                warn!("session table full; dropping HELLO");
                return Ok(());
            }
            if table.contains_key(&session_id) {
                // Already processing this session
                return Ok(());
            }
        }

        // Create session state
        let mut session = SessionState::new(session_id);
        session.remote_addr = Some(remote_addr);
        session.transition(SessionStatus::Established);

        {
            let mut table = self.sessions.lock().await;
            table.insert(session_id, session);
        }

        // Send HANDSHAKE_DONE (Phase 2: no real crypto, just acknowledge)
        let hs_done_pn = {
            let mut table = self.sessions.lock().await;
            let s = table.get_mut(&session_id).unwrap();
            s.next_packet_number()
        };

        let hs_done = NovaPacket {
            header: PacketHeader::new(PacketType::HandshakeDone, 0, session_id, PathId::INITIAL),
            packet_number: Some(hs_done_pn),
            payload: PacketPayload::HandshakeDone,
        };

        let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD);
        encode_packet(&hs_done, &mut buf)?;
        self.socket.send_to(&buf, remote_addr).await?;

        info!(session_id = %session_id, remote_addr = %remote_addr, "session.established");

        let _ = self.incoming_tx.send(IncomingMessage::NewSession {
            session_id,
            remote_addr,
        }).await;

        Ok(())
    }

    async fn handle_handshake_done(&self, packet: NovaPacket) -> NovaResult<()> {
        let session_id = packet.header.session_id;
        let mut table = self.sessions.lock().await;
        if let Some(session) = table.get_mut(&session_id) {
            if session.status == SessionStatus::Handshaking {
                session.transition(SessionStatus::Established);
                let remote_addr = session.remote_addr.unwrap();
                info!(session_id = %session_id, remote_addr = %remote_addr, "session.established");
            }
        }
        Ok(())
    }

    async fn handle_data(&self, packet: NovaPacket, remote_addr: SocketAddr) -> NovaResult<()> {
        let session_id = packet.header.session_id;

        let (pn, is_new) = {
            let mut table = self.sessions.lock().await;
            let session = table.entry(session_id).or_insert_with(|| {
                // Phantom session (data arrived before HELLO processed — race)
                let mut s = SessionState::new(session_id);
                s.remote_addr = Some(remote_addr);
                s.status = SessionStatus::Established;
                s
            });

            let pn = packet.packet_number.unwrap_or(0);
            let is_new = session.record_received(pn);
            if is_new {
                session.bytes_received += 1; // approximate; frames not yet counted
                session.packets_received += 1;
                session.touch();
            }
            (pn, is_new)
        };

        if !is_new {
            debug!(session_id = %session_id, pn = pn, "packet.duplicate_discarded");
            return Ok(());
        }

        // Send ACK
        self.send_ack(session_id, pn, remote_addr).await?;

        // Process frames
        if let PacketPayload::Data(frames) = &packet.payload {
            for frame in frames {
                if let Frame::Stream(sf) = frame {
                    let _ = self.incoming_tx.send(IncomingMessage::StreamData {
                        session_id,
                        stream_id: sf.stream_id,
                        offset: sf.offset,
                        data: sf.data.clone(),
                        fin: sf.fin,
                    }).await;

                    let mut table = self.sessions.lock().await;
                    if let Some(s) = table.get_mut(&session_id) {
                        s.bytes_received += sf.data.len() as u64;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_ack(&self, packet: NovaPacket) -> NovaResult<()> {
        let session_id = packet.header.session_id;

        // Collect any fast-retransmit work to do outside the lock.
        let mut fast_retransmit: Option<(SocketAddr, u64, Vec<Frame>)> = None;

        if let PacketPayload::Ack(frames) = &packet.payload {
            for frame in frames {
                if let Frame::Ack(ack) = frame {
                    let largest_acked = ack.largest_acked;
                    let ack_delay = Duration::from_micros(ack.ack_delay_us as u64);

                    {
                        let mut table = self.sessions.lock().await;
                        if let Some(session) = table.get_mut(&session_id) {
                            session.touch();

                            // Remove acked packets and collect an RTT sample.
                            let ack_result = session.retransmit.on_ack(largest_acked);
                            if let Some(send_time) = ack_result.rtt_sample_send_time {
                                let raw_rtt = send_time.elapsed();
                                let corrected = raw_rtt.saturating_sub(ack_delay);
                                session.rtt.update(corrected.max(Duration::from_millis(1)));
                            }

                            // Fast retransmit: three duplicate ACKs for the same largest_acked.
                            if largest_acked > session.last_acked {
                                session.last_acked = largest_acked;
                                session.dup_ack_count = 0;
                            } else if !session.retransmit.is_empty() {
                                session.dup_ack_count += 1;
                                if session.dup_ack_count >= 3 {
                                    session.dup_ack_count = 0;
                                    session.retransmissions += 1;
                                    if let Some(oldest_pn) = session.retransmit.oldest_unacked_pn() {
                                        if let Some(pkt) = session.retransmit.remove(oldest_pn) {
                                            if let Some(addr) = session.remote_addr {
                                                let new_pn = session.next_packet_number();
                                                let frames_clone = pkt.frames.clone();
                                                session.retransmit.push(UnackedPacket {
                                                    packet_number: new_pn,
                                                    path_id: pkt.path_id,
                                                    send_time: Instant::now(),
                                                    frames: pkt.frames,
                                                    byte_count: pkt.byte_count,
                                                });
                                                fast_retransmit = Some((addr, new_pn, frames_clone));
                                            }
                                        }
                                    }
                                }
                            }

                            debug!(
                                session_id = %session_id,
                                largest_acked = largest_acked,
                                pkts_removed = ack_result.packets_removed,
                                bytes_freed = ack_result.bytes_freed,
                                srtt_ms = session.rtt.srtt.as_millis(),
                                "ack.processed"
                            );
                        }
                    }
                }
            }
        }

        if let Some((remote_addr, new_pn, frames)) = fast_retransmit {
            let retransmit_pkt = self.build_data_packet(session_id, new_pn, frames);
            let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD);
            encode_packet(&retransmit_pkt, &mut buf)?;
            self.socket.send_to(&buf, remote_addr).await?;
            debug!(session_id = %session_id, pn = new_pn, "fast_retransmit.sent");
        }

        Ok(())
    }

    async fn handle_close(&self, packet: NovaPacket) -> NovaResult<()> {
        let session_id = packet.header.session_id;

        let (error_code, reason_str) = match &packet.payload {
            PacketPayload::Close(c) | PacketPayload::Error(c) => (
                c.inner.error_code,
                String::from_utf8_lossy(&c.inner.reason).into_owned(),
            ),
            _ => (0, String::new()),
        };

        {
            let mut table = self.sessions.lock().await;
            if let Some(s) = table.get_mut(&session_id) {
                s.transition(SessionStatus::Closed);
            }
        }

        info!(
            session_id = %session_id,
            error_code = error_code,
            reason = %reason_str,
            "session.closed_by_peer"
        );

        let _ = self.incoming_tx.send(IncomingMessage::SessionClosed {
            session_id,
            error_code,
            reason: reason_str,
        }).await;

        Ok(())
    }

    async fn send_ack(
        &self,
        session_id: SessionId,
        largest_acked: u64,
        remote_addr: SocketAddr,
    ) -> NovaResult<()> {
        let pn = {
            let mut table = self.sessions.lock().await;
            let s = table.get_mut(&session_id).ok_or(NovaError::SessionNotFound)?;
            s.next_packet_number()
        };

        let ack_packet = NovaPacket {
            header: PacketHeader::new(PacketType::Ack, 0, session_id, PathId::INITIAL),
            packet_number: Some(pn),
            payload: PacketPayload::Ack(vec![Frame::Ack(AckFrame {
                largest_acked,
                ack_delay_us: 0,
                ranges: vec![AckRange::single(largest_acked)],
            })]),
        };

        let mut buf = BytesMut::with_capacity(256);
        encode_packet(&ack_packet, &mut buf)?;
        self.socket.send_to(&buf, remote_addr).await?;

        debug!(session_id = %session_id, largest_acked = largest_acked, "ack.sent");
        Ok(())
    }

    /// Run the RTO retransmission loop. Checks every 50ms for packets whose
    /// retransmission timeout has expired and resends them with new packet numbers.
    /// Should be spawned with `tokio::spawn` alongside `run_recv_loop`.
    pub async fn run_rto_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(50));
        loop {
            interval.tick().await;

            // Collect all expired packets while holding the lock.
            let mut to_retransmit: Vec<(SessionId, SocketAddr, u64, Vec<Frame>)> = Vec::new();

            {
                let mut table = self.sessions.lock().await;
                for (session_id, session) in table.iter_mut() {
                    if session.is_closed() {
                        continue;
                    }
                    let rto = session.rtt.rto();
                    if let Some(expired_pn) = session.retransmit.rto_expired(rto) {
                        if let Some(pkt) = session.retransmit.remove(expired_pn) {
                            if let Some(addr) = session.remote_addr {
                                let new_pn = session.next_packet_number();
                                session.retransmissions += 1;
                                let frames_clone = pkt.frames.clone();
                                session.retransmit.push(UnackedPacket {
                                    packet_number: new_pn,
                                    path_id: pkt.path_id,
                                    send_time: Instant::now(),
                                    frames: pkt.frames,
                                    byte_count: pkt.byte_count,
                                });
                                to_retransmit.push((*session_id, addr, new_pn, frames_clone));
                            }
                        }
                    }
                }
            }

            // Send outside the lock.
            for (session_id, remote_addr, new_pn, frames) in to_retransmit {
                let packet = self.build_data_packet(session_id, new_pn, frames);
                let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD);
                match encode_packet(&packet, &mut buf) {
                    Ok(_) => {
                        if let Err(e) = self.socket.send_to(&buf, remote_addr).await {
                            warn!(session_id = %session_id, err = %e, "rto.send_error");
                        } else {
                            debug!(session_id = %session_id, pn = new_pn, "rto.retransmit_sent");
                        }
                    }
                    Err(e) => {
                        warn!(session_id = %session_id, err = %e, "rto.encode_error");
                    }
                }
            }
        }
    }

    fn build_hello_packet(&self, session_id: SessionId, service: ServiceId) -> NovaPacket {
        NovaPacket {
            header: PacketHeader::new(PacketType::Hello, 0, session_id, PathId::INITIAL),
            packet_number: None,
            payload: PacketPayload::Hello(HelloPayload::unauthenticated(service)),
        }
    }

    fn build_data_packet(&self, session_id: SessionId, pn: u64, frames: Vec<Frame>) -> NovaPacket {
        NovaPacket {
            header: PacketHeader::new(PacketType::Data, 0, session_id, PathId::INITIAL),
            packet_number: Some(pn),
            payload: PacketPayload::Data(frames),
        }
    }

    fn build_close_packet(
        &self,
        session_id: SessionId,
        pn: u64,
        error_code: u16,
        reason: &str,
    ) -> NovaPacket {
        NovaPacket {
            header: PacketHeader::new(PacketType::Close, 0, session_id, PathId::INITIAL),
            packet_number: Some(pn),
            payload: PacketPayload::Close(ClosePayload {
                inner: CloseFrame {
                    error_code,
                    frame_type: 0,
                    reason: Bytes::copy_from_slice(
                        &reason.as_bytes()[..reason.len().min(255)]
                    ),
                },
            }),
        }
    }

    /// Return the number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Return current stats for a session.
    pub async fn session_stats(&self, session_id: SessionId) -> Option<SessionStats> {
        let table = self.sessions.lock().await;
        table.get(&session_id).map(|s| SessionStats {
            status: s.status,
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            packets_sent: s.packets_sent,
            packets_received: s.packets_received,
            retransmissions: s.retransmissions,
            rtt_srtt: s.rtt.srtt,
            rtt_rto: s.rtt.rto(),
        })
    }
}

/// Snapshot of session statistics.
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub status: SessionStatus,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub retransmissions: u64,
    pub rtt_srtt: Duration,
    pub rtt_rto: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn local_addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[tokio::test]
    async fn endpoint_bind() {
        let cfg = EndpointConfig::server(local_addr(19990));
        let ep = Endpoint::bind(cfg).await.unwrap();
        assert_eq!(ep.session_count().await, 0);
    }

    #[tokio::test]
    async fn echo_handshake_and_data() {
        // Server endpoint
        let server_cfg = EndpointConfig::server(local_addr(19991));
        let mut server = Endpoint::bind(server_cfg).await.unwrap();
        let _server_incoming = server.take_incoming().unwrap();
        let server_arc = Arc::new(server);

        // Spawn server receive loop
        let server_recv = Arc::clone(&server_arc);
        tokio::spawn(async move {
            server_recv.run_recv_loop().await;
        });

        // Client endpoint
        let client_cfg = EndpointConfig::client(local_addr(19992));
        let mut client = Endpoint::bind(client_cfg).await.unwrap();
        let _client_incoming = client.take_incoming().unwrap();
        let client_arc = Arc::new(client);

        // Spawn client receive loop
        let client_recv = Arc::clone(&client_arc);
        tokio::spawn(async move {
            client_recv.run_recv_loop().await;
        });

        // Client connects to server
        let svc = ServiceId::from_name("echo");
        let session_id = client_arc.connect(local_addr(19991), svc).await.unwrap();
        assert_eq!(client_arc.session_count().await, 1);

        // Wait for session establishment on client (HANDSHAKE_DONE from server)
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send data from client to server
        client_arc.send_stream_data(
            session_id,
            0,
            0,
            Bytes::from_static(b"hello novanet"),
            false,
        ).await.unwrap();

        // Give everything time to propagate
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Server should have received the data
        let server_count = server_arc.session_count().await;
        assert!(server_count >= 1, "server should have at least 1 session");
    }
}
