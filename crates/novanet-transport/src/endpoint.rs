use bytes::{Bytes, BytesMut};
use novanet_core::{
    constants::{AEAD_TAG_SIZE, DATA_HEADER_SIZE, FIXED_HEADER_SIZE, HANDSHAKE_TIMEOUT_SECS, MAX_UDP_PAYLOAD},
    error::{NovaError, NovaResult},
    ids::{PathId, ServiceId, SessionId},
    PacketType,
};
use novanet_crypto::{
    aead::{self, AeadKey, AeadNonce},
    identity::{verify_signature, EphemeralKeypair, StaticKeypair},
    kdf::derive_session_keys,
    SessionKeys,
};
use novanet_wire::{
    codec::{decode_packet, encode_packet},
    frame::{AckFrame, AckRange, CloseFrame, Frame, StreamFrame},
    header::PacketHeader,
    packet::{ClosePayload, HandshakePayload, HelloPayload, NovaPacket, PacketPayload},
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
    pub bind_addr: SocketAddr,
    pub max_sessions: usize,
    pub handshake_timeout: Duration,
    pub is_server: bool,
    /// Server static keypair for authenticated handshakes. None = unauthenticated (Phase 2 compat).
    pub static_keypair: Option<Arc<StaticKeypair>>,
}

impl EndpointConfig {
    pub fn server(addr: SocketAddr) -> Self {
        EndpointConfig {
            bind_addr: addr,
            max_sessions: 1024,
            handshake_timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            is_server: true,
            static_keypair: None,
        }
    }

    pub fn server_with_crypto(addr: SocketAddr) -> Self {
        EndpointConfig {
            bind_addr: addr,
            max_sessions: 1024,
            handshake_timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            is_server: true,
            static_keypair: Some(Arc::new(StaticKeypair::generate())),
        }
    }

    pub fn client(addr: SocketAddr) -> Self {
        EndpointConfig {
            bind_addr: addr,
            max_sessions: 64,
            handshake_timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            is_server: false,
            static_keypair: None,
        }
    }
}

/// A message delivered to the application from a NovaNet session.
#[derive(Debug)]
pub enum IncomingMessage {
    StreamData {
        session_id: SessionId,
        stream_id: u32,
        offset: u64,
        data: Bytes,
        fin: bool,
    },
    NewSession {
        session_id: SessionId,
        remote_addr: SocketAddr,
    },
    SessionClosed {
        session_id: SessionId,
        error_code: u16,
        reason: String,
    },
}

type SessionTable = Arc<Mutex<HashMap<SessionId, SessionState>>>;

/// A NovaNet UDP endpoint.
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    config: EndpointConfig,
    sessions: SessionTable,
    incoming_tx: tokio::sync::mpsc::Sender<IncomingMessage>,
    incoming_rx: Option<tokio::sync::mpsc::Receiver<IncomingMessage>>,
}

impl Endpoint {
    pub async fn bind(config: EndpointConfig) -> NovaResult<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        info!(
            addr = %config.bind_addr,
            mode = if config.is_server { "server" } else { "client" },
            crypto = config.static_keypair.is_some(),
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

    pub fn take_incoming(&mut self) -> Option<tokio::sync::mpsc::Receiver<IncomingMessage>> {
        self.incoming_rx.take()
    }

    /// Initiate a new session to a remote endpoint (client side).
    pub async fn connect(&self, remote_addr: SocketAddr, service: ServiceId) -> NovaResult<SessionId> {
        let session_id = SessionId::generate();

        let ephem = EphemeralKeypair::generate();
        let ephem_pk = ephem.public_bytes;

        let mut session = SessionState::new(session_id);
        session.remote_addr = Some(remote_addr);
        session.is_initiator = true;
        session.pending_ephem = Some(ephem);
        session.transition(SessionStatus::Handshaking);

        let hello = NovaPacket {
            header: PacketHeader::new(PacketType::Hello, 0, session_id, PathId::INITIAL),
            packet_number: None,
            payload: PacketPayload::Hello(HelloPayload {
                client_ephemeral_pk: ephem_pk,
                ..HelloPayload::unauthenticated(service)
            }),
        };

        let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD);
        encode_packet(&hello, &mut buf)?;
        self.socket.send_to(&buf, remote_addr).await?;
        debug!(session_id = %session_id, remote_addr = %remote_addr, "session.hello_sent");

        let mut table = self.sessions.lock().await;
        table.insert(session_id, session);
        Ok(session_id)
    }

    /// Send stream data to a session. Returns ResourceLimit error if congestion window is full.
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
        let byte_count = data.len() + 14;

        let (remote_addr, pn, encrypt_info) = {
            let mut table = self.sessions.lock().await;
            let session = table.get_mut(&session_id).ok_or(NovaError::SessionNotFound)?;
            if !session.is_established() {
                return Err(NovaError::InvalidSessionState("not established"));
            }

            // Phase 5: congestion control
            let bif = session.retransmit.bytes_in_flight();
            if !session.congestion.0.can_send(bif, byte_count) {
                return Err(NovaError::ResourceLimit("congestion window full"));
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

            // Phase 4: capture encryption parameters
            let encrypt_info = session_encrypt_info(&session.session_keys, session.is_initiator);

            (remote_addr, pn, encrypt_info)
        };

        let packet = build_data_packet(session_id, pn, vec![frame]);
        let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD + AEAD_TAG_SIZE);
        encode_packet(&packet, &mut buf)?;

        if let Some((write_key, write_iv)) = encrypt_info {
            encrypt_buf(&mut buf, &write_key, &write_iv, pn)?;
        }

        self.socket.send_to(&buf, remote_addr).await?;
        debug!(session_id = %session_id, pn = pn, stream_id = stream_id, "packet.sent");
        Ok(())
    }

    /// Close a session gracefully.
    pub async fn close_session(&self, session_id: SessionId, reason: &str) -> NovaResult<()> {
        let (remote_addr, pn) = {
            let mut table = self.sessions.lock().await;
            let session = table.get_mut(&session_id).ok_or(NovaError::SessionNotFound)?;
            if session.is_closed() {
                return Ok(());
            }
            let pn = session.next_packet_number();
            session.transition(SessionStatus::Draining);
            (session.remote_addr.ok_or(NovaError::SessionNotFound)?, pn)
        };

        let packet = build_close_packet(session_id, pn, 0x0000, reason);
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

    /// Receive loop — spawned with `tokio::spawn`, runs indefinitely.
    pub async fn run_recv_loop(&self) {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD + 8];
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

        // Phase 4: decrypt DATA packets before full codec decode.
        let data = if data[1] == PacketType::Data.as_byte() {
            self.try_decrypt_data(data).await
        } else {
            data
        };

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
            PacketType::Hello => self.handle_hello(packet, remote_addr).await?,
            PacketType::Handshake => self.handle_handshake(packet).await?,
            PacketType::HandshakeDone => self.handle_handshake_done(packet).await?,
            PacketType::Data => self.handle_data(packet, remote_addr).await?,
            PacketType::Ack => self.handle_ack(packet).await?,
            PacketType::Close | PacketType::Error => self.handle_close(packet).await?,
            other => debug!(pkt_type = %other, "packet.unhandled_type"),
        }

        Ok(())
    }

    /// Attempt to decrypt a DATA packet in-place. Returns original bytes on failure or missing keys.
    async fn try_decrypt_data(&self, data: Bytes) -> Bytes {
        if data.len() < DATA_HEADER_SIZE + AEAD_TAG_SIZE {
            return data;
        }

        let session_id = {
            let mut sid = [0u8; 16];
            sid.copy_from_slice(&data[4..20]);
            SessionId::from_bytes(sid)
        };
        let pn = u64::from_be_bytes(data[FIXED_HEADER_SIZE..DATA_HEADER_SIZE].try_into().unwrap());

        let decrypt_params = {
            let table = self.sessions.lock().await;
            table.get(&session_id).and_then(|s| {
                s.session_keys.as_ref().map(|k| decrypt_key_iv(k, s.is_initiator))
            })
        };

        let (read_key, read_iv) = match decrypt_params {
            Some(p) => p,
            None => return data,
        };

        let nonce = AeadNonce::from_iv_and_packet_number(&read_iv, pn);
        let aad = data[..DATA_HEADER_SIZE].to_vec();
        let mut payload = data[DATA_HEADER_SIZE..].to_vec();

        match aead::open(&read_key, &nonce, &aad, &mut payload) {
            Ok(()) => {
                let mut new_data = aad;
                new_data.extend_from_slice(&payload);
                Bytes::from(new_data)
            }
            Err(_) => {
                warn!(session_id = %session_id, pn = pn, "data.aead_open_failed");
                Bytes::new() // empty → decode_packet will return an error, packet dropped
            }
        }
    }

    // ─── Handshake handlers ───────────────────────────────────────────────────

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
                return Ok(()); // duplicate HELLO
            }
        }

        if let Some(static_kp) = self.config.static_keypair.clone() {
            // Phase 4: authenticated crypto handshake
            let hello = match &packet.payload {
                PacketPayload::Hello(h) => h.clone(),
                _ => return Ok(()),
            };

            let server_ephem = EphemeralKeypair::generate();
            let server_ephem_pk = server_ephem.public_bytes;

            let shared = server_ephem
                .agree(&hello.client_ephemeral_pk)
                .map_err(|_| NovaError::HandshakeFailed("X25519 failed"))?;

            let session_keys = derive_session_keys(&shared.0, session_id.as_bytes())
                .map_err(|_| NovaError::HandshakeFailed("HKDF failed"))?;

            // Sign (session_id || server_ephem_pk) for client to verify server identity
            let mut sign_msg = Vec::with_capacity(16 + 32);
            sign_msg.extend_from_slice(session_id.as_bytes());
            sign_msg.extend_from_slice(&server_ephem_pk);
            let sig = static_kp.sign(&sign_msg);
            let server_static_pk = static_kp.public_key_bytes();

            let hs_pkt = NovaPacket {
                header: PacketHeader::new(PacketType::Handshake, 0, session_id, PathId::INITIAL),
                packet_number: None,
                payload: PacketPayload::Handshake(HandshakePayload {
                    server_ephemeral_pk: server_ephem_pk,
                    server_static_pk,
                    server_signature: sig,
                }),
            };

            let mut session = SessionState::new(session_id);
            session.remote_addr = Some(remote_addr);
            session.is_initiator = false;
            session.session_keys = Some(session_keys);
            session.transition(SessionStatus::Established);

            {
                let mut table = self.sessions.lock().await;
                table.insert(session_id, session);
            }

            let mut buf = BytesMut::with_capacity(256);
            encode_packet(&hs_pkt, &mut buf)?;
            self.socket.send_to(&buf, remote_addr).await?;
            info!(session_id = %session_id, remote_addr = %remote_addr, "session.established_with_crypto");
        } else {
            // Phase 2 fallback: unauthenticated, no encryption
            let mut session = SessionState::new(session_id);
            session.remote_addr = Some(remote_addr);
            session.transition(SessionStatus::Established);

            {
                let mut table = self.sessions.lock().await;
                table.insert(session_id, session);
            }

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
        }

        let _ = self.incoming_tx.send(IncomingMessage::NewSession { session_id, remote_addr }).await;
        Ok(())
    }

    /// Client receives HANDSHAKE from server — complete the crypto handshake.
    async fn handle_handshake(&self, packet: NovaPacket) -> NovaResult<()> {
        if self.config.is_server {
            return Ok(());
        }

        let session_id = packet.header.session_id;
        let hs = match &packet.payload {
            PacketPayload::Handshake(h) => h.clone(),
            _ => return Ok(()),
        };

        // Take the pending ephemeral key (consumes it; subsequent calls are no-ops)
        let pending_ephem = {
            let mut table = self.sessions.lock().await;
            table.get_mut(&session_id).and_then(|s| {
                if s.status == SessionStatus::Handshaking {
                    s.pending_ephem.take()
                } else {
                    None
                }
            })
        };

        let ephem = match pending_ephem {
            Some(e) => e,
            None => {
                debug!(session_id = %session_id, "handshake: no pending ephemeral key, ignoring");
                return Ok(());
            }
        };

        let shared = ephem
            .agree(&hs.server_ephemeral_pk)
            .map_err(|_| NovaError::HandshakeFailed("X25519 failed"))?;

        let session_keys = derive_session_keys(&shared.0, session_id.as_bytes())
            .map_err(|_| NovaError::HandshakeFailed("HKDF failed"))?;

        // Verify server signature over (session_id || server_ephemeral_pk)
        let mut sign_msg = Vec::with_capacity(16 + 32);
        sign_msg.extend_from_slice(session_id.as_bytes());
        sign_msg.extend_from_slice(&hs.server_ephemeral_pk);
        if verify_signature(&hs.server_static_pk, &sign_msg, &hs.server_signature).is_err() {
            warn!(session_id = %session_id, "handshake: server signature verification failed");
            return Err(NovaError::HandshakeFailed("signature verification failed"));
        }

        let remote_addr = {
            let mut table = self.sessions.lock().await;
            let s = table.get_mut(&session_id).ok_or(NovaError::SessionNotFound)?;
            s.session_keys = Some(session_keys);
            s.transition(SessionStatus::Established);
            s.remote_addr.unwrap()
        };

        info!(session_id = %session_id, remote_addr = %remote_addr, "session.established_with_crypto");
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

    // ─── Data path ────────────────────────────────────────────────────────────

    async fn handle_data(&self, packet: NovaPacket, remote_addr: SocketAddr) -> NovaResult<()> {
        let session_id = packet.header.session_id;

        let (pn, is_new) = {
            let mut table = self.sessions.lock().await;
            let session = table.entry(session_id).or_insert_with(|| {
                let mut s = SessionState::new(session_id);
                s.remote_addr = Some(remote_addr);
                s.status = SessionStatus::Established;
                s
            });
            let pn = packet.packet_number.unwrap_or(0);
            let is_new = session.record_received(pn);
            if is_new {
                session.bytes_received += 1;
                session.packets_received += 1;
                session.touch();
            }
            (pn, is_new)
        };

        if !is_new {
            debug!(session_id = %session_id, pn = pn, "packet.duplicate_discarded");
            return Ok(());
        }

        self.send_ack(session_id, pn, remote_addr).await?;

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
        let mut fast_retransmit: Option<(SocketAddr, u64, Vec<Frame>, Option<(AeadKey, [u8; 12])>)> = None;

        if let PacketPayload::Ack(frames) = &packet.payload {
            for frame in frames {
                if let Frame::Ack(ack) = frame {
                    let largest_acked = ack.largest_acked;
                    let ack_delay = Duration::from_micros(ack.ack_delay_us as u64);

                    {
                        let mut table = self.sessions.lock().await;
                        if let Some(session) = table.get_mut(&session_id) {
                            session.touch();

                            let ack_result = session.retransmit.on_ack(largest_acked);

                            // Phase 5: notify congestion controller
                            if ack_result.bytes_freed > 0 {
                                session.congestion.0.on_ack(ack_result.bytes_freed, session.rtt.srtt);
                            }

                            if let Some(send_time) = ack_result.rtt_sample_send_time {
                                let raw_rtt = send_time.elapsed();
                                let corrected = raw_rtt.saturating_sub(ack_delay);
                                session.rtt.update(corrected.max(Duration::from_millis(1)));
                            }

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
                                                let enc = session_encrypt_info(
                                                    &session.session_keys,
                                                    session.is_initiator,
                                                );
                                                session.retransmit.push(UnackedPacket {
                                                    packet_number: new_pn,
                                                    path_id: pkt.path_id,
                                                    send_time: Instant::now(),
                                                    frames: pkt.frames,
                                                    byte_count: pkt.byte_count,
                                                });
                                                fast_retransmit = Some((addr, new_pn, frames_clone, enc));
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

        if let Some((remote_addr, new_pn, frames, enc)) = fast_retransmit {
            let pkt = build_data_packet(session_id, new_pn, frames);
            let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD + AEAD_TAG_SIZE);
            encode_packet(&pkt, &mut buf)?;
            if let Some((write_key, write_iv)) = enc {
                encrypt_buf(&mut buf, &write_key, &write_iv, new_pn)?;
            }
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

    /// RTO retransmission loop — spawned with `tokio::spawn`, runs indefinitely.
    pub async fn run_rto_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(50));
        loop {
            interval.tick().await;

            let mut to_retransmit: Vec<(SessionId, SocketAddr, u64, Vec<Frame>, Option<(AeadKey, [u8; 12])>)> = Vec::new();

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
                                // Phase 5: notify congestion controller of loss
                                session.congestion.0.on_loss(pkt.byte_count);
                                let frames_clone = pkt.frames.clone();
                                let enc = session_encrypt_info(
                                    &session.session_keys,
                                    session.is_initiator,
                                );
                                session.retransmit.push(UnackedPacket {
                                    packet_number: new_pn,
                                    path_id: pkt.path_id,
                                    send_time: Instant::now(),
                                    frames: pkt.frames,
                                    byte_count: pkt.byte_count,
                                });
                                to_retransmit.push((*session_id, addr, new_pn, frames_clone, enc));
                            }
                        }
                    }
                }
            }

            for (session_id, remote_addr, new_pn, frames, enc) in to_retransmit {
                let packet = build_data_packet(session_id, new_pn, frames);
                let mut buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD + AEAD_TAG_SIZE);
                match encode_packet(&packet, &mut buf) {
                    Ok(_) => {
                        if let Some((write_key, write_iv)) = enc {
                            if let Err(e) = encrypt_buf(&mut buf, &write_key, &write_iv, new_pn) {
                                warn!(session_id = %session_id, err = %e, "rto.seal_error");
                                continue;
                            }
                        }
                        if let Err(e) = self.socket.send_to(&buf, remote_addr).await {
                            warn!(session_id = %session_id, err = %e, "rto.send_error");
                        } else {
                            debug!(session_id = %session_id, pn = new_pn, "rto.retransmit_sent");
                        }
                    }
                    Err(e) => warn!(session_id = %session_id, err = %e, "rto.encode_error"),
                }
            }
        }
    }

    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

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
            congestion_window: s.congestion.0.congestion_window(),
            has_crypto: s.session_keys.is_some(),
        })
    }
}

// ─── Free helpers (no self access needed) ────────────────────────────────────

/// Extract (write_key, write_iv) for the sender side, if keys are available.
fn session_encrypt_info(
    keys: &Option<SessionKeys>,
    is_initiator: bool,
) -> Option<(AeadKey, [u8; 12])> {
    keys.as_ref().map(|k| {
        if is_initiator {
            (AeadKey::from_bytes(k.client_write_key), k.client_write_iv)
        } else {
            (AeadKey::from_bytes(k.server_write_key), k.server_write_iv)
        }
    })
}

/// Extract (read_key, read_iv) for the receiver side (opposite of sender).
fn decrypt_key_iv(keys: &SessionKeys, is_initiator: bool) -> (AeadKey, [u8; 12]) {
    if is_initiator {
        (AeadKey::from_bytes(keys.server_write_key), keys.server_write_iv)
    } else {
        (AeadKey::from_bytes(keys.client_write_key), keys.client_write_iv)
    }
}

/// Encrypt the payload portion (bytes[DATA_HEADER_SIZE..]) of an already-encoded DATA packet.
fn encrypt_buf(
    buf: &mut BytesMut,
    write_key: &AeadKey,
    write_iv: &[u8; 12],
    pn: u64,
) -> NovaResult<()> {
    let nonce = AeadNonce::from_iv_and_packet_number(write_iv, pn);
    let aad = buf[..DATA_HEADER_SIZE].to_vec();
    let mut payload: Vec<u8> = buf[DATA_HEADER_SIZE..].to_vec();
    aead::seal(write_key, &nonce, &aad, &mut payload)
        .map_err(|_| NovaError::CryptoError("AEAD seal failed"))?;
    buf.clear();
    buf.extend_from_slice(&aad);
    buf.extend_from_slice(&payload);
    Ok(())
}

fn build_data_packet(session_id: SessionId, pn: u64, frames: Vec<Frame>) -> NovaPacket {
    NovaPacket {
        header: PacketHeader::new(PacketType::Data, 0, session_id, PathId::INITIAL),
        packet_number: Some(pn),
        payload: PacketPayload::Data(frames),
    }
}

fn build_close_packet(session_id: SessionId, pn: u64, error_code: u16, reason: &str) -> NovaPacket {
    NovaPacket {
        header: PacketHeader::new(PacketType::Close, 0, session_id, PathId::INITIAL),
        packet_number: Some(pn),
        payload: PacketPayload::Close(ClosePayload {
            inner: CloseFrame {
                error_code,
                frame_type: 0,
                reason: Bytes::copy_from_slice(&reason.as_bytes()[..reason.len().min(255)]),
            },
        }),
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
    pub congestion_window: usize,
    pub has_crypto: bool,
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
        let server_cfg = EndpointConfig::server(local_addr(19991));
        let mut server = Endpoint::bind(server_cfg).await.unwrap();
        let _server_incoming = server.take_incoming().unwrap();
        let server_arc = Arc::new(server);
        let server_recv = Arc::clone(&server_arc);
        tokio::spawn(async move { server_recv.run_recv_loop().await });

        let client_cfg = EndpointConfig::client(local_addr(19992));
        let mut client = Endpoint::bind(client_cfg).await.unwrap();
        let _client_incoming = client.take_incoming().unwrap();
        let client_arc = Arc::new(client);
        let client_recv = Arc::clone(&client_arc);
        tokio::spawn(async move { client_recv.run_recv_loop().await });

        let svc = ServiceId::from_name("echo");
        let session_id = client_arc.connect(local_addr(19991), svc).await.unwrap();
        assert_eq!(client_arc.session_count().await, 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        client_arc
            .send_stream_data(session_id, 0, 0, Bytes::from_static(b"hello novanet"), false)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(server_arc.session_count().await >= 1);
    }
}
