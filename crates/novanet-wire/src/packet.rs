use bytes::Bytes;
use novanet_core::{
    ids::{NodeId, ServiceId},
    PacketType,
};

use crate::{
    frame::{CloseFrame, Frame},
    header::PacketHeader,
};

/// A fully decoded NovaNet packet, including header and typed payload.
#[derive(Debug, Clone, PartialEq)]
pub struct NovaPacket {
    pub header: PacketHeader,
    /// Packet number (None for HELLO and RETRY which have no packet number).
    pub packet_number: Option<u64>,
    pub payload: PacketPayload,
}

impl NovaPacket {
    pub fn packet_type(&self) -> PacketType {
        self.header.packet_type
    }
}

/// Typed payload for each packet variant.
#[derive(Debug, Clone, PartialEq)]
pub enum PacketPayload {
    /// HELLO — unauthenticated session initiation (Phase 1: no encryption).
    Hello(HelloPayload),

    /// RETRY — stateless server retry (unencrypted).
    Retry(RetryPayload),

    /// HANDSHAKE — carries crypto handshake messages.
    Handshake(HandshakePayload),

    /// HANDSHAKE_DONE — signals handshake complete.
    HandshakeDone,

    /// DATA — sequence of frames (encrypted in Phase 4+).
    Data(Vec<Frame>),

    /// ACK — standalone acknowledgment.
    Ack(Vec<Frame>),

    /// PATH_CHALLENGE — validate a path.
    PathChallenge(PathChallengePayload),

    /// PATH_RESPONSE — respond to path challenge.
    PathResponse(PathChallengePayload),

    /// CLOSE — graceful session close.
    Close(ClosePayload),

    /// ERROR — fatal protocol error.
    Error(ErrorPayload),

    /// PADDING — no-op.
    Padding { count: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPayload {
    /// Client's ephemeral public key (32 bytes, X25519). Empty in Phase 1 (no crypto).
    pub client_ephemeral_pk: [u8; 32],
    /// Client's long-term node identity. Zero in Phase 1 (unauthenticated).
    pub client_node_id: NodeId,
    /// Desired service identifier.
    pub desired_service_id: ServiceId,
    /// Retry token (empty if no retry required).
    pub retry_token: Vec<u8>,
    /// Supported protocol versions (at least [0x01]).
    pub supported_versions: Vec<u8>,
}

impl HelloPayload {
    pub fn unauthenticated(desired_service: ServiceId) -> Self {
        HelloPayload {
            client_ephemeral_pk: [0u8; 32],
            client_node_id: NodeId::zero(),
            desired_service_id: desired_service,
            retry_token: Vec::new(),
            supported_versions: vec![0x01],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPayload {
    /// Server-issued retry token (encrypted by server-local key).
    pub retry_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePayload {
    /// Raw crypto bytes (server ephemeral PK, signature, etc.).
    pub crypto_data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChallengePayload {
    /// 8 random bytes. PATH_RESPONSE must echo these exactly.
    pub data: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosePayload {
    pub inner: CloseFrame,
}

pub type ErrorPayload = ClosePayload;
