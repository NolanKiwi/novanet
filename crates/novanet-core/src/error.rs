use thiserror::Error;

pub type NovaResult<T> = Result<T, NovaError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NovaError {
    // Wire format errors
    #[error("packet too short: need {needed} bytes, got {got}")]
    PacketTooShort { needed: usize, got: usize },

    #[error("unknown packet type: 0x{0:02X}")]
    UnknownPacketType(u8),

    #[error("unknown frame type: 0x{0:02X}")]
    UnknownFrameType(u8),

    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),

    #[error("frame decode error: {0}")]
    FrameDecodeError(&'static str),

    #[error("buffer too small for encoding: need {needed}, have {have}")]
    BufferTooSmall { needed: usize, have: usize },

    #[error("packet exceeds maximum size: {size} > {max}")]
    PacketTooLarge { size: usize, max: usize },

    // Session errors
    #[error("session not found")]
    SessionNotFound,

    #[error("session already exists")]
    SessionAlreadyExists,

    #[error("session state invalid for operation: {0}")]
    InvalidSessionState(&'static str),

    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("idle timeout")]
    IdleTimeout,

    // Protocol errors (correspond to wire-level error codes)
    #[error("internal implementation error: {0}")]
    InternalError(&'static str),

    #[error("protocol violation: {0}")]
    ProtocolViolation(&'static str),

    #[error("crypto error: {0}")]
    CryptoError(&'static str),

    #[error("stream limit exceeded")]
    StreamLimitExceeded,

    #[error("flow control violation")]
    FlowControlViolation,

    #[error("handshake failed: {0}")]
    HandshakeFailed(&'static str),

    #[error("version negotiation failed")]
    VersionNegotiationFailed,

    #[error("replay detected: packet number {0}")]
    ReplayDetected(u64),

    #[error("address validation failed")]
    AddressValidationFailed,

    #[error("resource limit reached: {0}")]
    ResourceLimit(&'static str),

    // I/O errors (Phase 2+)
    #[error("I/O error: {0}")]
    Io(String),
}

impl NovaError {
    /// Wire-level error code for this error.
    pub fn wire_code(&self) -> u16 {
        match self {
            NovaError::InternalError(_) => 0x0001,
            NovaError::ProtocolViolation(_) => 0x0002,
            NovaError::CryptoError(_) => 0x0003,
            NovaError::StreamLimitExceeded => 0x0004,
            NovaError::FlowControlViolation => 0x0005,
            NovaError::HandshakeFailed(_) => 0x0006,
            NovaError::VersionNegotiationFailed => 0x0007,
            NovaError::ReplayDetected(_) => 0x0008,
            NovaError::AddressValidationFailed => 0x0009,
            NovaError::ResourceLimit(_) => 0x000A,
            _ => 0x0001, // default: internal error
        }
    }
}

impl From<std::io::Error> for NovaError {
    fn from(e: std::io::Error) -> Self {
        NovaError::Io(e.to_string())
    }
}
