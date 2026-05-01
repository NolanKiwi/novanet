/// Current protocol version byte.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Maximum UDP payload in bytes (conservative MTU to avoid fragmentation).
pub const MAX_UDP_PAYLOAD: usize = 1200;

/// Minimum valid NovaNet packet size (header only).
pub const MIN_PACKET_SIZE: usize = 21;

/// Fixed header size: version(1) + type(1) + flags(1) + header_len(1) + session_id(16) + path_id(1).
pub const FIXED_HEADER_SIZE: usize = 21;

/// Packet number field size in bytes.
pub const PACKET_NUMBER_SIZE: usize = 8;

/// AEAD authentication tag size in bytes (ChaCha20-Poly1305).
pub const AEAD_TAG_SIZE: usize = 16;

/// Minimum header size for data-phase packets (fixed header + packet number).
pub const DATA_HEADER_SIZE: usize = FIXED_HEADER_SIZE + PACKET_NUMBER_SIZE;

/// Initial congestion window in bytes (10 max-size packets).
pub const INITIAL_CWND: usize = 10 * MAX_UDP_PAYLOAD;

/// Minimum congestion window in bytes.
pub const MIN_CWND: usize = 2 * MAX_UDP_PAYLOAD;

/// Initial RTT estimate in milliseconds (conservative).
pub const INITIAL_RTT_MS: u64 = 333;

/// Maximum ACK ranges per ACK frame.
pub const MAX_ACK_RANGES: usize = 255;

/// Maximum number of concurrent streams per session (per direction).
pub const MAX_STREAMS: u32 = (1 << 31) - 1;

/// Session idle timeout in seconds.
pub const MAX_SESSION_IDLE_SECS: u64 = 60;

/// Handshake timeout in seconds.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Path challenge timeout in seconds.
pub const PATH_CHALLENGE_TIMEOUT_SECS: u64 = 3;

/// Retry token lifetime in seconds.
pub const RETRY_TOKEN_LIFETIME_SECS: u64 = 15;

/// Anti-amplification factor: server may send at most this multiple of client bytes before
/// address validation.
pub const ANTI_AMPL_FACTOR: usize = 3;

/// Size of the path challenge/response data in bytes.
pub const PATH_CHALLENGE_SIZE: usize = 8;
