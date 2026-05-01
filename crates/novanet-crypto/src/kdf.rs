/// Key derivation stubs for Phase 1. Phase 4 implements HKDF-SHA256.

/// Derived session keys after a successful handshake.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
    pub client_write_iv: [u8; 12],
    pub server_write_iv: [u8; 12],
}

/// Derive session keys from a shared DH secret and session ID.
/// Phase 1: returns zero keys (no crypto).
/// Phase 4: implements full HKDF-SHA256 key schedule.
pub fn derive_session_keys(_dh_secret: &[u8], _session_id: &[u8; 16]) -> SessionKeys {
    SessionKeys {
        client_write_key: [0u8; 32],
        server_write_key: [0u8; 32],
        client_write_iv: [0u8; 12],
        server_write_iv: [0u8; 12],
    }
}
