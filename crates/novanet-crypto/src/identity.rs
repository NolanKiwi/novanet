/// Key identity stubs for Phase 1. Phase 4 replaces with X25519 + Ed25519.

/// An ephemeral X25519 keypair for ECDH key exchange.
/// In Phase 1, all bytes are zero (no actual crypto).
pub struct EphemeralKeypair {
    pub public_key: [u8; 32],
    #[allow(dead_code)]
    secret_key: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate a new ephemeral keypair.
    /// Phase 1: returns zero keys (placeholder).
    /// Phase 4: uses ring::agreement::EphemeralPrivateKey.
    pub fn generate() -> Self {
        EphemeralKeypair {
            public_key: [0u8; 32],
            secret_key: [0u8; 32],
        }
    }
}

/// A long-term Ed25519 keypair for node authentication.
/// Phase 1: not used (all sessions are unauthenticated).
pub struct StaticKeypair {
    pub public_key: [u8; 32],
    #[allow(dead_code)]
    secret_key: [u8; 32],
}

impl StaticKeypair {
    pub fn generate() -> Self {
        StaticKeypair {
            public_key: [0u8; 32],
            secret_key: [0u8; 32],
        }
    }
}
