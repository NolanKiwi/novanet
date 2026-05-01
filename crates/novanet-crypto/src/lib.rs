/// Cryptographic primitives for NovaNet.
///
/// Phase 1: stubs only. Phase 4 will implement:
///   - X25519 key exchange
///   - Ed25519 signing/verification
///   - HKDF-SHA256 key derivation
///   - ChaCha20-Poly1305 AEAD encryption/decryption

pub mod aead;
pub mod identity;
pub mod kdf;

pub use aead::{AeadKey, AeadNonce, AEAD_KEY_SIZE, AEAD_NONCE_SIZE, AEAD_TAG_SIZE};
pub use identity::{EphemeralKeypair, StaticKeypair};
pub use kdf::derive_session_keys;
