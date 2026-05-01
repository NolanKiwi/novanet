/// AEAD stub for Phase 1. Phase 4 will implement ChaCha20-Poly1305.

pub const AEAD_KEY_SIZE: usize = 32;
pub const AEAD_NONCE_SIZE: usize = 12;
pub const AEAD_TAG_SIZE: usize = 16;

#[derive(Debug, Clone)]
pub struct AeadKey([u8; AEAD_KEY_SIZE]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; AEAD_KEY_SIZE]) -> Self {
        AeadKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; AEAD_KEY_SIZE] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct AeadNonce([u8; AEAD_NONCE_SIZE]);

impl AeadNonce {
    /// Derive nonce from base IV and packet number (XOR construction per spec).
    pub fn from_iv_and_packet_number(iv: &[u8; AEAD_NONCE_SIZE], packet_number: u64) -> Self {
        let mut nonce = *iv;
        let pn_bytes = packet_number.to_be_bytes();
        // XOR packet number (big-endian, zero-padded to 12 bytes) into IV
        for (i, &b) in pn_bytes.iter().enumerate() {
            nonce[AEAD_NONCE_SIZE - 8 + i] ^= b;
        }
        AeadNonce(nonce)
    }

    pub fn as_bytes(&self) -> &[u8; AEAD_NONCE_SIZE] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_derivation_is_deterministic() {
        let iv = [0u8; AEAD_NONCE_SIZE];
        let n1 = AeadNonce::from_iv_and_packet_number(&iv, 42);
        let n2 = AeadNonce::from_iv_and_packet_number(&iv, 42);
        assert_eq!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn nonce_derivation_differs_for_different_pn() {
        let iv = [0u8; AEAD_NONCE_SIZE];
        let n1 = AeadNonce::from_iv_and_packet_number(&iv, 1);
        let n2 = AeadNonce::from_iv_and_packet_number(&iv, 2);
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }
}
