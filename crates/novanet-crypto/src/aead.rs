use thiserror::Error;

pub const AEAD_KEY_SIZE: usize = 32;
pub const AEAD_NONCE_SIZE: usize = 12;
pub const AEAD_TAG_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD seal failed")]
    Seal,
    #[error("AEAD open failed (authentication tag mismatch or data corrupted)")]
    Open,
    #[error("X25519 key agreement failed")]
    KeyAgreement,
    #[error("Ed25519 signature verification failed")]
    InvalidSignature,
    #[error("key generation failed")]
    KeyGeneration,
    #[error("HKDF key derivation failed")]
    Kdf,
}

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
    /// Derive nonce by XOR-ing the 8-byte packet number (big-endian) into the base IV.
    pub fn from_iv_and_packet_number(iv: &[u8; AEAD_NONCE_SIZE], packet_number: u64) -> Self {
        let mut nonce = *iv;
        let pn_bytes = packet_number.to_be_bytes();
        for (i, &b) in pn_bytes.iter().enumerate() {
            nonce[AEAD_NONCE_SIZE - 8 + i] ^= b;
        }
        AeadNonce(nonce)
    }

    pub fn as_bytes(&self) -> &[u8; AEAD_NONCE_SIZE] {
        &self.0
    }
}

/// Encrypt `data` in-place with ChaCha20-Poly1305, appending the 16-byte authentication tag.
pub fn seal(
    key: &AeadKey,
    nonce: &AeadNonce,
    aad: &[u8],
    data: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key.as_bytes()).map_err(|_| CryptoError::Seal)?;
    let lsk = LessSafeKey::new(unbound);
    let nonce_val = Nonce::assume_unique_for_key(*nonce.as_bytes());
    lsk.seal_in_place_append_tag(nonce_val, Aad::from(aad), data)
        .map_err(|_| CryptoError::Seal)
}

/// Decrypt `data` in-place (ciphertext + 16-byte tag), truncating to the plaintext length.
pub fn open(
    key: &AeadKey,
    nonce: &AeadNonce,
    aad: &[u8],
    data: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
    if data.len() < AEAD_TAG_SIZE {
        return Err(CryptoError::Open);
    }
    let pt_len = data.len() - AEAD_TAG_SIZE;
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key.as_bytes()).map_err(|_| CryptoError::Open)?;
    let lsk = LessSafeKey::new(unbound);
    let nonce_val = Nonce::assume_unique_for_key(*nonce.as_bytes());
    // open_in_place returns a &mut [u8] slice into data; discard it so we can truncate.
    let _ = lsk
        .open_in_place(nonce_val, Aad::from(aad), data.as_mut_slice())
        .map_err(|_| CryptoError::Open)?;
    data.truncate(pt_len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AeadKey {
        AeadKey::from_bytes([0x42u8; AEAD_KEY_SIZE])
    }

    fn test_nonce(pn: u64) -> AeadNonce {
        AeadNonce::from_iv_and_packet_number(&[0x11u8; AEAD_NONCE_SIZE], pn)
    }

    #[test]
    fn nonce_derivation_is_deterministic() {
        let n1 = test_nonce(42);
        let n2 = test_nonce(42);
        assert_eq!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn nonce_differs_for_different_pn() {
        assert_ne!(test_nonce(1).as_bytes(), test_nonce(2).as_bytes());
    }

    #[test]
    fn seal_then_open_roundtrip() {
        let key = test_key();
        let nonce = test_nonce(0);
        let aad = b"session_id_goes_here";
        let plaintext = b"hello encrypted novanet";

        let mut buf = plaintext.to_vec();
        seal(&key, &nonce, aad, &mut buf).expect("seal should succeed");
        assert_eq!(buf.len(), plaintext.len() + AEAD_TAG_SIZE);

        open(&key, &nonce, aad, &mut buf).expect("open should succeed");
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn open_fails_on_tampered_ciphertext() {
        let key = test_key();
        let nonce = test_nonce(0);
        let aad = b"aad";

        let mut buf = b"secret message".to_vec();
        seal(&key, &nonce, aad, &mut buf).unwrap();

        // Flip a bit in the ciphertext
        buf[0] ^= 0xFF;
        assert!(open(&key, &nonce, aad, &mut buf).is_err());
    }

    #[test]
    fn open_fails_on_wrong_aad() {
        let key = test_key();
        let nonce = test_nonce(0);

        let mut buf = b"secret".to_vec();
        seal(&key, &nonce, b"correct_aad", &mut buf).unwrap();
        assert!(open(&key, &nonce, b"wrong_aad", &mut buf).is_err());
    }

    #[test]
    fn open_fails_on_truncated_data() {
        let key = test_key();
        let nonce = test_nonce(0);
        let mut buf = vec![0u8; AEAD_TAG_SIZE - 1]; // too short
        assert!(open(&key, &nonce, b"aad", &mut buf).is_err());
    }
}
