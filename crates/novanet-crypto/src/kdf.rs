use crate::aead::CryptoError;
use ring::hkdf::{self, KeyType, HKDF_SHA256};

/// Derived session keys after a successful handshake.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
    pub client_write_iv: [u8; 12],
    pub server_write_iv: [u8; 12],
}

struct OutputLen(usize);
impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    prk.expand(&[label], OutputLen(out.len()))
        .map_err(|_| CryptoError::Kdf)?
        .fill(out)
        .map_err(|_| CryptoError::Kdf)
}

/// Derive session keys from a DH shared secret and session ID using HKDF-SHA256.
///
/// The session_id is used as the HKDF salt; the DH secret is the IKM.
/// Four separate expand calls derive client/server write keys and IVs.
pub fn derive_session_keys(
    dh_secret: &[u8],
    session_id: &[u8; 16],
) -> Result<SessionKeys, CryptoError> {
    let salt = hkdf::Salt::new(HKDF_SHA256, session_id);
    let prk = salt.extract(dh_secret);

    let mut client_write_key = [0u8; 32];
    let mut server_write_key = [0u8; 32];
    let mut client_write_iv = [0u8; 12];
    let mut server_write_iv = [0u8; 12];

    hkdf_expand(&prk, b"novanet client key", &mut client_write_key)?;
    hkdf_expand(&prk, b"novanet server key", &mut server_write_key)?;
    hkdf_expand(&prk, b"novanet client iv", &mut client_write_iv)?;
    hkdf_expand(&prk, b"novanet server iv", &mut server_write_iv)?;

    Ok(SessionKeys { client_write_key, server_write_key, client_write_iv, server_write_iv })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let secret = [0xABu8; 32];
        let session_id = [0x01u8; 16];
        let k1 = derive_session_keys(&secret, &session_id).unwrap();
        let k2 = derive_session_keys(&secret, &session_id).unwrap();
        assert_eq!(k1.client_write_key, k2.client_write_key);
        assert_eq!(k1.server_write_key, k2.server_write_key);
        assert_eq!(k1.client_write_iv, k2.client_write_iv);
        assert_eq!(k1.server_write_iv, k2.server_write_iv);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let session_id = [0x01u8; 16];
        let k1 = derive_session_keys(&[0xAAu8; 32], &session_id).unwrap();
        let k2 = derive_session_keys(&[0xBBu8; 32], &session_id).unwrap();
        assert_ne!(k1.client_write_key, k2.client_write_key);
    }

    #[test]
    fn different_session_ids_produce_different_keys() {
        let secret = [0xABu8; 32];
        let k1 = derive_session_keys(&secret, &[0x01u8; 16]).unwrap();
        let k2 = derive_session_keys(&secret, &[0x02u8; 16]).unwrap();
        assert_ne!(k1.client_write_key, k2.client_write_key);
    }

    #[test]
    fn all_four_keys_are_distinct() {
        let secret = [0xCDu8; 32];
        let session_id = [0x42u8; 16];
        let k = derive_session_keys(&secret, &session_id).unwrap();
        // Keys should all be non-zero and mutually distinct
        assert_ne!(k.client_write_key, [0u8; 32]);
        assert_ne!(k.client_write_key, k.server_write_key);
        assert_ne!(k.client_write_iv, k.server_write_iv);
    }
}
