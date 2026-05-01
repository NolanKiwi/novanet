use crate::aead::CryptoError;

pub struct SharedSecret(pub Vec<u8>);

/// Ephemeral X25519 keypair for ECDH key exchange.
pub struct EphemeralKeypair {
    private: ring::agreement::EphemeralPrivateKey,
    pub public_bytes: [u8; 32],
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let private =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
                .expect("X25519 key generation should not fail");
        let public = private.compute_public_key().expect("compute_public_key should not fail");
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public.as_ref());
        EphemeralKeypair { private, public_bytes }
    }

    /// Consume the keypair and perform X25519 DH with the peer's public key.
    pub fn agree(self, peer_pk: &[u8; 32]) -> Result<SharedSecret, CryptoError> {
        let peer =
            ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, peer_pk.as_ref());
        ring::agreement::agree_ephemeral(self.private, &peer, |km| SharedSecret(km.to_vec()))
            .map_err(|_| CryptoError::KeyAgreement)
    }
}

impl std::fmt::Debug for EphemeralKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeypair")
            .field("public_bytes", &self.public_bytes)
            .finish_non_exhaustive()
    }
}

/// Long-term Ed25519 keypair for server authentication.
pub struct StaticKeypair {
    keypair: ring::signature::Ed25519KeyPair,
}

impl StaticKeypair {
    pub fn generate() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("Ed25519 pkcs8 generation should not fail");
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .expect("Ed25519 from_pkcs8 should not fail");
        StaticKeypair { keypair }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        use ring::signature::KeyPair;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(self.keypair.public_key().as_ref());
        pk
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig = self.keypair.sign(message);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }
}

impl std::fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StaticKeypair(<opaque>)")
    }
}

/// Verify an Ed25519 signature over `message` with the given 32-byte public key.
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifier =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key.as_ref());
    verifier
        .verify(message, signature.as_ref())
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_key_agreement_produces_same_shared_secret() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let alice_pk = alice.public_bytes;
        let bob_pk = bob.public_bytes;

        let alice_shared = alice.agree(&bob_pk).unwrap();
        let bob_shared = bob.agree(&alice_pk).unwrap();

        assert_eq!(alice_shared.0, bob_shared.0, "DH shared secrets must match");
        assert!(!alice_shared.0.is_empty());
        assert_ne!(alice_shared.0, vec![0u8; alice_shared.0.len()]);
    }

    #[test]
    fn ed25519_sign_and_verify() {
        let kp = StaticKeypair::generate();
        let msg = b"hello novanet";
        let sig = kp.sign(msg);
        let pk = kp.public_key_bytes();
        verify_signature(&pk, msg, &sig).expect("valid signature should verify");
    }

    #[test]
    fn ed25519_verify_fails_on_tampered_message() {
        let kp = StaticKeypair::generate();
        let sig = kp.sign(b"original");
        let pk = kp.public_key_bytes();
        assert!(verify_signature(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn ed25519_verify_fails_on_wrong_key() {
        let kp1 = StaticKeypair::generate();
        let kp2 = StaticKeypair::generate();
        let msg = b"hello";
        let sig = kp1.sign(msg);
        let wrong_pk = kp2.public_key_bytes();
        assert!(verify_signature(&wrong_pk, msg, &sig).is_err());
    }
}
