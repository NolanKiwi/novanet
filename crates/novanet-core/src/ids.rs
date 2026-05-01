use rand::RngCore;
use std::fmt;

/// 128-bit session identifier. Chosen randomly by the client.
/// Not derived from IP addresses or ports.
/// Survives path migration, NAT rebinding, and IP address changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        SessionId(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        SessionId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn zero() -> Self {
        SessionId([0u8; 16])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i == 8 {
                write!(f, "-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 16]> for SessionId {
    fn from(bytes: [u8; 16]) -> Self {
        SessionId(bytes)
    }
}

impl From<SessionId> for [u8; 16] {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

/// 32-byte node identifier. Derived from a long-term Ed25519 public key (SHA-256 hash).
/// Stable across reboots and network changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn zero() -> Self {
        NodeId([0u8; 32])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "...")
    }
}

impl From<[u8; 32]> for NodeId {
    fn from(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }
}

/// 32-byte service identifier. Names a service endpoint on a node.
/// In Phase 1, treated as an opaque label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceId([u8; 32]);

impl ServiceId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ServiceId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn zero() -> Self {
        ServiceId([0u8; 32])
    }

    /// Derive a ServiceId from a human-readable name using a fixed derivation.
    /// This is not cryptographic binding — just a convenient label mapping.
    pub fn from_name(name: &str) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        let h1 = hasher.finish();
        name.len().hash(&mut hasher);
        let h2 = hasher.finish();
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&h1.to_le_bytes());
        bytes[8..16].copy_from_slice(&h2.to_le_bytes());
        bytes[16..24].copy_from_slice(&h1.wrapping_add(h2).to_le_bytes());
        bytes[24..32].copy_from_slice(&h1.wrapping_mul(h2 | 1).to_le_bytes());
        ServiceId(bytes)
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "...")
    }
}

impl From<[u8; 32]> for ServiceId {
    fn from(bytes: [u8; 32]) -> Self {
        ServiceId(bytes)
    }
}

/// 1-byte path identifier within a session.
/// 0x00 = initial/only path. Additional paths use 0x01–0xFF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathId(pub u8);

impl PathId {
    pub const INITIAL: PathId = PathId(0x00);

    pub fn new(id: u8) -> Self {
        PathId(id)
    }

    pub fn as_u8(self) -> u8 {
        self.0
    }
}

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "path:{}", self.0)
    }
}

impl Default for PathId {
    fn default() -> Self {
        PathId::INITIAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_roundtrip() {
        let id = SessionId::generate();
        let bytes: [u8; 16] = id.into();
        let id2 = SessionId::from(bytes);
        assert_eq!(id, id2);
    }

    #[test]
    fn session_id_uniqueness() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        assert_ne!(id1, id2, "Two generated SessionIds must differ");
    }

    #[test]
    fn session_id_display() {
        let id = SessionId::from_bytes([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let s = id.to_string();
        assert!(s.contains('-'), "display should have a dash separator");
        assert_eq!(s.len(), 33); // 32 hex + 1 dash
    }

    #[test]
    fn node_id_zero() {
        let id = NodeId::zero();
        assert!(id.is_zero());
    }

    #[test]
    fn service_id_from_name_is_deterministic() {
        let id1 = ServiceId::from_name("echo");
        let id2 = ServiceId::from_name("echo");
        assert_eq!(id1, id2);
    }

    #[test]
    fn service_id_from_name_differs() {
        let id1 = ServiceId::from_name("echo");
        let id2 = ServiceId::from_name("file-transfer");
        assert_ne!(id1, id2);
    }

    #[test]
    fn path_id_initial() {
        assert_eq!(PathId::INITIAL.as_u8(), 0);
    }
}
