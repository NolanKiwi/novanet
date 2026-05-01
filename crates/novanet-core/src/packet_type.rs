use crate::error::NovaError;

/// All NovaNet packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    // Handshake
    Hello         = 0x01,
    Retry         = 0x02,
    Handshake     = 0x03,
    HandshakeDone = 0x04,

    // Data path
    Data          = 0x10,
    Ack           = 0x11,
    Nack          = 0x12,

    // Path management
    PathChallenge = 0x20,
    PathResponse  = 0x21,
    Migrate       = 0x22,

    // Key management
    KeyUpdate     = 0x30,

    // Session control
    Close         = 0x40,
    Error         = 0x41,

    // Utility
    Padding       = 0xFF,
}

impl PacketType {
    pub fn from_byte(b: u8) -> Result<Self, NovaError> {
        match b {
            0x01 => Ok(PacketType::Hello),
            0x02 => Ok(PacketType::Retry),
            0x03 => Ok(PacketType::Handshake),
            0x04 => Ok(PacketType::HandshakeDone),
            0x10 => Ok(PacketType::Data),
            0x11 => Ok(PacketType::Ack),
            0x12 => Ok(PacketType::Nack),
            0x20 => Ok(PacketType::PathChallenge),
            0x21 => Ok(PacketType::PathResponse),
            0x22 => Ok(PacketType::Migrate),
            0x30 => Ok(PacketType::KeyUpdate),
            0x40 => Ok(PacketType::Close),
            0x41 => Ok(PacketType::Error),
            0xFF => Ok(PacketType::Padding),
            other => Err(NovaError::UnknownPacketType(other)),
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Whether this packet type carries a packet number.
    pub fn has_packet_number(self) -> bool {
        matches!(
            self,
            PacketType::Data
                | PacketType::Ack
                | PacketType::Nack
                | PacketType::PathChallenge
                | PacketType::PathResponse
                | PacketType::Migrate
                | PacketType::KeyUpdate
                | PacketType::Close
                | PacketType::Error
                | PacketType::HandshakeDone
        )
    }

    /// Whether this packet is part of the handshake phase (not yet encrypted with traffic keys).
    pub fn is_handshake(self) -> bool {
        matches!(
            self,
            PacketType::Hello | PacketType::Retry | PacketType::Handshake | PacketType::HandshakeDone
        )
    }

    /// Whether this packet type can appear in an established session.
    pub fn is_data_phase(self) -> bool {
        !self.is_handshake()
    }
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            PacketType::Hello => "HELLO",
            PacketType::Retry => "RETRY",
            PacketType::Handshake => "HANDSHAKE",
            PacketType::HandshakeDone => "HANDSHAKE_DONE",
            PacketType::Data => "DATA",
            PacketType::Ack => "ACK",
            PacketType::Nack => "NACK",
            PacketType::PathChallenge => "PATH_CHALLENGE",
            PacketType::PathResponse => "PATH_RESPONSE",
            PacketType::Migrate => "MIGRATE",
            PacketType::KeyUpdate => "KEY_UPDATE",
            PacketType::Close => "CLOSE",
            PacketType::Error => "ERROR",
            PacketType::Padding => "PADDING",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_known_types_roundtrip() {
        let types = [
            PacketType::Hello,
            PacketType::Retry,
            PacketType::Handshake,
            PacketType::HandshakeDone,
            PacketType::Data,
            PacketType::Ack,
            PacketType::Nack,
            PacketType::PathChallenge,
            PacketType::PathResponse,
            PacketType::Migrate,
            PacketType::KeyUpdate,
            PacketType::Close,
            PacketType::Error,
            PacketType::Padding,
        ];
        for pt in types {
            let b = pt.as_byte();
            let pt2 = PacketType::from_byte(b).expect("roundtrip should succeed");
            assert_eq!(pt, pt2);
        }
    }

    #[test]
    fn unknown_type_returns_error() {
        assert!(PacketType::from_byte(0x00).is_err());
        assert!(PacketType::from_byte(0x05).is_err());
        assert!(PacketType::from_byte(0xFE).is_err());
    }

    #[test]
    fn packet_number_presence() {
        assert!(!PacketType::Hello.has_packet_number());
        assert!(!PacketType::Retry.has_packet_number());
        assert!(!PacketType::Handshake.has_packet_number());
        assert!(PacketType::HandshakeDone.has_packet_number());
        assert!(PacketType::Data.has_packet_number());
        assert!(PacketType::Ack.has_packet_number());
        assert!(PacketType::Close.has_packet_number());
    }
}
