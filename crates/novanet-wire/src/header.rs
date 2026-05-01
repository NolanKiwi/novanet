use bytes::{Buf, BufMut, Bytes, BytesMut};
use novanet_core::{
    constants::{FIXED_HEADER_SIZE, PROTOCOL_VERSION},
    error::{NovaError, NovaResult},
    ids::{PathId, SessionId},
    PacketType,
};

/// The common packet header present in every NovaNet packet.
///
/// Layout (21 bytes fixed):
///   version   (1)
///   pkt_type  (1)
///   flags     (1)
///   hdr_len   (1)  — total header length; if > FIXED_HEADER_SIZE, extension headers follow
///   session_id (16)
///   path_id   (1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: u8,
    /// Total header length including fixed fields and any extension headers.
    /// Minimum value: FIXED_HEADER_SIZE (21).
    pub header_len: u8,
    pub session_id: SessionId,
    pub path_id: PathId,
}

impl PacketHeader {
    pub fn new(packet_type: PacketType, flags: u8, session_id: SessionId, path_id: PathId) -> Self {
        PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            flags,
            header_len: FIXED_HEADER_SIZE as u8,
            session_id,
            path_id,
        }
    }

    /// Encode this header into `buf`. Returns number of bytes written.
    pub fn encode(&self, buf: &mut BytesMut) -> NovaResult<usize> {
        if buf.remaining_mut() < FIXED_HEADER_SIZE {
            return Err(NovaError::BufferTooSmall {
                needed: FIXED_HEADER_SIZE,
                have: buf.remaining_mut(),
            });
        }
        buf.put_u8(self.version);
        buf.put_u8(self.packet_type.as_byte());
        buf.put_u8(self.flags);
        buf.put_u8(self.header_len);
        buf.put_slice(self.session_id.as_bytes());
        buf.put_u8(self.path_id.as_u8());
        Ok(FIXED_HEADER_SIZE)
    }

    /// Decode a header from `buf`. Advances `buf` past the fixed header bytes.
    /// Does NOT consume extension header bytes if header_len > FIXED_HEADER_SIZE.
    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < FIXED_HEADER_SIZE {
            return Err(NovaError::PacketTooShort {
                needed: FIXED_HEADER_SIZE,
                got: buf.remaining(),
            });
        }
        let version = buf.get_u8();
        let type_byte = buf.get_u8();
        let flags = buf.get_u8();
        let header_len = buf.get_u8();
        let mut session_bytes = [0u8; 16];
        buf.copy_to_slice(&mut session_bytes);
        let path_id = buf.get_u8();

        if version != PROTOCOL_VERSION {
            return Err(NovaError::InvalidHeader("unsupported protocol version"));
        }
        if (header_len as usize) < FIXED_HEADER_SIZE {
            return Err(NovaError::InvalidHeader("header_len smaller than fixed header"));
        }

        let packet_type = PacketType::from_byte(type_byte)?;

        Ok(PacketHeader {
            version,
            packet_type,
            flags,
            header_len,
            session_id: SessionId::from_bytes(session_bytes),
            path_id: PathId::new(path_id),
        })
    }

    /// How many extension header bytes follow the fixed header?
    pub fn extension_len(&self) -> usize {
        (self.header_len as usize).saturating_sub(FIXED_HEADER_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use novanet_core::ids::SessionId;

    fn make_header(pt: PacketType) -> PacketHeader {
        PacketHeader::new(pt, 0x00, SessionId::generate(), PathId::INITIAL)
    }

    #[test]
    fn roundtrip_hello() {
        let hdr = make_header(PacketType::Hello);
        let mut buf = BytesMut::with_capacity(64);
        hdr.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = PacketHeader::decode(&mut bytes).unwrap();
        assert_eq!(hdr, decoded);
        assert_eq!(bytes.remaining(), 0, "all header bytes consumed");
    }

    #[test]
    fn roundtrip_all_types() {
        let types = [
            PacketType::Hello,
            PacketType::Retry,
            PacketType::Handshake,
            PacketType::HandshakeDone,
            PacketType::Data,
            PacketType::Ack,
            PacketType::Close,
            PacketType::Error,
            PacketType::PathChallenge,
            PacketType::PathResponse,
        ];
        for pt in types {
            let hdr = make_header(pt);
            let mut buf = BytesMut::with_capacity(64);
            hdr.encode(&mut buf).unwrap();
            let mut bytes = buf.freeze();
            let decoded = PacketHeader::decode(&mut bytes).unwrap();
            assert_eq!(hdr, decoded, "failed roundtrip for {pt}");
        }
    }

    #[test]
    fn decode_truncated_returns_error() {
        let hdr = make_header(PacketType::Data);
        let mut buf = BytesMut::with_capacity(64);
        hdr.encode(&mut buf).unwrap();
        let full = buf.freeze();

        // Try all partial lengths
        for len in 0..FIXED_HEADER_SIZE {
            let mut partial = full.slice(0..len);
            let result = PacketHeader::decode(&mut partial);
            assert!(result.is_err(), "expected error at prefix length {len}");
        }
    }

    #[test]
    fn decode_bad_version_returns_error() {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(0x99); // bad version
        buf.put_u8(PacketType::Data.as_byte());
        buf.put_u8(0x00); // flags
        buf.put_u8(FIXED_HEADER_SIZE as u8); // header_len
        buf.put_bytes(0, 16); // session_id
        buf.put_u8(0); // path_id
        let mut bytes = buf.freeze();
        assert!(PacketHeader::decode(&mut bytes).is_err());
    }

    #[test]
    fn decode_unknown_packet_type_returns_error() {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(PROTOCOL_VERSION);
        buf.put_u8(0xFE); // unknown type
        buf.put_u8(0x00);
        buf.put_u8(FIXED_HEADER_SIZE as u8);
        buf.put_bytes(0, 16);
        buf.put_u8(0);
        let mut bytes = buf.freeze();
        assert!(PacketHeader::decode(&mut bytes).is_err());
    }

    #[test]
    fn decode_header_len_too_small_returns_error() {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(PROTOCOL_VERSION);
        buf.put_u8(PacketType::Data.as_byte());
        buf.put_u8(0x00);
        buf.put_u8(10); // header_len smaller than FIXED_HEADER_SIZE
        buf.put_bytes(0, 16);
        buf.put_u8(0);
        let mut bytes = buf.freeze();
        assert!(PacketHeader::decode(&mut bytes).is_err());
    }

    #[test]
    fn session_id_preserved() {
        let sid = SessionId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ]);
        let hdr = PacketHeader::new(PacketType::Data, 0, sid, PathId::INITIAL);
        let mut buf = BytesMut::with_capacity(64);
        hdr.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = PacketHeader::decode(&mut bytes).unwrap();
        assert_eq!(decoded.session_id, sid);
    }

    #[test]
    fn path_id_preserved() {
        let hdr = PacketHeader::new(
            PacketType::Data,
            0,
            SessionId::generate(),
            PathId::new(7),
        );
        let mut buf = BytesMut::with_capacity(64);
        hdr.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = PacketHeader::decode(&mut bytes).unwrap();
        assert_eq!(decoded.path_id, PathId::new(7));
    }
}
