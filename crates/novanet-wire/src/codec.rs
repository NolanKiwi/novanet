/// Top-level encode/decode for complete NovaNet packets.
///
/// In Phase 1 (no crypto), packets are encoded/decoded without encryption.
/// In Phase 4+, the codec layer will apply AEAD encryption/decryption between
/// frame serialization and UDP I/O.
use bytes::{Buf, BufMut, Bytes, BytesMut};
use novanet_core::{
    constants::{FIXED_HEADER_SIZE, MAX_UDP_PAYLOAD},
    error::{NovaError, NovaResult},
    ids::{NodeId, ServiceId},
    PacketType,
};

use crate::{
    frame::{CloseFrame, Frame},
    header::PacketHeader,
    packet::{
        ClosePayload, HandshakePayload, HelloPayload, NovaPacket, PacketPayload,
        PathChallengePayload, RetryPayload,
    },
};

/// Encode a complete NovaNet packet into a `BytesMut`.
///
/// In Phase 1, this does no encryption. The returned bytes are ready to send over UDP.
pub fn encode_packet(packet: &NovaPacket, buf: &mut BytesMut) -> NovaResult<usize> {
    let start_len = buf.len();

    packet.header.encode(buf)?;

    if let Some(pn) = packet.packet_number {
        buf.put_u64(pn);
    }

    encode_payload(&packet.payload, buf)?;

    let written = buf.len() - start_len;
    if written > MAX_UDP_PAYLOAD {
        return Err(NovaError::PacketTooLarge {
            size: written,
            max: MAX_UDP_PAYLOAD,
        });
    }
    Ok(written)
}

fn encode_payload(payload: &PacketPayload, buf: &mut BytesMut) -> NovaResult<()> {
    match payload {
        PacketPayload::Hello(p) => encode_hello(p, buf),
        PacketPayload::Retry(p) => encode_retry(p, buf),
        PacketPayload::Handshake(p) => encode_handshake(p, buf),
        PacketPayload::HandshakeDone => Ok(()),
        PacketPayload::Data(frames) | PacketPayload::Ack(frames) => {
            for frame in frames {
                frame.encode(buf)?;
            }
            Ok(())
        }
        PacketPayload::PathChallenge(p) | PacketPayload::PathResponse(p) => {
            buf.put_slice(&p.data);
            Ok(())
        }
        PacketPayload::Close(p) | PacketPayload::Error(p) => p.inner.encode(buf),
        PacketPayload::Padding { count } => {
            buf.put_bytes(0x00, *count);
            Ok(())
        }
    }
}

fn encode_hello(p: &HelloPayload, buf: &mut BytesMut) -> NovaResult<()> {
    buf.put_slice(&p.client_ephemeral_pk);
    buf.put_slice(p.client_node_id.as_bytes());
    buf.put_slice(p.desired_service_id.as_bytes());
    let token_len = p.retry_token.len().min(255) as u8;
    buf.put_u8(token_len);
    buf.put_slice(&p.retry_token[..token_len as usize]);
    let ver_len = p.supported_versions.len().min(255) as u8;
    buf.put_u8(ver_len);
    buf.put_slice(&p.supported_versions[..ver_len as usize]);
    Ok(())
}

fn encode_retry(p: &RetryPayload, buf: &mut BytesMut) -> NovaResult<()> {
    let token_len = p.retry_token.len().min(255) as u8;
    buf.put_u8(token_len);
    buf.put_slice(&p.retry_token[..token_len as usize]);
    Ok(())
}

fn encode_handshake(p: &HandshakePayload, buf: &mut BytesMut) -> NovaResult<()> {
    // Fixed layout: server_ephemeral_pk(32) || server_static_pk(32) || server_signature(64) = 128 bytes
    buf.put_slice(&p.server_ephemeral_pk);
    buf.put_slice(&p.server_static_pk);
    buf.put_slice(&p.server_signature);
    Ok(())
}

/// Decode a complete NovaNet packet from a UDP payload.
///
/// In Phase 1, no decryption is applied.
pub fn decode_packet(mut buf: Bytes) -> NovaResult<NovaPacket> {
    if buf.remaining() < FIXED_HEADER_SIZE {
        return Err(NovaError::PacketTooShort {
            needed: FIXED_HEADER_SIZE,
            got: buf.remaining(),
        });
    }

    let header = PacketHeader::decode(&mut buf)?;

    // Skip extension headers if any
    let ext_len = header.extension_len();
    if buf.remaining() < ext_len {
        return Err(NovaError::PacketTooShort {
            needed: ext_len,
            got: buf.remaining(),
        });
    }
    buf.advance(ext_len);

    // Read packet number for types that have one
    let packet_number = if header.packet_type.has_packet_number() {
        if buf.remaining() < 8 {
            return Err(NovaError::PacketTooShort { needed: 8, got: buf.remaining() });
        }
        Some(buf.get_u64())
    } else {
        None
    };

    // Decode payload based on packet type
    let payload = decode_payload(header.packet_type, buf)?;

    Ok(NovaPacket { header, packet_number, payload })
}

fn decode_payload(packet_type: PacketType, buf: Bytes) -> NovaResult<PacketPayload> {
    match packet_type {
        PacketType::Hello => decode_hello(buf).map(PacketPayload::Hello),
        PacketType::Retry => decode_retry(buf).map(PacketPayload::Retry),
        PacketType::Handshake => decode_handshake(buf).map(PacketPayload::Handshake),
        PacketType::HandshakeDone => Ok(PacketPayload::HandshakeDone),
        PacketType::Data => Frame::decode_all(buf).map(PacketPayload::Data),
        PacketType::Ack => Frame::decode_all(buf).map(PacketPayload::Ack),
        PacketType::PathChallenge => decode_path_challenge(buf).map(PacketPayload::PathChallenge),
        PacketType::PathResponse => decode_path_challenge(buf).map(PacketPayload::PathResponse),
        PacketType::Close => decode_close(buf).map(PacketPayload::Close),
        PacketType::Error => decode_close(buf).map(PacketPayload::Error),
        PacketType::Padding => {
            let count = buf.remaining();
            Ok(PacketPayload::Padding { count })
        }
        PacketType::Nack
        | PacketType::Migrate
        | PacketType::KeyUpdate => {
            // Known but not yet implemented; return raw frames if any
            Frame::decode_all(buf).map(PacketPayload::Data)
        }
    }
}

fn decode_hello(mut buf: Bytes) -> NovaResult<HelloPayload> {
    // ephemeral pk (32) + node_id (32) + service_id (32) = 96 minimum
    if buf.remaining() < 96 {
        return Err(NovaError::PacketTooShort { needed: 96, got: buf.remaining() });
    }
    let mut ephem = [0u8; 32];
    buf.copy_to_slice(&mut ephem);
    let mut node_bytes = [0u8; 32];
    buf.copy_to_slice(&mut node_bytes);
    let mut svc_bytes = [0u8; 32];
    buf.copy_to_slice(&mut svc_bytes);

    if buf.remaining() < 1 {
        return Err(NovaError::PacketTooShort { needed: 1, got: 0 });
    }
    let token_len = buf.get_u8() as usize;
    if buf.remaining() < token_len {
        return Err(NovaError::PacketTooShort { needed: token_len, got: buf.remaining() });
    }
    let retry_token = buf.copy_to_bytes(token_len).to_vec();

    if buf.remaining() < 1 {
        return Err(NovaError::PacketTooShort { needed: 1, got: 0 });
    }
    let ver_len = buf.get_u8() as usize;
    if buf.remaining() < ver_len {
        return Err(NovaError::PacketTooShort { needed: ver_len, got: buf.remaining() });
    }
    let supported_versions = buf.copy_to_bytes(ver_len).to_vec();

    Ok(HelloPayload {
        client_ephemeral_pk: ephem,
        client_node_id: NodeId::from_bytes(node_bytes),
        desired_service_id: ServiceId::from_bytes(svc_bytes),
        retry_token,
        supported_versions,
    })
}

fn decode_retry(mut buf: Bytes) -> NovaResult<RetryPayload> {
    if buf.remaining() < 1 {
        return Err(NovaError::PacketTooShort { needed: 1, got: 0 });
    }
    let token_len = buf.get_u8() as usize;
    if buf.remaining() < token_len {
        return Err(NovaError::PacketTooShort { needed: token_len, got: buf.remaining() });
    }
    let retry_token = buf.copy_to_bytes(token_len).to_vec();
    Ok(RetryPayload { retry_token })
}

fn decode_handshake(mut buf: Bytes) -> NovaResult<HandshakePayload> {
    // Fixed layout: server_ephemeral_pk(32) || server_static_pk(32) || server_signature(64) = 128 bytes
    const HS_SIZE: usize = 32 + 32 + 64;
    if buf.remaining() < HS_SIZE {
        return Err(NovaError::PacketTooShort { needed: HS_SIZE, got: buf.remaining() });
    }
    let mut server_ephemeral_pk = [0u8; 32];
    let mut server_static_pk = [0u8; 32];
    let mut server_signature = [0u8; 64];
    buf.copy_to_slice(&mut server_ephemeral_pk);
    buf.copy_to_slice(&mut server_static_pk);
    buf.copy_to_slice(&mut server_signature);
    Ok(HandshakePayload { server_ephemeral_pk, server_static_pk, server_signature })
}

fn decode_path_challenge(mut buf: Bytes) -> NovaResult<PathChallengePayload> {
    if buf.remaining() < 8 {
        return Err(NovaError::PacketTooShort { needed: 8, got: buf.remaining() });
    }
    let mut data = [0u8; 8];
    buf.copy_to_slice(&mut data);
    Ok(PathChallengePayload { data })
}

fn decode_close(buf: Bytes) -> NovaResult<ClosePayload> {
    let mut b = buf;
    CloseFrame::decode(&mut b).map(|inner| ClosePayload { inner })
}

/// Estimate the minimum number of bytes needed to encode a packet.
pub fn min_encoded_size(packet_type: PacketType, has_frames: bool) -> usize {
    let mut size = FIXED_HEADER_SIZE;
    if packet_type.has_packet_number() {
        size += 8;
    }
    if has_frames {
        size += 1; // at least one frame type byte
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;
    use novanet_core::{ids::{PathId, SessionId, ServiceId}, PacketType};
    use crate::{frame::{AckFrame, AckRange, StreamFrame}, header::PacketHeader, packet::*};
    use bytes::Bytes;

    fn make_header(pt: PacketType) -> PacketHeader {
        PacketHeader::new(pt, 0, SessionId::generate(), PathId::INITIAL)
    }

    fn roundtrip(packet: NovaPacket) -> NovaPacket {
        let mut buf = BytesMut::with_capacity(1200);
        encode_packet(&packet, &mut buf).expect("encode");
        let bytes = buf.freeze();
        decode_packet(bytes).expect("decode")
    }

    #[test]
    fn hello_roundtrip() {
        let svc = ServiceId::from_name("echo");
        let packet = NovaPacket {
            header: make_header(PacketType::Hello),
            packet_number: None,
            payload: PacketPayload::Hello(HelloPayload::unauthenticated(svc)),
        };
        let decoded = roundtrip(packet.clone());
        assert_eq!(packet.header.session_id, decoded.header.session_id);
        assert_eq!(packet.packet_number, decoded.packet_number);
        assert_eq!(packet.payload, decoded.payload);
    }

    #[test]
    fn handshake_done_roundtrip() {
        let packet = NovaPacket {
            header: make_header(PacketType::HandshakeDone),
            packet_number: Some(0),
            payload: PacketPayload::HandshakeDone,
        };
        let decoded = roundtrip(packet.clone());
        assert_eq!(decoded.payload, PacketPayload::HandshakeDone);
        assert_eq!(decoded.packet_number, Some(0));
    }

    #[test]
    fn data_with_stream_frame_roundtrip() {
        let packet = NovaPacket {
            header: make_header(PacketType::Data),
            packet_number: Some(42),
            payload: PacketPayload::Data(vec![
                Frame::Stream(StreamFrame {
                    stream_id: 0,
                    offset: 0,
                    fin: false,
                    high_priority: false,
                    data: Bytes::from_static(b"hello, novanet!"),
                }),
            ]),
        };
        let decoded = roundtrip(packet.clone());
        assert_eq!(decoded.packet_number, Some(42));
        if let PacketPayload::Data(frames) = decoded.payload {
            assert_eq!(frames.len(), 1);
            if let Frame::Stream(sf) = &frames[0] {
                assert_eq!(sf.data.as_ref(), b"hello, novanet!");
                assert_eq!(sf.stream_id, 0);
            } else {
                panic!("expected stream frame");
            }
        } else {
            panic!("expected data payload");
        }
    }

    #[test]
    fn ack_packet_roundtrip() {
        let packet = NovaPacket {
            header: make_header(PacketType::Ack),
            packet_number: Some(100),
            payload: PacketPayload::Ack(vec![
                Frame::Ack(AckFrame {
                    largest_acked: 99,
                    ack_delay_us: 250,
                    ranges: vec![AckRange::new(95, 99)],
                }),
            ]),
        };
        let decoded = roundtrip(packet);
        assert_eq!(decoded.packet_number, Some(100));
        if let PacketPayload::Ack(frames) = decoded.payload {
            assert_eq!(frames.len(), 1);
        } else {
            panic!("expected ack payload");
        }
    }

    #[test]
    fn close_packet_roundtrip() {
        let packet = NovaPacket {
            header: make_header(PacketType::Close),
            packet_number: Some(200),
            payload: PacketPayload::Close(ClosePayload {
                inner: crate::frame::CloseFrame {
                    error_code: 0x0000,
                    frame_type: 0,
                    reason: Bytes::from_static(b"graceful close"),
                },
            }),
        };
        let decoded = roundtrip(packet);
        if let PacketPayload::Close(cp) = decoded.payload {
            assert_eq!(cp.inner.error_code, 0x0000);
            assert_eq!(cp.inner.reason.as_ref(), b"graceful close");
        } else {
            panic!("expected close payload");
        }
    }

    #[test]
    fn path_challenge_roundtrip() {
        let challenge_data = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
        let packet = NovaPacket {
            header: make_header(PacketType::PathChallenge),
            packet_number: Some(1),
            payload: PacketPayload::PathChallenge(PathChallengePayload { data: challenge_data }),
        };
        let decoded = roundtrip(packet);
        if let PacketPayload::PathChallenge(p) = decoded.payload {
            assert_eq!(p.data, challenge_data);
        } else {
            panic!("expected path challenge payload");
        }
    }

    #[test]
    fn packet_number_preserved() {
        for pn in [0u64, 1, 100, u64::MAX - 1, u64::MAX] {
            let packet = NovaPacket {
                header: make_header(PacketType::Data),
                packet_number: Some(pn),
                payload: PacketPayload::Data(vec![]),
            };
            let decoded = roundtrip(packet);
            assert_eq!(decoded.packet_number, Some(pn), "packet number {pn} not preserved");
        }
    }

    #[test]
    fn session_id_preserved_across_types() {
        let sid = SessionId::from_bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
        let types = [PacketType::Hello, PacketType::Data, PacketType::Close];
        for pt in types {
            let header = PacketHeader::new(pt, 0, sid, PathId::INITIAL);
            let pn = if pt.has_packet_number() { Some(0) } else { None };
            let payload = match pt {
                PacketType::Hello => PacketPayload::Hello(HelloPayload::unauthenticated(
                    ServiceId::from_name("test"),
                )),
                PacketType::Data => PacketPayload::Data(vec![]),
                PacketType::Close => PacketPayload::Close(ClosePayload {
                    inner: crate::frame::CloseFrame {
                        error_code: 0,
                        frame_type: 0,
                        reason: Bytes::new(),
                    },
                }),
                _ => unreachable!(),
            };
            let packet = NovaPacket { header, packet_number: pn, payload };
            let decoded = roundtrip(packet);
            assert_eq!(decoded.header.session_id, sid, "session_id not preserved for {pt}");
        }
    }

    #[test]
    fn decode_empty_bytes_returns_error() {
        assert!(decode_packet(Bytes::new()).is_err());
    }

    #[test]
    fn decode_too_short_returns_error() {
        for len in 1..FIXED_HEADER_SIZE {
            let buf = Bytes::from(vec![0u8; len]);
            assert!(decode_packet(buf).is_err(), "expected error for {len} bytes");
        }
    }

    #[test]
    fn encode_rejects_oversized_packet() {
        // A DATA packet with a huge payload should exceed MAX_UDP_PAYLOAD
        let big_data = Bytes::from(vec![0u8; MAX_UDP_PAYLOAD]);
        let packet = NovaPacket {
            header: make_header(PacketType::Data),
            packet_number: Some(1),
            payload: PacketPayload::Data(vec![
                Frame::Stream(StreamFrame {
                    stream_id: 0,
                    offset: 0,
                    fin: false,
                    high_priority: false,
                    data: big_data,
                }),
            ]),
        };
        let mut buf = BytesMut::new();
        assert!(encode_packet(&packet, &mut buf).is_err());
    }

    #[test]
    fn retry_packet_roundtrip() {
        let token = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let packet = NovaPacket {
            header: make_header(PacketType::Retry),
            packet_number: None,
            payload: PacketPayload::Retry(RetryPayload { retry_token: token.clone() }),
        };
        let decoded = roundtrip(packet);
        if let PacketPayload::Retry(r) = decoded.payload {
            assert_eq!(r.retry_token, token);
        } else {
            panic!("expected retry payload");
        }
    }

    #[test]
    fn multi_frame_data_packet() {
        let packet = NovaPacket {
            header: make_header(PacketType::Data),
            packet_number: Some(5),
            payload: PacketPayload::Data(vec![
                Frame::Stream(StreamFrame {
                    stream_id: 1,
                    offset: 100,
                    fin: false,
                    high_priority: false,
                    data: Bytes::from_static(b"first"),
                }),
                Frame::Stream(StreamFrame {
                    stream_id: 2,
                    offset: 0,
                    fin: true,
                    high_priority: true,
                    data: Bytes::from_static(b"second"),
                }),
                Frame::Ack(AckFrame {
                    largest_acked: 4,
                    ack_delay_us: 100,
                    ranges: vec![AckRange::new(1, 4)],
                }),
            ]),
        };
        let decoded = roundtrip(packet);
        if let PacketPayload::Data(frames) = decoded.payload {
            assert_eq!(frames.len(), 3);
        } else {
            panic!("expected data payload with 3 frames");
        }
    }
}
