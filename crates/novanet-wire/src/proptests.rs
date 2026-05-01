/// Property-based tests for the packet codec.
///
/// These test invariants that must hold for *any* input:
/// - encode(decode(encode(x))) == encode(x)  [round-trip stability]
/// - decode never panics on arbitrary bytes
/// - packet_number is always preserved exactly
/// - session_id is always preserved exactly

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use novanet_core::{
        ids::{PathId, ServiceId, SessionId},
        PacketType,
    };
    use crate::{
        codec::{decode_packet, encode_packet},
        frame::{AckFrame, AckRange, Frame, StreamFrame},
        header::PacketHeader,
        packet::{HelloPayload, NovaPacket, PacketPayload},
    };
    use proptest::prelude::*;

    // --- Arbitrary generators ---

    fn arb_session_id() -> impl Strategy<Value = SessionId> {
        any::<[u8; 16]>().prop_map(SessionId::from_bytes)
    }

    fn arb_path_id() -> impl Strategy<Value = PathId> {
        any::<u8>().prop_map(PathId::new)
    }

    fn arb_stream_data(max_len: usize) -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), 0..=max_len).prop_map(Bytes::from)
    }

    fn arb_stream_frame(max_data: usize) -> impl Strategy<Value = Frame> {
        (
            any::<u32>(),  // stream_id
            any::<u64>(),  // offset
            any::<bool>(), // fin
            any::<bool>(), // high_priority
            arb_stream_data(max_data),
        )
            .prop_map(|(stream_id, offset, fin, high_priority, data)| {
                Frame::Stream(StreamFrame {
                    stream_id,
                    offset,
                    fin,
                    high_priority,
                    data,
                })
            })
    }

    fn arb_ack_ranges() -> impl Strategy<Value = Vec<AckRange>> {
        // Generate up to 8 non-overlapping ACK ranges in descending order
        prop::collection::vec((any::<u32>(), 1u32..=50u32), 0..8).prop_map(|pairs| {
            let mut ranges = Vec::new();
            let mut pos: u64 = 1000;
            for (gap, len) in pairs {
                let end = pos;
                let start = pos.saturating_sub(len as u64 - 1);
                ranges.push(AckRange::new(start, end));
                pos = pos.saturating_sub(len as u64 + gap as u64 + 1);
                if pos == 0 {
                    break;
                }
            }
            ranges
        })
    }

    fn arb_ack_frame() -> impl Strategy<Value = Frame> {
        (1000u64..10000u64, any::<u32>(), arb_ack_ranges()).prop_map(
            |(largest, delay, ranges)| {
                Frame::Ack(AckFrame {
                    largest_acked: largest,
                    ack_delay_us: delay,
                    ranges,
                })
            },
        )
    }

    fn arb_frames(max_data: usize) -> impl Strategy<Value = Vec<Frame>> {
        prop::collection::vec(
            prop_oneof![
                arb_stream_frame(max_data),
                arb_ack_frame(),
                Just(Frame::Padding),
            ],
            0..5,
        )
    }

    fn arb_data_packet(max_data: usize) -> impl Strategy<Value = NovaPacket> {
        (
            arb_session_id(),
            arb_path_id(),
            any::<u64>(),
            arb_frames(max_data),
        )
            .prop_map(|(session_id, path_id, pn, frames)| NovaPacket {
                header: PacketHeader::new(PacketType::Data, 0, session_id, path_id),
                packet_number: Some(pn),
                payload: PacketPayload::Data(frames),
            })
    }

    fn arb_hello_packet() -> impl Strategy<Value = NovaPacket> {
        arb_session_id().prop_map(|session_id| NovaPacket {
            header: PacketHeader::new(PacketType::Hello, 0, session_id, PathId::INITIAL),
            packet_number: None,
            payload: PacketPayload::Hello(HelloPayload::unauthenticated(
                ServiceId::from_name("proptest"),
            )),
        })
    }

    // --- Properties ---

    proptest! {
        #[test]
        fn data_packet_roundtrip(packet in arb_data_packet(500)) {
            let mut buf = BytesMut::with_capacity(1200);
            // Skip packets too large for our MTU (generated frames might be large)
            if encode_packet(&packet, &mut buf).is_err() {
                return Ok(());
            }
            let bytes = buf.freeze();
            let decoded = decode_packet(bytes).expect("decode should succeed");
            prop_assert_eq!(decoded.header.session_id, packet.header.session_id);
            prop_assert_eq!(decoded.packet_number, packet.packet_number);
            prop_assert_eq!(decoded.header.path_id, packet.header.path_id);
        }

        #[test]
        fn hello_packet_roundtrip(packet in arb_hello_packet()) {
            let mut buf = BytesMut::with_capacity(1200);
            encode_packet(&packet, &mut buf).expect("hello encode");
            let bytes = buf.freeze();
            let decoded = decode_packet(bytes).expect("hello decode");
            prop_assert_eq!(decoded.header.session_id, packet.header.session_id);
            prop_assert!(decoded.packet_number.is_none());
        }

        #[test]
        fn packet_number_preserved_exactly(pn in any::<u64>()) {
            let session_id = SessionId::from_bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
            let packet = NovaPacket {
                header: PacketHeader::new(PacketType::Data, 0, session_id, PathId::INITIAL),
                packet_number: Some(pn),
                payload: PacketPayload::Data(vec![]),
            };
            let mut buf = BytesMut::with_capacity(256);
            encode_packet(&packet, &mut buf).unwrap();
            let decoded = decode_packet(buf.freeze()).unwrap();
            prop_assert_eq!(decoded.packet_number, Some(pn));
        }

        #[test]
        fn session_id_preserved_exactly(bytes in any::<[u8; 16]>()) {
            let session_id = SessionId::from_bytes(bytes);
            let packet = NovaPacket {
                header: PacketHeader::new(PacketType::Data, 0, session_id, PathId::INITIAL),
                packet_number: Some(0),
                payload: PacketPayload::Data(vec![]),
            };
            let mut buf = BytesMut::with_capacity(256);
            encode_packet(&packet, &mut buf).unwrap();
            let decoded = decode_packet(buf.freeze()).unwrap();
            prop_assert_eq!(decoded.header.session_id, session_id);
        }

        #[test]
        fn decode_arbitrary_bytes_never_panics(raw in prop::collection::vec(any::<u8>(), 0..1200)) {
            // decode should return Err, not panic, on any input
            let _ = decode_packet(Bytes::from(raw));
        }

        #[test]
        fn encode_decode_encode_is_stable(packet in arb_data_packet(200)) {
            let mut buf1 = BytesMut::with_capacity(1200);
            if encode_packet(&packet, &mut buf1).is_err() {
                return Ok(());
            }
            let bytes1 = buf1.freeze();

            let decoded = decode_packet(bytes1.clone()).expect("first decode");
            let mut buf2 = BytesMut::with_capacity(1200);
            encode_packet(&decoded, &mut buf2).expect("re-encode");
            let bytes2 = buf2.freeze();

            // The wire bytes must be identical (deterministic encoding)
            prop_assert_eq!(bytes1, bytes2);
        }

        #[test]
        fn ack_frame_roundtrip_arbitrary(
            largest in 0u64..100000u64,
            delay in any::<u32>(),
            ranges in arb_ack_ranges()
        ) {
            use crate::frame::{AckFrame, Frame};
            let frame = Frame::Ack(AckFrame {
                largest_acked: largest,
                ack_delay_us: delay,
                ranges,
            });
            let mut buf = BytesMut::with_capacity(512);
            frame.encode(&mut buf).unwrap();
            let decoded_frames = Frame::decode_all(buf.freeze()).unwrap();
            prop_assert_eq!(decoded_frames.len(), 1);
            if let Frame::Ack(a) = &decoded_frames[0] {
                prop_assert_eq!(a.largest_acked, largest);
                prop_assert_eq!(a.ack_delay_us, delay);
            } else {
                return Err(TestCaseError::fail("expected ACK frame"));
            }
        }
    }
}
