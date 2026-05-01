use bytes::{Buf, BufMut, Bytes, BytesMut};
use novanet_core::error::{NovaError, NovaResult};

/// Frame type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Padding           = 0x00,
    Ack               = 0x01,
    Crypto            = 0x02,
    Stream            = 0x10,
    StreamReset       = 0x11,
    StreamStop        = 0x12,
    Datagram          = 0x20,
    MaxData           = 0x30,
    MaxStreamData     = 0x31,
    DataBlocked       = 0x32,
    StreamDataBlocked = 0x33,
    NewPath           = 0x40,
    PathStatus        = 0x41,
    KeyPhase          = 0x50,
    CloseStream       = 0x60,
}

impl FrameType {
    pub fn from_byte(b: u8) -> Result<Self, NovaError> {
        match b {
            0x00 => Ok(FrameType::Padding),
            0x01 => Ok(FrameType::Ack),
            0x02 => Ok(FrameType::Crypto),
            0x10 => Ok(FrameType::Stream),
            0x11 => Ok(FrameType::StreamReset),
            0x12 => Ok(FrameType::StreamStop),
            0x20 => Ok(FrameType::Datagram),
            0x30 => Ok(FrameType::MaxData),
            0x31 => Ok(FrameType::MaxStreamData),
            0x32 => Ok(FrameType::DataBlocked),
            0x33 => Ok(FrameType::StreamDataBlocked),
            0x40 => Ok(FrameType::NewPath),
            0x41 => Ok(FrameType::PathStatus),
            0x50 => Ok(FrameType::KeyPhase),
            0x60 => Ok(FrameType::CloseStream),
            other => Err(NovaError::UnknownFrameType(other)),
        }
    }
}

/// A single ACK range: packets [start, end] were received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    /// Smallest packet number in this range (inclusive).
    pub start: u64,
    /// Largest packet number in this range (inclusive).
    pub end: u64,
}

impl AckRange {
    pub fn single(pkt: u64) -> Self {
        AckRange { start: pkt, end: pkt }
    }

    pub fn new(start: u64, end: u64) -> Self {
        debug_assert!(start <= end, "AckRange start must be <= end");
        AckRange { start, end }
    }

    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// ACK frame — acknowledges received packets using ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame {
    /// Largest packet number acknowledged.
    pub largest_acked: u64,
    /// ACK delay in microseconds (time between receiving largest_acked and sending this ACK).
    pub ack_delay_us: u32,
    /// List of ACK ranges, ordered largest to smallest.
    /// The first range always ends at largest_acked.
    pub ranges: Vec<AckRange>,
}

impl AckFrame {
    /// Encode this ACK frame into `buf`.
    pub fn encode(&self, buf: &mut BytesMut) -> NovaResult<()> {
        if self.ranges.len() > 255 {
            return Err(NovaError::FrameDecodeError("too many ACK ranges"));
        }
        buf.put_u8(FrameType::Ack as u8);
        buf.put_u8(self.ranges.len() as u8);
        buf.put_u64(self.largest_acked);
        buf.put_u32(self.ack_delay_us);

        // Encode ranges as (gap, ack_length) pairs.
        // First range: end = largest_acked, length = end - start + 1.
        // Subsequent ranges: gap = (prev_start - 1) - current_end, length = end - start + 1.
        let mut prev_start = self.largest_acked + 1;
        for range in &self.ranges {
            let gap = prev_start.saturating_sub(range.end + 1);
            let ack_len = range.len().saturating_sub(1); // stored as length - 1
            buf.put_u64(gap);
            buf.put_u64(ack_len);
            prev_start = range.start;
        }
        Ok(())
    }

    /// Decode an ACK frame from `buf` (type byte already consumed).
    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 13 {
            return Err(NovaError::PacketTooShort { needed: 13, got: buf.remaining() });
        }
        let range_count = buf.get_u8() as usize;
        let largest_acked = buf.get_u64();
        let ack_delay_us = buf.get_u32();

        if buf.remaining() < range_count * 16 {
            return Err(NovaError::PacketTooShort {
                needed: range_count * 16,
                got: buf.remaining(),
            });
        }

        let mut ranges = Vec::with_capacity(range_count);
        let mut prev_start = largest_acked + 1;
        for _ in 0..range_count {
            let gap = buf.get_u64();
            let ack_len = buf.get_u64(); // stored as length - 1
            let end = prev_start.saturating_sub(1).saturating_sub(gap);
            let start = end.saturating_sub(ack_len);
            ranges.push(AckRange { start, end });
            prev_start = start;
        }

        Ok(AckFrame { largest_acked, ack_delay_us, ranges })
    }
}

/// STREAM frame — carries stream data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub stream_id: u32,
    pub offset: u64,
    /// FIN flag: this is the last data on this stream.
    pub fin: bool,
    /// Priority flag.
    pub high_priority: bool,
    pub data: Bytes,
}

impl StreamFrame {
    pub const FLAG_FIN: u8 = 0x01;
    pub const FLAG_PRIORITY: u8 = 0x02;

    pub fn encode(&self, buf: &mut BytesMut) -> NovaResult<()> {
        let mut flags = 0u8;
        if self.fin { flags |= Self::FLAG_FIN; }
        if self.high_priority { flags |= Self::FLAG_PRIORITY; }

        if self.data.len() > u16::MAX as usize {
            return Err(NovaError::PacketTooLarge {
                size: self.data.len(),
                max: u16::MAX as usize,
            });
        }

        buf.put_u8(FrameType::Stream as u8);
        buf.put_u8(flags);
        buf.put_u32(self.stream_id);
        buf.put_u64(self.offset);
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(&self.data);
        Ok(())
    }

    /// Decode a STREAM frame (type byte already consumed).
    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 15 {
            return Err(NovaError::PacketTooShort { needed: 15, got: buf.remaining() });
        }
        let flags = buf.get_u8();
        let stream_id = buf.get_u32();
        let offset = buf.get_u64();
        let data_len = buf.get_u16() as usize;

        if buf.remaining() < data_len {
            return Err(NovaError::PacketTooShort { needed: data_len, got: buf.remaining() });
        }
        let data = buf.copy_to_bytes(data_len);

        Ok(StreamFrame {
            stream_id,
            offset,
            fin: flags & Self::FLAG_FIN != 0,
            high_priority: flags & Self::FLAG_PRIORITY != 0,
            data,
        })
    }
}

/// DATAGRAM frame — unreliable, unordered payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    pub data: Bytes,
}

impl DatagramFrame {
    pub fn encode(&self, buf: &mut BytesMut) -> NovaResult<()> {
        if self.data.len() > u16::MAX as usize {
            return Err(NovaError::PacketTooLarge {
                size: self.data.len(),
                max: u16::MAX as usize,
            });
        }
        buf.put_u8(FrameType::Datagram as u8);
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(&self.data);
        Ok(())
    }

    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 2 {
            return Err(NovaError::PacketTooShort { needed: 2, got: buf.remaining() });
        }
        let data_len = buf.get_u16() as usize;
        if buf.remaining() < data_len {
            return Err(NovaError::PacketTooShort { needed: data_len, got: buf.remaining() });
        }
        let data = buf.copy_to_bytes(data_len);
        Ok(DatagramFrame { data })
    }
}

/// PATH_CHALLENGE or PATH_RESPONSE frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChallengeFrame {
    pub data: [u8; 8],
}

impl PathChallengeFrame {
    pub fn encode(&self, buf: &mut BytesMut, is_response: bool) {
        let ty = if is_response { FrameType::PathStatus } else { FrameType::NewPath };
        buf.put_u8(ty as u8);
        buf.put_slice(&self.data);
    }

    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 8 {
            return Err(NovaError::PacketTooShort { needed: 8, got: buf.remaining() });
        }
        let mut data = [0u8; 8];
        buf.copy_to_slice(&mut data);
        Ok(PathChallengeFrame { data })
    }
}

/// MAX_DATA frame — advertise connection-level flow control credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxDataFrame {
    pub max_data: u64,
}

impl MaxDataFrame {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(FrameType::MaxData as u8);
        buf.put_u64(self.max_data);
    }

    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 8 {
            return Err(NovaError::PacketTooShort { needed: 8, got: buf.remaining() });
        }
        Ok(MaxDataFrame { max_data: buf.get_u64() })
    }
}

/// MAX_STREAM_DATA frame — advertise stream-level flow control credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    pub stream_id: u32,
    pub max_stream_data: u64,
}

impl MaxStreamDataFrame {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(FrameType::MaxStreamData as u8);
        buf.put_u32(self.stream_id);
        buf.put_u64(self.max_stream_data);
    }

    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 12 {
            return Err(NovaError::PacketTooShort { needed: 12, got: buf.remaining() });
        }
        Ok(MaxStreamDataFrame {
            stream_id: buf.get_u32(),
            max_stream_data: buf.get_u64(),
        })
    }
}

/// CLOSE frame payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    pub error_code: u16,
    pub frame_type: u8,
    pub reason: Bytes,
}

impl CloseFrame {
    pub fn encode(&self, buf: &mut BytesMut) -> NovaResult<()> {
        let reason_len = self.reason.len().min(255);
        buf.put_u16(self.error_code);
        buf.put_u8(self.frame_type);
        buf.put_u8(reason_len as u8);
        buf.put_slice(&self.reason[..reason_len]);
        Ok(())
    }

    pub fn decode(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 4 {
            return Err(NovaError::PacketTooShort { needed: 4, got: buf.remaining() });
        }
        let error_code = buf.get_u16();
        let frame_type = buf.get_u8();
        let reason_len = buf.get_u8() as usize;
        if buf.remaining() < reason_len {
            return Err(NovaError::PacketTooShort { needed: reason_len, got: buf.remaining() });
        }
        let reason = buf.copy_to_bytes(reason_len);
        Ok(CloseFrame { error_code, frame_type, reason })
    }
}

/// ERROR frame payload (same format as CLOSE).
pub type ErrorFrame = CloseFrame;

/// A decoded frame from the encrypted payload of a DATA packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding,
    Ack(AckFrame),
    Stream(StreamFrame),
    Datagram(DatagramFrame),
    MaxData(MaxDataFrame),
    MaxStreamData(MaxStreamDataFrame),
    PathChallenge(PathChallengeFrame),
    PathResponse(PathChallengeFrame),
    Close(CloseFrame),
    Error(ErrorFrame),
}

impl Frame {
    /// Decode a single frame from `buf`. Advances `buf` past the frame bytes.
    pub fn decode_one(buf: &mut Bytes) -> NovaResult<Self> {
        if buf.remaining() < 1 {
            return Err(NovaError::PacketTooShort { needed: 1, got: 0 });
        }
        let frame_type_byte = buf.get_u8();
        let frame_type = FrameType::from_byte(frame_type_byte)?;

        match frame_type {
            FrameType::Padding => Ok(Frame::Padding),
            FrameType::Ack => AckFrame::decode(buf).map(Frame::Ack),
            FrameType::Stream => StreamFrame::decode(buf).map(Frame::Stream),
            FrameType::Datagram => DatagramFrame::decode(buf).map(Frame::Datagram),
            FrameType::MaxData => MaxDataFrame::decode(buf).map(Frame::MaxData),
            FrameType::MaxStreamData => MaxStreamDataFrame::decode(buf).map(Frame::MaxStreamData),
            FrameType::NewPath => PathChallengeFrame::decode(buf).map(Frame::PathChallenge),
            FrameType::PathStatus => PathChallengeFrame::decode(buf).map(Frame::PathResponse),
            // Types we acknowledge but haven't fully decoded yet
            FrameType::Crypto
            | FrameType::StreamReset
            | FrameType::StreamStop
            | FrameType::DataBlocked
            | FrameType::StreamDataBlocked
            | FrameType::KeyPhase
            | FrameType::CloseStream => {
                // Treat as unknown but non-fatal in current phase; skip remaining bytes.
                // In production this would be an error for mandatory frames.
                Err(NovaError::FrameDecodeError("frame type not yet implemented"))
            }
        }
    }

    /// Decode all frames from `buf` until it is empty.
    pub fn decode_all(mut buf: Bytes) -> NovaResult<Vec<Frame>> {
        let mut frames = Vec::new();
        while buf.remaining() > 0 {
            // Skip consecutive PADDING bytes efficiently
            if buf.chunk()[0] == 0x00 {
                buf.advance(1);
                frames.push(Frame::Padding);
                continue;
            }
            frames.push(Frame::decode_one(&mut buf)?);
        }
        Ok(frames)
    }

    pub fn encode(&self, buf: &mut BytesMut) -> NovaResult<()> {
        match self {
            Frame::Padding => { buf.put_u8(0x00); Ok(()) }
            Frame::Ack(f) => f.encode(buf),
            Frame::Stream(f) => f.encode(buf),
            Frame::Datagram(f) => f.encode(buf),
            Frame::MaxData(f) => { f.encode(buf); Ok(()) }
            Frame::MaxStreamData(f) => { f.encode(buf); Ok(()) }
            Frame::PathChallenge(f) => { f.encode(buf, false); Ok(()) }
            Frame::PathResponse(f) => { f.encode(buf, true); Ok(()) }
            Frame::Close(f) => f.encode(buf),
            Frame::Error(f) => f.encode(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_frame(frame: Frame) -> Frame {
        let mut buf = BytesMut::with_capacity(256);
        frame.encode(&mut buf).expect("encode succeeded");
        let bytes = buf.freeze();
        let frames = Frame::decode_all(bytes).expect("decode succeeded");
        assert_eq!(frames.len(), 1);
        frames.into_iter().next().unwrap()
    }

    #[test]
    fn stream_frame_roundtrip() {
        let f = Frame::Stream(StreamFrame {
            stream_id: 42,
            offset: 1024,
            fin: true,
            high_priority: false,
            data: Bytes::from_static(b"hello world"),
        });
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn stream_frame_empty_data() {
        let f = Frame::Stream(StreamFrame {
            stream_id: 0,
            offset: 0,
            fin: true,
            high_priority: false,
            data: Bytes::new(),
        });
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn datagram_frame_roundtrip() {
        let f = Frame::Datagram(DatagramFrame {
            data: Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        });
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn ack_frame_roundtrip_single_range() {
        let f = Frame::Ack(AckFrame {
            largest_acked: 10,
            ack_delay_us: 500,
            ranges: vec![AckRange::new(8, 10)],
        });
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn ack_frame_roundtrip_empty_ranges() {
        let f = Frame::Ack(AckFrame {
            largest_acked: 5,
            ack_delay_us: 0,
            ranges: vec![],
        });
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn max_data_frame_roundtrip() {
        let f = Frame::MaxData(MaxDataFrame { max_data: 1_000_000 });
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn max_stream_data_frame_roundtrip() {
        let f = Frame::MaxStreamData(MaxStreamDataFrame {
            stream_id: 3,
            max_stream_data: 65536,
        });
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn padding_frame_roundtrip() {
        let f = Frame::Padding;
        assert_eq!(roundtrip_frame(f.clone()), f);
    }

    #[test]
    fn multiple_padding_frames() {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_bytes(0x00, 5);
        let bytes = buf.freeze();
        let frames = Frame::decode_all(bytes).unwrap();
        assert_eq!(frames.len(), 5);
        assert!(frames.iter().all(|f| *f == Frame::Padding));
    }

    #[test]
    fn decode_truncated_stream_frame() {
        let f = StreamFrame {
            stream_id: 1,
            offset: 0,
            fin: false,
            high_priority: false,
            data: Bytes::from_static(b"data"),
        };
        let mut buf = BytesMut::new();
        f.encode(&mut buf).unwrap();
        let full = buf.freeze();

        // Truncate after frame type byte
        for len in 1..full.len() {
            let partial = full.slice(0..len);
            let result = Frame::decode_all(partial);
            assert!(result.is_err(), "expected error at length {len}");
        }
    }

    #[test]
    fn decode_unknown_frame_type_returns_error() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xEE); // unknown
        let bytes = buf.freeze();
        assert!(Frame::decode_all(bytes).is_err());
    }

    #[test]
    fn decode_multiple_frames() {
        let mut buf = BytesMut::with_capacity(256);
        Frame::Stream(StreamFrame {
            stream_id: 1,
            offset: 0,
            fin: false,
            high_priority: false,
            data: Bytes::from_static(b"abc"),
        }).encode(&mut buf).unwrap();
        Frame::Ack(AckFrame {
            largest_acked: 100,
            ack_delay_us: 1000,
            ranges: vec![AckRange::new(98, 100)],
        }).encode(&mut buf).unwrap();
        Frame::Datagram(DatagramFrame {
            data: Bytes::from_static(b"xyz"),
        }).encode(&mut buf).unwrap();

        let frames = Frame::decode_all(buf.freeze()).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(matches!(frames[0], Frame::Stream(_)));
        assert!(matches!(frames[1], Frame::Ack(_)));
        assert!(matches!(frames[2], Frame::Datagram(_)));
    }

    #[test]
    fn close_frame_roundtrip() {
        let mut buf = BytesMut::new();
        let cf = CloseFrame {
            error_code: 0x0002,
            frame_type: 0x10,
            reason: Bytes::from_static(b"protocol violation"),
        };
        cf.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = CloseFrame::decode(&mut bytes).unwrap();
        assert_eq!(cf, decoded);
    }
}
