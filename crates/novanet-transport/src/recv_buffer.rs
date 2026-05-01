use bytes::Bytes;
use std::collections::BTreeMap;

/// Out-of-order stream reassembly buffer.
///
/// Accepts stream segments (offset, data) in any order and delivers in-order
/// data to the application when contiguous segments are available.
pub struct RecvBuffer {
    /// Next byte offset expected by the application.
    next_offset: u64,
    /// Out-of-order segments: byte_offset → data.
    pending: BTreeMap<u64, Bytes>,
    /// Total bytes buffered (for limit enforcement).
    buffered_bytes: usize,
    /// Maximum bytes to buffer.
    max_buffer: usize,
    /// Whether FIN has been received and its byte offset.
    fin_offset: Option<u64>,
}

impl RecvBuffer {
    pub fn new(max_buffer: usize) -> Self {
        RecvBuffer {
            next_offset: 0,
            pending: BTreeMap::new(),
            buffered_bytes: 0,
            max_buffer,
            fin_offset: None,
        }
    }

    /// Insert a stream segment. Returns any contiguous data now ready to deliver.
    ///
    /// `fin` marks this as the last segment.
    pub fn ingest(&mut self, offset: u64, data: Bytes, fin: bool) -> IngestResult {
        if fin {
            let fin_at = offset + data.len() as u64;
            self.fin_offset = Some(fin_at);
        }

        if data.is_empty() && !fin {
            return self.drain();
        }

        // Ignore already-delivered data
        if offset + data.len() as u64 <= self.next_offset {
            return self.drain();
        }

        // Trim leading bytes if segment overlaps with already-delivered data
        let (effective_offset, effective_data) = if offset < self.next_offset {
            let skip = (self.next_offset - offset) as usize;
            (self.next_offset, data.slice(skip..))
        } else {
            (offset, data)
        };

        if effective_data.is_empty() {
            return self.drain();
        }

        // Buffer overflow check
        if self.buffered_bytes + effective_data.len() > self.max_buffer {
            return IngestResult {
                ready_data: Bytes::new(),
                is_finished: false,
                buffer_overflow: true,
            };
        }

        self.buffered_bytes += effective_data.len();
        self.pending.insert(effective_offset, effective_data);

        self.drain()
    }

    /// Drain all contiguous data from next_offset.
    fn drain(&mut self) -> IngestResult {
        let mut ready = Vec::new();

        loop {
            match self.pending.iter().next() {
                Some((&offset, _)) if offset == self.next_offset => {
                    let (_, data) = self.pending.pop_first().unwrap();
                    let len = data.len();
                    self.next_offset += len as u64;
                    self.buffered_bytes -= len;
                    ready.push(data);
                }
                _ => break,
            }
        }

        let is_finished = self.fin_offset.map_or(false, |fin| self.next_offset >= fin);

        IngestResult {
            ready_data: if ready.is_empty() {
                Bytes::new()
            } else if ready.len() == 1 {
                ready.into_iter().next().unwrap()
            } else {
                // Concatenate into one Bytes allocation
                let total: usize = ready.iter().map(|b| b.len()).sum();
                let mut out = bytes::BytesMut::with_capacity(total);
                for chunk in ready {
                    use bytes::BufMut;
                    out.put(chunk);
                }
                out.freeze()
            },
            is_finished,
            buffer_overflow: false,
        }
    }

    pub fn next_expected_offset(&self) -> u64 {
        self.next_offset
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn is_complete(&self) -> bool {
        self.fin_offset.map_or(false, |fin| self.next_offset >= fin)
    }
}

/// Result of ingesting a stream segment.
#[derive(Debug)]
pub struct IngestResult {
    /// Data ready to deliver to the application (may be empty if segment was out-of-order).
    pub ready_data: Bytes,
    /// True if the stream is fully received (FIN reached).
    pub is_finished: bool,
    /// True if the receive buffer is full.
    pub buffer_overflow: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 64 * 1024;

    #[test]
    fn in_order_delivery() {
        let mut buf = RecvBuffer::new(MAX);
        let r = buf.ingest(0, Bytes::from_static(b"hello"), false);
        assert_eq!(r.ready_data.as_ref(), b"hello");
        assert!(!r.is_finished);
        assert_eq!(buf.next_expected_offset(), 5);
    }

    #[test]
    fn out_of_order_then_fill() {
        let mut buf = RecvBuffer::new(MAX);

        // Segment 2 arrives first
        let r1 = buf.ingest(5, Bytes::from_static(b"world"), false);
        assert!(r1.ready_data.is_empty(), "should buffer until 0..5 arrives");

        // Segment 1 fills the gap
        let r2 = buf.ingest(0, Bytes::from_static(b"hello"), false);
        assert_eq!(r2.ready_data.as_ref(), b"helloworld");
        assert_eq!(buf.next_expected_offset(), 10);
    }

    #[test]
    fn fin_detection() {
        let mut buf = RecvBuffer::new(MAX);
        let r = buf.ingest(0, Bytes::from_static(b"done"), true);
        assert_eq!(r.ready_data.as_ref(), b"done");
        assert!(r.is_finished);
        assert!(buf.is_complete());
    }

    #[test]
    fn duplicate_segment_ignored() {
        let mut buf = RecvBuffer::new(MAX);
        buf.ingest(0, Bytes::from_static(b"hello"), false);
        // Deliver offset=0 again (retransmit)
        let r = buf.ingest(0, Bytes::from_static(b"hello"), false);
        assert!(r.ready_data.is_empty(), "duplicate should not re-deliver");
        assert_eq!(buf.next_expected_offset(), 5);
    }

    #[test]
    fn overlapping_segment() {
        let mut buf = RecvBuffer::new(MAX);
        buf.ingest(0, Bytes::from_static(b"hello"), false);
        // Overlapping: starts at 3, repeats " world" but 2 bytes overlap
        let r = buf.ingest(3, Bytes::from_static(b"lo world"), false);
        assert_eq!(r.ready_data.as_ref(), b" world");
        assert_eq!(buf.next_expected_offset(), 11);
    }

    #[test]
    fn buffer_overflow() {
        // max_buffer=9, so a 10-byte out-of-order segment should overflow.
        // The first in-order 5 bytes drain immediately (buffered_bytes stays 0),
        // then the out-of-order 10-byte segment at offset=10 tries to buffer 10 bytes into
        // a 9-byte limit → overflow.
        let mut buf = RecvBuffer::new(9);
        buf.ingest(0, Bytes::from(vec![0u8; 5]), false);
        let r = buf.ingest(10, Bytes::from(vec![0u8; 10]), false);
        assert!(r.buffer_overflow, "should report overflow");
    }

    #[test]
    fn multiple_out_of_order_filled_in_sequence() {
        let mut buf = RecvBuffer::new(MAX);
        // "first"(5) at 0, "secon"(5) at 5, "third"(5) at 10 → "firstseconthird"
        buf.ingest(10, Bytes::from_static(b"third"), false);
        buf.ingest(5, Bytes::from_static(b"secon"), false);
        let r = buf.ingest(0, Bytes::from_static(b"first"), false);
        assert_eq!(r.ready_data.as_ref(), b"firstseconthird");
    }

    #[test]
    fn fin_out_of_order() {
        let mut buf = RecvBuffer::new(MAX);
        // FIN arrives with last data segment, but preceding segment missing
        buf.ingest(5, Bytes::from_static(b"world"), true);
        assert!(!buf.is_complete());
        // Fill the gap
        let r = buf.ingest(0, Bytes::from_static(b"hello"), false);
        assert_eq!(r.ready_data.as_ref(), b"helloworld");
        assert!(r.is_finished);
    }
}
