use novanet_core::ids::PathId;
use novanet_wire::frame::Frame;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A single unacknowledged packet in the retransmission queue.
#[derive(Debug, Clone)]
pub struct UnackedPacket {
    pub packet_number: u64,
    pub path_id: PathId,
    pub send_time: Instant,
    /// Original frames; cloned into a new DATA packet on retransmission.
    pub frames: Vec<Frame>,
    pub byte_count: usize,
}

/// Queue of unacknowledged packets, ordered by packet number (ascending).
///
/// Invariants:
///   - Packets are in ascending packet_number order.
///   - Each packet_number appears at most once.
///   - Total in-flight bytes = sum of byte_count for all entries.
#[derive(Debug, Default)]
pub struct RetransmitQueue {
    packets: VecDeque<UnackedPacket>,
    bytes_in_flight: usize,
}

impl RetransmitQueue {
    pub fn new() -> Self {
        RetransmitQueue::default()
    }

    /// Add a new packet to the tail of the queue.
    pub fn push(&mut self, pkt: UnackedPacket) {
        // In normal operation, packets are always added in ascending order.
        debug_assert!(
            self.packets.back().map_or(true, |last| last.packet_number < pkt.packet_number),
            "RetransmitQueue: packet numbers must be strictly increasing"
        );
        self.bytes_in_flight += pkt.byte_count;
        self.packets.push_back(pkt);
    }

    /// Remove all packets acknowledged by an ACK with largest_acked.
    /// Returns the number of packets removed and the byte count freed.
    pub fn on_ack(&mut self, largest_acked: u64) -> AckResult {
        let mut removed = 0;
        let mut bytes_freed = 0;
        let mut rtt_sample: Option<(u64, Instant)> = None;

        while let Some(front) = self.packets.front() {
            if front.packet_number <= largest_acked {
                let pkt = self.packets.pop_front().unwrap();
                self.bytes_in_flight -= pkt.byte_count;
                bytes_freed += pkt.byte_count;
                removed += 1;
                // Only the largest acked packet provides an RTT sample
                if pkt.packet_number == largest_acked {
                    rtt_sample = Some((pkt.packet_number, pkt.send_time));
                }
            } else {
                break;
            }
        }

        AckResult {
            packets_removed: removed,
            bytes_freed,
            rtt_sample_send_time: rtt_sample.map(|(_, t)| t),
        }
    }

    /// Find all packets that should be declared lost due to RTO.
    /// Returns the oldest unacknowledged packet (if any) if it was sent more than `rto` ago.
    pub fn rto_expired(&self, rto: Duration) -> Option<u64> {
        self.packets.front().and_then(|pkt| {
            if pkt.send_time.elapsed() > rto {
                Some(pkt.packet_number)
            } else {
                None
            }
        })
    }

    /// Remove a specific packet by packet_number (e.g., declared lost).
    /// Returns the removed packet if found.
    pub fn remove(&mut self, packet_number: u64) -> Option<UnackedPacket> {
        if let Some(pos) = self.packets.iter().position(|p| p.packet_number == packet_number) {
            let pkt = self.packets.remove(pos).unwrap();
            self.bytes_in_flight -= pkt.byte_count;
            Some(pkt)
        } else {
            None
        }
    }

    /// Total bytes currently in flight (sum of all unacknowledged packet sizes).
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// Number of unacknowledged packets.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Smallest unacknowledged packet number (for RTO timer anchoring).
    pub fn oldest_unacked_pn(&self) -> Option<u64> {
        self.packets.front().map(|p| p.packet_number)
    }

    /// Iterate over unacknowledged packets.
    pub fn iter(&self) -> impl Iterator<Item = &UnackedPacket> {
        self.packets.iter()
    }
}

/// Result of processing an ACK.
#[derive(Debug)]
pub struct AckResult {
    pub packets_removed: usize,
    pub bytes_freed: usize,
    /// Send time of the largest-acked packet, for RTT sampling.
    pub rtt_sample_send_time: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use novanet_core::ids::PathId;

    fn make_pkt(pn: u64, size: usize) -> UnackedPacket {
        UnackedPacket {
            packet_number: pn,
            path_id: PathId::INITIAL,
            send_time: Instant::now(),
            frames: vec![],
            byte_count: size,
        }
    }

    #[test]
    fn push_and_ack_all() {
        let mut q = RetransmitQueue::new();
        q.push(make_pkt(0, 100));
        q.push(make_pkt(1, 200));
        q.push(make_pkt(2, 300));
        assert_eq!(q.bytes_in_flight(), 600);
        assert_eq!(q.len(), 3);

        let result = q.on_ack(2);
        assert_eq!(result.packets_removed, 3);
        assert_eq!(result.bytes_freed, 600);
        assert!(q.is_empty());
        assert_eq!(q.bytes_in_flight(), 0);
    }

    #[test]
    fn ack_partial() {
        let mut q = RetransmitQueue::new();
        q.push(make_pkt(0, 100));
        q.push(make_pkt(1, 200));
        q.push(make_pkt(2, 300));

        let result = q.on_ack(1);
        assert_eq!(result.packets_removed, 2);
        assert_eq!(result.bytes_freed, 300);
        assert_eq!(q.len(), 1);
        assert_eq!(q.bytes_in_flight(), 300);
    }

    #[test]
    fn ack_beyond_queue() {
        let mut q = RetransmitQueue::new();
        q.push(make_pkt(5, 100));
        let result = q.on_ack(100);
        assert_eq!(result.packets_removed, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn ack_empty_queue() {
        let mut q = RetransmitQueue::new();
        let result = q.on_ack(10);
        assert_eq!(result.packets_removed, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn remove_specific_packet() {
        let mut q = RetransmitQueue::new();
        q.push(make_pkt(0, 100));
        q.push(make_pkt(1, 200));
        q.push(make_pkt(2, 300));

        let removed = q.remove(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().packet_number, 1);
        assert_eq!(q.len(), 2);
        assert_eq!(q.bytes_in_flight(), 400);
    }

    #[test]
    fn remove_nonexistent() {
        let mut q = RetransmitQueue::new();
        q.push(make_pkt(0, 100));
        assert!(q.remove(99).is_none());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn rto_not_expired_for_new_packet() {
        let mut q = RetransmitQueue::new();
        q.push(make_pkt(0, 100));
        // A freshly created packet has not exceeded any reasonable RTO
        let expired = q.rto_expired(Duration::from_secs(100));
        assert!(expired.is_none());
    }

    #[test]
    fn oldest_unacked_pn() {
        let mut q = RetransmitQueue::new();
        assert!(q.oldest_unacked_pn().is_none());
        q.push(make_pkt(5, 100));
        q.push(make_pkt(6, 100));
        assert_eq!(q.oldest_unacked_pn(), Some(5));
    }

    #[test]
    fn rtt_sample_is_from_largest_acked() {
        let mut q = RetransmitQueue::new();
        q.push(make_pkt(0, 100));
        q.push(make_pkt(1, 100));
        q.push(make_pkt(2, 100));

        let result = q.on_ack(1);
        // RTT sample should come from packet 1 (largest_acked = 1)
        assert!(result.rtt_sample_send_time.is_some());
    }
}
