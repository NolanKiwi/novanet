use novanet_core::{
    constants::{INITIAL_RTT_MS, MAX_SESSION_IDLE_SECS},
    ids::{PathId, SessionId},
};
use std::time::{Duration, Instant};

use crate::retransmit::RetransmitQueue;

/// Session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Initial,
    Handshaking,
    Established,
    Migrating,
    Draining,
    Closed,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Initial => write!(f, "initial"),
            SessionStatus::Handshaking => write!(f, "handshaking"),
            SessionStatus::Established => write!(f, "established"),
            SessionStatus::Migrating => write!(f, "migrating"),
            SessionStatus::Draining => write!(f, "draining"),
            SessionStatus::Closed => write!(f, "closed"),
        }
    }
}

/// RTT estimator (RFC 6298 style) per session/path.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT.
    pub srtt: Duration,
    /// RTT variance.
    pub rttvar: Duration,
    /// Minimum observed RTT.
    pub min_rtt: Duration,
    /// Whether we have any samples yet.
    initialized: bool,
}

impl RttEstimator {
    pub fn new() -> Self {
        let initial = Duration::from_millis(INITIAL_RTT_MS);
        RttEstimator {
            srtt: initial,
            rttvar: initial / 2,
            min_rtt: initial,
            initialized: false,
        }
    }

    /// Update estimates with a new RTT sample (already corrected for ACK delay).
    pub fn update(&mut self, sample: Duration) {
        if !self.initialized {
            self.srtt = sample;
            self.rttvar = sample / 2;
            self.min_rtt = sample;
            self.initialized = true;
            return;
        }

        if sample < self.min_rtt {
            self.min_rtt = sample;
        }

        let srtt_secs = self.srtt.as_secs_f64();
        let var_secs = self.rttvar.as_secs_f64();
        let sample_secs = sample.as_secs_f64();

        let new_var = (1.0 - 0.25) * var_secs + 0.25 * (srtt_secs - sample_secs).abs();
        let new_srtt = (1.0 - 0.125) * srtt_secs + 0.125 * sample_secs;

        self.rttvar = Duration::from_secs_f64(new_var.max(0.0));
        self.srtt = Duration::from_secs_f64(new_srtt.max(0.001)); // min 1ms
    }

    /// Current RTO (RFC 6298).
    pub fn rto(&self) -> Duration {
        let rto = self.srtt + 4 * self.rttvar;
        rto.max(Duration::from_millis(200))
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-stream state tracked by the session.
#[derive(Debug)]
pub struct StreamInfo {
    pub stream_id: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_fin: bool,
    pub recv_fin: bool,
}

impl StreamInfo {
    pub fn new(stream_id: u32) -> Self {
        StreamInfo {
            stream_id,
            bytes_sent: 0,
            bytes_received: 0,
            send_fin: false,
            recv_fin: false,
        }
    }
}

/// In-memory state for a single NovaNet session.
#[derive(Debug)]
pub struct SessionState {
    pub session_id: SessionId,
    pub status: SessionStatus,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub remote_addr: Option<std::net::SocketAddr>,

    // Packet number tracking
    pub next_send_pn: u64,
    pub largest_received_pn: u64,
    pub received_bitmap: u128,   // sliding window of received packet numbers

    // RTT
    pub rtt: RttEstimator,

    // Streams
    pub streams: Vec<StreamInfo>,

    // Bytes counters
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub retransmissions: u64,

    // Active path
    pub active_path: PathId,

    // Idle timeout
    pub idle_timeout: Duration,

    // Retransmission queue (unacknowledged outgoing packets)
    pub retransmit: RetransmitQueue,

    // Duplicate-ACK tracking for fast retransmit
    pub last_acked: u64,
    pub dup_ack_count: u32,
}

impl SessionState {
    pub fn new(session_id: SessionId) -> Self {
        let now = Instant::now();
        SessionState {
            session_id,
            status: SessionStatus::Initial,
            created_at: now,
            last_activity: now,
            remote_addr: None,
            next_send_pn: 0,
            largest_received_pn: 0,
            received_bitmap: 0,
            rtt: RttEstimator::new(),
            streams: Vec::new(),
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            retransmissions: 0,
            active_path: PathId::INITIAL,
            idle_timeout: Duration::from_secs(MAX_SESSION_IDLE_SECS),
            retransmit: RetransmitQueue::new(),
            last_acked: 0,
            dup_ack_count: 0,
        }
    }

    pub fn is_established(&self) -> bool {
        self.status == SessionStatus::Established
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.status, SessionStatus::Closed | SessionStatus::Draining)
    }

    /// Get and increment the next outgoing packet number.
    pub fn next_packet_number(&mut self) -> u64 {
        let pn = self.next_send_pn;
        self.next_send_pn += 1;
        pn
    }

    /// Record receipt of a packet number. Returns true if it's new (not a duplicate/replay).
    pub fn record_received(&mut self, pn: u64) -> bool {
        if pn < self.largest_received_pn.saturating_sub(127) {
            // Far outside the window; treat as replay
            return false;
        }

        if pn > self.largest_received_pn {
            // Shift the window forward
            let shift = pn - self.largest_received_pn;
            if shift >= 128 {
                self.received_bitmap = 0;
            } else {
                self.received_bitmap <<= shift;
            }
            self.largest_received_pn = pn;
            self.received_bitmap |= 1;
            true
        } else {
            // Within window — check if already seen
            let offset = self.largest_received_pn - pn;
            if offset >= 128 {
                return false; // outside bitmap range
            }
            let mask = 1u128 << offset;
            if self.received_bitmap & mask != 0 {
                false // duplicate
            } else {
                self.received_bitmap |= mask;
                true
            }
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn is_idle(&self) -> bool {
        self.last_activity.elapsed() > self.idle_timeout
    }

    pub fn update_rtt(&mut self, sample: Duration) {
        self.rtt.update(sample);
    }

    pub fn transition(&mut self, new_status: SessionStatus) {
        tracing::debug!(
            session_id = %self.session_id,
            from = %self.status,
            to = %new_status,
            "session.state_transition"
        );
        self.status = new_status;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_numbers_increment() {
        let mut s = SessionState::new(SessionId::generate());
        assert_eq!(s.next_packet_number(), 0);
        assert_eq!(s.next_packet_number(), 1);
        assert_eq!(s.next_packet_number(), 2);
    }

    #[test]
    fn initial_status() {
        let s = SessionState::new(SessionId::generate());
        assert_eq!(s.status, SessionStatus::Initial);
        assert!(!s.is_established());
    }

    #[test]
    fn record_received_in_order() {
        let mut s = SessionState::new(SessionId::generate());
        assert!(s.record_received(0));
        assert!(s.record_received(1));
        assert!(s.record_received(2));
    }

    #[test]
    fn record_received_duplicate() {
        let mut s = SessionState::new(SessionId::generate());
        assert!(s.record_received(5));
        assert!(!s.record_received(5), "duplicate should return false");
    }

    #[test]
    fn record_received_out_of_order() {
        let mut s = SessionState::new(SessionId::generate());
        assert!(s.record_received(10));
        assert!(s.record_received(8)); // out of order but within window
        assert!(!s.record_received(8), "duplicate out-of-order should return false");
        assert!(s.record_received(9));
    }

    #[test]
    fn record_received_old_packet_replay() {
        let mut s = SessionState::new(SessionId::generate());
        // Advance window to 200
        for i in 100..=200u64 {
            s.record_received(i);
        }
        // Packet 0 is too old
        assert!(!s.record_received(0), "very old packet should be rejected as replay");
    }

    #[test]
    fn rtt_estimator_first_sample() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(50));
        assert_eq!(rtt.srtt, Duration::from_millis(50));
    }

    #[test]
    fn rtt_estimator_converges() {
        let mut rtt = RttEstimator::new();
        for _ in 0..20 {
            rtt.update(Duration::from_millis(100));
        }
        let srtt_ms = rtt.srtt.as_millis();
        assert!(srtt_ms > 80 && srtt_ms < 120, "SRTT should converge to ~100ms, got {srtt_ms}ms");
    }

    #[test]
    fn rto_minimum() {
        let rtt = RttEstimator::new();
        assert!(rtt.rto() >= Duration::from_millis(200));
    }

    #[test]
    fn state_transition() {
        let mut s = SessionState::new(SessionId::generate());
        s.transition(SessionStatus::Handshaking);
        assert_eq!(s.status, SessionStatus::Handshaking);
        s.transition(SessionStatus::Established);
        assert!(s.is_established());
    }
}
