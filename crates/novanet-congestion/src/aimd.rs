use std::time::Duration;
use novanet_core::constants::{INITIAL_CWND, MIN_CWND, MAX_UDP_PAYLOAD};
use crate::CongestionController;

/// Simple AIMD (Additive Increase Multiplicative Decrease) congestion controller.
///
/// Phase 1 algorithm:
///   - Slow start: cwnd grows by max_datagram_size per acked packet until ssthresh.
///   - Congestion avoidance: cwnd grows by max_datagram_size^2 / cwnd per acked byte.
///   - On loss: ssthresh = cwnd / 2, cwnd = ssthresh, exit slow start.
pub struct AimdController {
    cwnd: usize,
    ssthresh: usize,
    max_datagram_size: usize,
}

impl AimdController {
    pub fn new() -> Self {
        AimdController {
            cwnd: INITIAL_CWND,
            ssthresh: usize::MAX,
            max_datagram_size: MAX_UDP_PAYLOAD,
        }
    }

    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }
}

impl Default for AimdController {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController for AimdController {
    fn on_ack(&mut self, acked_bytes: usize, _rtt: Duration) {
        if self.in_slow_start() {
            // Slow start: increase by one max_datagram_size per acked packet
            self.cwnd = self.cwnd.saturating_add(self.max_datagram_size);
        } else {
            // Congestion avoidance: increase by max_datagram_size^2 / cwnd
            let increment = self.max_datagram_size
                .saturating_mul(acked_bytes)
                / self.cwnd.max(1);
            self.cwnd = self.cwnd.saturating_add(increment.max(1));
        }
    }

    fn on_loss(&mut self, _lost_bytes: usize) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh;
    }

    fn congestion_window(&self) -> usize {
        self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_cwnd() {
        let cc = AimdController::new();
        assert_eq!(cc.congestion_window(), INITIAL_CWND);
    }

    #[test]
    fn slow_start_increases() {
        let mut cc = AimdController::new();
        let initial = cc.congestion_window();
        cc.on_ack(MAX_UDP_PAYLOAD, Duration::from_millis(50));
        assert!(cc.congestion_window() > initial);
    }

    #[test]
    fn loss_reduces_cwnd() {
        let mut cc = AimdController::new();
        // Grow past slow start threshold
        for _ in 0..100 {
            cc.on_ack(MAX_UDP_PAYLOAD, Duration::from_millis(10));
        }
        let before = cc.congestion_window();
        cc.on_loss(MAX_UDP_PAYLOAD);
        assert!(cc.congestion_window() < before);
    }

    #[test]
    fn cwnd_never_below_min() {
        let mut cc = AimdController::new();
        // Multiple loss events should not reduce cwnd below MIN_CWND
        for _ in 0..100 {
            cc.on_loss(MAX_UDP_PAYLOAD);
        }
        assert!(cc.congestion_window() >= MIN_CWND);
    }

    #[test]
    fn can_send_respects_cwnd() {
        let cc = AimdController::new();
        let cwnd = cc.congestion_window();
        assert!(cc.can_send(0, MAX_UDP_PAYLOAD));
        assert!(!cc.can_send(cwnd, 1));
        assert!(!cc.can_send(cwnd - MAX_UDP_PAYLOAD + 1, MAX_UDP_PAYLOAD));
    }
}
