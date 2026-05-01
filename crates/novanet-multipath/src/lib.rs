/// Multipath and mobility support for NovaNet.
/// Phase 6 implementation — currently a stub with type definitions.

use std::time::{Duration, Instant};
use novanet_core::ids::PathId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    /// Path is being probed; not yet validated.
    Probing,
    /// PATH_CHALLENGE sent, awaiting PATH_RESPONSE.
    Validating,
    /// Path is active and validated.
    Active,
    /// Path is degraded but not yet failed.
    Degraded,
    /// Path validation failed or excessive loss.
    Failed,
    /// Path is valid but not primary; kept as standby.
    Standby,
}

/// Per-path metrics and state.
#[derive(Debug)]
pub struct PathState {
    pub path_id: PathId,
    pub status: PathStatus,
    pub smoothed_rtt: Duration,
    pub rtt_variance: Duration,
    pub loss_rate: f64,
    pub last_validated: Option<Instant>,
    pub challenge_data: Option<[u8; 8]>,
}

impl PathState {
    pub fn new(path_id: PathId) -> Self {
        PathState {
            path_id,
            status: PathStatus::Probing,
            smoothed_rtt: Duration::from_millis(333),
            rtt_variance: Duration::from_millis(100),
            loss_rate: 0.0,
            last_validated: None,
            challenge_data: None,
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self.status, PathStatus::Active | PathStatus::Degraded)
    }

    /// Update RTT using RFC 6298 exponential moving average.
    pub fn update_rtt(&mut self, sample: Duration) {
        const ALPHA: f64 = 0.125;
        const BETA: f64 = 0.25;
        let srtt_secs = self.smoothed_rtt.as_secs_f64();
        let sample_secs = sample.as_secs_f64();
        let rttvar_secs = self.rtt_variance.as_secs_f64();
        let new_rttvar = (1.0 - BETA) * rttvar_secs + BETA * (srtt_secs - sample_secs).abs();
        let new_srtt = (1.0 - ALPHA) * srtt_secs + ALPHA * sample_secs;
        self.smoothed_rtt = Duration::from_secs_f64(new_srtt.max(0.0));
        self.rtt_variance = Duration::from_secs_f64(new_rttvar.max(0.0));
    }

    /// Retransmission timeout based on current RTT estimate (RFC 6298).
    pub fn rto(&self) -> Duration {
        let rto = self.smoothed_rtt + 4 * self.rtt_variance;
        rto.max(Duration::from_millis(200))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_path_is_probing() {
        let p = PathState::new(PathId::INITIAL);
        assert_eq!(p.status, PathStatus::Probing);
        assert!(!p.is_usable());
    }

    #[test]
    fn rtt_update_converges() {
        let mut p = PathState::new(PathId::INITIAL);
        p.status = PathStatus::Active;
        for _ in 0..20 {
            p.update_rtt(Duration::from_millis(50));
        }
        // After 20 samples of 50ms, srtt should be close to 50ms
        let srtt_ms = p.smoothed_rtt.as_millis();
        assert!(srtt_ms < 150, "srtt should converge toward 50ms, got {srtt_ms}ms");
    }

    #[test]
    fn rto_has_minimum() {
        let p = PathState::new(PathId::INITIAL);
        assert!(p.rto() >= Duration::from_millis(200));
    }
}
