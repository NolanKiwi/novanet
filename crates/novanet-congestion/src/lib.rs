use std::time::Duration;

/// Trait for pluggable congestion control algorithms.
///
/// The transport layer calls these methods to notify the controller of network
/// events. The controller responds by adjusting the congestion window.
pub trait CongestionController: Send + Sync {
    /// Called when an ACK is received for `acked_bytes` of data.
    /// `rtt` is the measured round-trip time for the acked packet.
    fn on_ack(&mut self, acked_bytes: usize, rtt: Duration);

    /// Called when a packet loss event is detected.
    /// `lost_bytes` is the total bytes in lost packets.
    fn on_loss(&mut self, lost_bytes: usize);

    /// Current congestion window in bytes.
    fn congestion_window(&self) -> usize;

    /// Returns true if the sender may send a packet of `packet_size` bytes
    /// given that `bytes_in_flight` bytes are already unacknowledged.
    fn can_send(&self, bytes_in_flight: usize, packet_size: usize) -> bool {
        bytes_in_flight + packet_size <= self.congestion_window()
    }
}

pub mod aimd;
pub use aimd::AimdController;
