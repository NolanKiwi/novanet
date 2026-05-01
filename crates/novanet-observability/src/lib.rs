use novanet_core::ids::{PathId, SessionId};
use tracing::{debug, info, warn};

/// Emit a structured event when a session is created.
pub fn session_created(session_id: SessionId, local_addr: &str, remote_addr: &str) {
    info!(
        session_id = %session_id,
        local_addr = local_addr,
        remote_addr = remote_addr,
        "session.created"
    );
}

/// Emit a structured event when a session is established.
pub fn session_established(session_id: SessionId, rtt_ms: u64) {
    info!(
        session_id = %session_id,
        rtt_ms = rtt_ms,
        "session.established"
    );
}

/// Emit a structured event when a session closes.
pub fn session_closed(session_id: SessionId, reason: &str) {
    info!(
        session_id = %session_id,
        reason = reason,
        "session.closed"
    );
}

/// Emit a structured event when a path is validated.
pub fn path_validated(session_id: SessionId, path_id: PathId, rtt_ms: u64) {
    info!(
        session_id = %session_id,
        path_id = %path_id,
        rtt_ms = rtt_ms,
        "path.validated"
    );
}

/// Emit a structured event when a packet is lost.
pub fn packet_lost(session_id: SessionId, path_id: PathId, packet_number: u64) {
    debug!(
        session_id = %session_id,
        path_id = %path_id,
        packet_number = packet_number,
        "packet.lost"
    );
}

/// Emit a structured event when a packet is retransmitted.
pub fn packet_retransmitted(
    session_id: SessionId,
    path_id: PathId,
    new_packet_number: u64,
) {
    debug!(
        session_id = %session_id,
        path_id = %path_id,
        new_packet_number = new_packet_number,
        "packet.retransmitted"
    );
}

/// Emit a structured event when the congestion window changes.
pub fn congestion_updated(session_id: SessionId, cwnd: usize, bytes_in_flight: usize) {
    debug!(
        session_id = %session_id,
        cwnd = cwnd,
        bytes_in_flight = bytes_in_flight,
        "congestion.updated"
    );
}

/// Emit a warning when a crypto error occurs.
pub fn crypto_error(session_id: SessionId, detail: &str) {
    warn!(
        session_id = %session_id,
        detail = detail,
        "crypto.error"
    );
}
