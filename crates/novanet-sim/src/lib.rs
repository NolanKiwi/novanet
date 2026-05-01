use rand::Rng;
use std::time::Duration;

/// Configuration for a simulated network link.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// One-way packet delay (added to every packet).
    pub base_delay: Duration,
    /// Random additional delay range [0, jitter].
    pub jitter: Duration,
    /// Probability of dropping each packet (0.0 to 1.0).
    pub loss_rate: f64,
    /// Probability of reordering a packet (0.0 to 1.0).
    pub reorder_rate: f64,
}

impl LinkConfig {
    pub fn perfect() -> Self {
        LinkConfig {
            base_delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss_rate: 0.0,
            reorder_rate: 0.0,
        }
    }

    pub fn lan() -> Self {
        LinkConfig {
            base_delay: Duration::from_millis(1),
            jitter: Duration::from_micros(500),
            loss_rate: 0.0001,
            reorder_rate: 0.0,
        }
    }

    pub fn wan() -> Self {
        LinkConfig {
            base_delay: Duration::from_millis(40),
            jitter: Duration::from_millis(5),
            loss_rate: 0.001,
            reorder_rate: 0.001,
        }
    }

    pub fn lossy() -> Self {
        LinkConfig {
            base_delay: Duration::from_millis(40),
            jitter: Duration::from_millis(5),
            loss_rate: 0.02,
            reorder_rate: 0.0,
        }
    }

    pub fn mobile() -> Self {
        LinkConfig {
            base_delay: Duration::from_millis(50),
            jitter: Duration::from_millis(15),
            loss_rate: 0.01,
            reorder_rate: 0.005,
        }
    }
}

/// Decision about what to do with a packet being transmitted through a simulated link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketDecision {
    /// Deliver the packet after the computed delay.
    Deliver { delay: Duration },
    /// Drop the packet silently.
    Drop,
}

/// A simulated network link that applies loss, delay, and jitter.
pub struct SimulatedLink {
    config: LinkConfig,
}

impl SimulatedLink {
    pub fn new(config: LinkConfig) -> Self {
        SimulatedLink { config }
    }

    /// Decide what happens to a packet on this link.
    pub fn process_packet(&self) -> PacketDecision {
        let mut rng = rand::thread_rng();

        // Loss check
        if rng.gen::<f64>() < self.config.loss_rate {
            return PacketDecision::Drop;
        }

        // Compute delay with jitter
        let jitter_ms = if self.config.jitter.is_zero() {
            0
        } else {
            rng.gen_range(0..=self.config.jitter.as_millis() as u64)
        };
        let delay = self.config.base_delay + Duration::from_millis(jitter_ms);

        PacketDecision::Deliver { delay }
    }

    pub fn config(&self) -> &LinkConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_link_never_drops() {
        let link = SimulatedLink::new(LinkConfig::perfect());
        for _ in 0..1000 {
            assert_eq!(
                link.process_packet(),
                PacketDecision::Deliver { delay: Duration::ZERO }
            );
        }
    }

    #[test]
    fn lossy_link_drops_some() {
        let link = SimulatedLink::new(LinkConfig {
            base_delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss_rate: 0.5,
            reorder_rate: 0.0,
        });
        let mut drops = 0;
        for _ in 0..10_000 {
            if link.process_packet() == PacketDecision::Drop {
                drops += 1;
            }
        }
        // With 50% loss, we expect roughly 3000–7000 drops
        assert!(drops > 3000, "expected significant drops, got {drops}");
        assert!(drops < 7000, "expected some deliveries, got {drops} drops");
    }

    #[test]
    fn high_loss_link_drops_most() {
        let link = SimulatedLink::new(LinkConfig {
            base_delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss_rate: 1.0,
            reorder_rate: 0.0,
        });
        for _ in 0..100 {
            assert_eq!(link.process_packet(), PacketDecision::Drop);
        }
    }
}
