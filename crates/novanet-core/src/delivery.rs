/// Delivery semantics for a NovaNet channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryMode {
    /// Reliable, ordered byte stream. Like TCP.
    ReliableStream,

    /// Reliable, ordered discrete messages. Each message arrives exactly once,
    /// in order, as a complete unit.
    ReliableMessage,

    /// Unreliable, unordered datagrams. May be lost, duplicated, or reordered.
    /// Never retransmitted. Like UDP.
    UnreliableDatagram,

    /// Partially reliable messages. A message is retransmitted up to a maximum
    /// number of times or until a deadline, then dropped.
    PartiallyReliable { max_retransmits: u8 },
}

impl DeliveryMode {
    pub fn is_reliable(self) -> bool {
        matches!(
            self,
            DeliveryMode::ReliableStream | DeliveryMode::ReliableMessage
        )
    }

    pub fn is_ordered(self) -> bool {
        matches!(
            self,
            DeliveryMode::ReliableStream | DeliveryMode::ReliableMessage
        )
    }
}

impl std::fmt::Display for DeliveryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryMode::ReliableStream => write!(f, "reliable-stream"),
            DeliveryMode::ReliableMessage => write!(f, "reliable-message"),
            DeliveryMode::UnreliableDatagram => write!(f, "unreliable-datagram"),
            DeliveryMode::PartiallyReliable { max_retransmits } => {
                write!(f, "partial({max_retransmits}-retransmits)")
            }
        }
    }
}
