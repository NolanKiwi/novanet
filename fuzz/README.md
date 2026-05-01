# NovaNet Fuzz Targets

## Setup

```bash
# Install cargo-fuzz (requires nightly Rust)
cargo install cargo-fuzz

# Initialize the fuzz workspace (run once)
cargo fuzz init

# Copy packet_decode_fuzz.rs into the generated fuzz/fuzz_targets/ directory
cp packet_decode_fuzz.rs fuzz/fuzz_targets/packet_decode.rs
```

## Running

```bash
# Fuzz the packet decoder (conservative settings for CI)
cargo +nightly fuzz run packet_decode -- -max_len=1200 -runs=1000000

# Longer run for research
cargo +nightly fuzz run packet_decode -- -max_len=1200 -timeout=3600

# Minimize a crash
cargo +nightly fuzz tmin packet_decode crash-<hash>
```

## Coverage

View coverage (requires nightly):
```bash
cargo +nightly fuzz coverage packet_decode
```

## What to Fuzz

Priority order:
1. `decode_packet` — the primary attack surface (any inbound UDP packet).
2. `Frame::decode_all` — frame decoder inside the encrypted payload.
3. `PacketHeader::decode` — first 21 bytes of every packet.
4. `AckFrame::decode` — ACK processing on the receiver.
5. Handshake state machine (Phase 4+).
