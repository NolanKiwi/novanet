/// Fuzz target for the NovaNet packet decoder.
///
/// Run with:
///   cargo fuzz run packet_decode -- -max_len=1200
///
/// This target exercises:
/// - decode_packet: the full packet decoder
/// - Frame::decode_all: the frame sequence decoder
/// - PacketHeader::decode: the header parser
///
/// The target must never panic. Returning an Err is the correct response to malformed input.

// Note: This file is a template for a cargo-fuzz target.
// To use it, run: cargo install cargo-fuzz
// Then: cd /path/to/novanet && cargo fuzz init
// And replace the generated fuzz target with this content.

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use novanet_wire::{
    codec::decode_packet,
    frame::Frame,
    header::PacketHeader,
};

fuzz_target!(|data: &[u8]| {
    // Fuzz the complete packet decoder
    let _ = decode_packet(Bytes::copy_from_slice(data));

    // Fuzz the frame decoder independently
    let _ = Frame::decode_all(Bytes::copy_from_slice(data));

    // Fuzz the header decoder independently
    let mut bytes = Bytes::copy_from_slice(data);
    let _ = PacketHeader::decode(&mut bytes);
});
