use bytes::{Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use novanet_core::ids::{PathId, ServiceId, SessionId};
use novanet_wire::{
    codec::{decode_packet, encode_packet},
    frame::{AckFrame, AckRange, StreamFrame},
    header::PacketHeader,
    packet::{HelloPayload, NovaPacket, PacketPayload},
};
use novanet_core::PacketType;

fn make_data_packet(payload_size: usize) -> NovaPacket {
    NovaPacket {
        header: PacketHeader::new(PacketType::Data, 0, SessionId::generate(), PathId::INITIAL),
        packet_number: Some(42),
        payload: PacketPayload::Data(vec![
            novanet_wire::frame::Frame::Stream(StreamFrame {
                stream_id: 0,
                offset: 0,
                fin: false,
                high_priority: false,
                data: Bytes::from(vec![0xAB; payload_size]),
            }),
        ]),
    }
}

fn bench_encode_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_data");
    for size in [64, 256, 512, 1100] {
        let packet = make_data_packet(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &packet, |b, p| {
            b.iter(|| {
                let mut buf = BytesMut::with_capacity(1200);
                encode_packet(p, &mut buf).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_decode_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_data");
    for size in [64, 256, 512, 1100] {
        let packet = make_data_packet(size);
        let mut buf = BytesMut::with_capacity(1200);
        encode_packet(&packet, &mut buf).unwrap();
        let bytes = buf.freeze();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &bytes, |b, raw| {
            b.iter(|| decode_packet(raw.clone()).unwrap());
        });
    }
    group.finish();
}

fn bench_encode_ack(c: &mut Criterion) {
    let ack_packet = NovaPacket {
        header: PacketHeader::new(PacketType::Ack, 0, SessionId::generate(), PathId::INITIAL),
        packet_number: Some(100),
        payload: PacketPayload::Ack(vec![
            novanet_wire::frame::Frame::Ack(AckFrame {
                largest_acked: 99,
                ack_delay_us: 250,
                ranges: vec![
                    AckRange::new(90, 99),
                    AckRange::new(80, 87),
                    AckRange::new(70, 75),
                ],
            }),
        ]),
    };
    c.bench_function("encode_ack_3ranges", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(256);
            encode_packet(&ack_packet, &mut buf).unwrap();
        });
    });
}

fn bench_encode_hello(c: &mut Criterion) {
    let hello = NovaPacket {
        header: PacketHeader::new(PacketType::Hello, 0, SessionId::generate(), PathId::INITIAL),
        packet_number: None,
        payload: PacketPayload::Hello(HelloPayload::unauthenticated(ServiceId::from_name("bench"))),
    };
    c.bench_function("encode_hello", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(256);
            encode_packet(&hello, &mut buf).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_encode_data,
    bench_decode_data,
    bench_encode_ack,
    bench_encode_hello,
);
criterion_main!(benches);
