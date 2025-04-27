use geneve_rs::geneve::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn marshalling(c: &mut Criterion) {
    let mut group = c.benchmark_group("marshalling");

    let decoded = Header {
        version: 0,
        control_flag: false,
        critical_flag: false,
        protocol: 0x86dd,
        vni: 0x00aaaaee,
        options: Some(vec![
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0a,
                c_flag: false,
                data: Some(&[0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(&[0x00, 0x02, 0x00, 0x00]),
            },
        ]),
        options_len: 0,
    };

    group.bench_function("header_vec", |b| b.iter(|| {
        let mut test_vec = Vec::new();

        decoded.marshal(black_box(&mut test_vec)).expect("failed to marshal");
    }));

    group.bench_function("slice", |b| b.iter(||{
        let mut test_buffer: [u8;128] = [0u8;128];

        decoded.marshal_to_slice(black_box(&mut test_buffer)).expect("failed to marshal");
    }));
}

fn unmarshalling(c: &mut Criterion) {
    let mut group = c.benchmark_group("unmarshalling");

    let encoded: [u8; 24] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00,
    ];

    group.bench_function("header", |b| b.iter(|| {
        let _ = Header::unmarshal(black_box(&encoded)).expect("failed to unmarshal");
    }));
}

criterion_group!(benches, marshalling, unmarshalling);
criterion_main!(benches);
