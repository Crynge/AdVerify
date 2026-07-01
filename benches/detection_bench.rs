use criterion::{black_box, criterion_group, criterion_main, Criterion};

use adverify::bid_stream::BidRequest;
use adverify::detection::{FraudDetector, GeneralizedFraudDetector};

fn make_bench_request() -> BidRequest {
    BidRequest {
        id: "bench-bid-12345".into(),
        imp: vec![adverify::bid_stream::Impression {
            id: "1".into(),
            banner: Some(adverify::bid_stream::Banner {
                w: Some(300),
                h: Some(250),
                pos: Some(7),
                battr: vec![1, 3, 5],
            }),
            video: None,
            bidfloor: 0.05,
            bidfloorcur: "USD".into(),
            instl: 0,
            tagid: "tag-bench".into(),
            secure: 1,
        }],
        device: Some(adverify::bid_stream::Device {
            ua: "Mozilla/5.0 (Linux; Android 14; Pixel 9 Pro) AppleWebKit/537.36".into(),
            geo: Some(adverify::bid_stream::Geo {
                lat: Some(40.7128),
                lon: Some(-74.006),
                country: "USA".into(),
                region: "NY".into(),
                city: "New York".into(),
                zip: "10001".into(),
                r#type: Some(2),
            }),
            dnt: 0,
            lmt: 0,
            ip: "192.168.1.100".into(),
            devicetype: Some(4),
            make: "Google".into(),
            model: "Pixel 9 Pro".into(),
            os: "Android".into(),
            osv: "14.0".into(),
            w: Some(1080),
            h: Some(2400),
            ppi: Some(480),
            pxratio: 2.625,
            language: "en".into(),
            carrier: "Verizon".into(),
            connectiontype: Some(6),
            ifa: "bench-ifa-12345".into(),
        }),
        user: Some(adverify::bid_stream::User {
            id: "user-bench".into(),
            buyeruid: "bu-bench".into(),
            yob: Some(1990),
            gender: "M".into(),
            geo: None,
        }),
        app: Some(adverify::bid_stream::App {
            id: "com.bench.app".into(),
            name: "BenchApp".into(),
            bundle: "com.bench.app".into(),
            domain: "bench.example.com".into(),
            cat: vec!["IAB12".into()],
            ver: "1.0".into(),
            paid: 0,
            publisher: None,
        }),
        site: None,
    }
}

fn bench_detection(c: &mut Criterion) {
    let detector = GeneralizedFraudDetector::new();
    let request = make_bench_request();

    c.bench_function("detect_single_request", |b| {
        b.iter(|| {
            let score = detector.detect(black_box(&request));
            black_box(score);
        });
    });
}

fn bench_detection_batch(c: &mut Criterion) {
    let detector = GeneralizedFraudDetector::new();
    let requests: Vec<BidRequest> = (0..100).map(|_| make_bench_request()).collect();

    c.bench_function("detect_batch_100", |b| {
        b.iter(|| {
            for req in &requests {
                let score = detector.detect(black_box(req));
                black_box(score);
            }
        });
    });
}

criterion_group!(benches, bench_detection, bench_detection_batch);
criterion_main!(benches);
