use adverify::bid_stream::{BidRequest, Device, Impression, App};
use adverify::detection::{FraudDetector, FraudScore, GeneralizedFraudDetector};

fn make_bid_request(
    device: Option<Device>,
    app: Option<App>,
    imp: Vec<Impression>,
    has_site: bool,
) -> BidRequest {
    BidRequest {
        id: "detect-test".into(),
        imp,
        device,
        user: None,
        app,
        site: if has_site {
            Some(adverify::bid_stream::Site {
                id: "site-1".into(),
                name: "TestSite".into(),
                domain: "testsite.com".into(),
                cat: vec![],
                publisher: None,
            })
        } else {
            None
        },
    }
}

#[test]
fn test_detect_known_bot() {
    let device = Device {
        ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".into(),
        geo: None,
        dnt: 0,
        lmt: 0,
        ip: String::new(),
        devicetype: Some(4),
        make: String::new(),
        model: String::new(),
        os: "Android".into(),
        osv: String::new(),
        w: Some(1080),
        h: Some(2400),
        ppi: None,
        pxratio: 1.0,
        language: "en".into(),
        carrier: String::new(),
        connectiontype: None,
        ifa: "valid-ifa".into(),
    };
    let req = make_bid_request(Some(device), None, vec![], false);
    let detector = GeneralizedFraudDetector::new();
    let score = detector.detect(&req);
    assert!(score.is_fraudulent);
    assert!(score.confidence > 0.5);
}

#[test]
fn test_detect_missing_ifa() {
    let device = Device {
        ua: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36".into(),
        geo: None,
        dnt: 1,
        lmt: 1,
        ip: String::new(),
        devicetype: Some(4),
        make: String::new(),
        model: String::new(),
        os: "Android".into(),
        osv: String::new(),
        w: Some(1080),
        h: Some(2400),
        ppi: None,
        pxratio: 1.0,
        language: "en".into(),
        carrier: String::new(),
        connectiontype: None,
        ifa: "".into(),
    };
    let req = make_bid_request(Some(device), None, vec![], false);
    let detector = GeneralizedFraudDetector::new();
    let score = detector.detect(&req);
    assert!(score.is_fraudulent);
}

#[test]
fn test_detect_impression_laundering_both_app_site() {
    let app = App {
        id: "app-1".into(),
        name: "TestApp".into(),
        bundle: "com.test.app".into(),
        domain: String::new(),
        cat: vec![],
        ver: String::new(),
        paid: 0,
        publisher: None,
    };
    let req = make_bid_request(None, Some(app), vec![], true);
    let detector = GeneralizedFraudDetector::new();
    let score = detector.detect(&req);
    assert!(score.is_fraudulent);
    assert!(score.reasons.iter().any(|r| r.contains("app and site")));
}

#[test]
fn test_detect_ad_stacking() {
    let device = Device {
        ua: "Mozilla/5.0".into(),
        geo: None,
        dnt: 0,
        lmt: 0,
        ip: String::new(),
        devicetype: Some(4),
        make: String::new(),
        model: String::new(),
        os: "iOS".into(),
        osv: String::new(),
        w: Some(375),  // iPhone viewport
        h: Some(812),
        ppi: None,
        pxratio: 1.0,
        language: "en".into(),
        carrier: String::new(),
        connectiontype: None,
        ifa: "valid-ifa".into(),
    };
    let imp = Impression {
        id: "1".into(),
        banner: Some(adverify::bid_stream::Banner {
            w: Some(1920),
            h: Some(1080),
            pos: None,
            battr: vec![],
        }),
        video: None,
        bidfloor: 0.0,
        bidfloorcur: "USD".into(),
        instl: 0,
        tagid: String::new(),
        secure: 0,
    };
    let req = make_bid_request(Some(device), None, vec![imp], false);
    let detector = GeneralizedFraudDetector::new();
    let score = detector.detect(&req);
    assert!(score.is_fraudulent);
}

#[test]
fn test_benign_request_not_flagged() {
    let device = Device {
        ua: "Mozilla/5.0 (Linux; Android 14; Pixel 9 Pro) AppleWebKit/537.36 Chrome/125.0".into(),
        geo: None,
        dnt: 0,
        lmt: 0,
        ip: String::new(),
        devicetype: Some(4),
        make: "Google".into(),
        model: "Pixel 9 Pro".into(),
        os: "Android".into(),
        osv: "14.0".into(),
        w: Some(1080),
        h: Some(2400),
        ppi: None,
        pxratio: 2.625,
        language: "en".into(),
        carrier: "Verizon".into(),
        connectiontype: Some(6),
        ifa: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".into(),
    };
    let app = App {
        id: "com.example".into(),
        name: "Example".into(),
        bundle: "com.example.app".into(),
        domain: "example.com".into(),
        cat: vec![],
        ver: String::new(),
        paid: 0,
        publisher: None,
    };
    let imp = Impression {
        id: "1".into(),
        banner: Some(adverify::bid_stream::Banner {
            w: Some(300),
            h: Some(250),
            pos: Some(7),
            battr: vec![],
        }),
        video: None,
        bidfloor: 0.05,
        bidfloorcur: "USD".into(),
        instl: 0,
        tagid: "tag-1".into(),
        secure: 1,
    };
    let req = make_bid_request(Some(device), Some(app), vec![imp], false);
    let detector = GeneralizedFraudDetector::new();
    let score = detector.detect(&req);
    assert!(!score.is_fraudulent, "Benign request flagged: {:?}", score.reasons);
}

#[test]
fn test_fraud_score_aggregate() {
    let benign = FraudScore::benign();
    let flagged = FraudScore {
        is_fraudulent: true,
        confidence: 0.8,
        reasons: vec!["test".into()],
    };
    let result = FraudScore::aggregate(&[benign, flagged]);
    assert!(result.is_fraudulent);
    assert!((result.confidence - 0.8).abs() < 1e-6);
}
