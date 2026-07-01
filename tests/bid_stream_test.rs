use adverify::bid_stream::{BidRequest, BidStreamParser, BidStreamProcessor};
use adverify::detection::{FraudDetector, FraudScore};

struct NoopDetector;

impl FraudDetector for NoopDetector {
    fn detect(&self, _request: &BidRequest) -> FraudScore {
        FraudScore::benign()
    }
}

#[tokio::test]
async fn test_parse_single_bid_request() {
    let json = r#"{
        "id": "test-bid-1",
        "imp": [{"id": "1", "banner": {"w": 300, "h": 250}, "bidfloor": 0.05, "bidfloorcur": "USD"}],
        "app": {"id": "com.test", "name": "TestApp", "bundle": "com.test.app"},
        "device": {"ua": "Mozilla/5.0", "os": "Android", "w": 1080, "h": 2400, "ifa": "test-ifa"},
        "user": {"id": "user-1"}
    }"#;

    let mut parser = BidStreamParser::new();
    let result = parser.parse_line(json);
    assert!(result.is_ok(), "Failed to parse valid bid request");
    let bid = result.unwrap();
    assert!(bid.is_some());
    let bid = bid.unwrap();
    assert_eq!(bid.id, "test-bid-1");
    assert_eq!(bid.imp.len(), 1);
    assert_eq!(parser.parsed_count(), 1);
}

#[tokio::test]
async fn test_parse_invalid_json() {
    let mut parser = BidStreamParser::new();
    let result = parser.parse_line("this is not json");
    assert!(result.is_err(), "Invalid JSON should return error");
}

#[tokio::test]
async fn test_parse_empty_line() {
    let mut parser = BidStreamParser::new();
    let result = parser.parse_line("");
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_processor_with_temp_file() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    for _ in 0..5 {
        writeln!(
            tmpfile,
            r#"{{"id":"bid","imp":[],"device":{{"ua":"test","os":"Android"}}}}"#
        )
        .unwrap();
    }
    let path = tmpfile.into_temp_path();
    let processor = BidStreamProcessor::new(2);
    let detector = NoopDetector;
    let batches = processor.process_file(&path, &detector).await.unwrap();
    assert_eq!(batches.len(), 3); // 5 items: batch size 2 → 3 batches (2+2+1)
    let total: usize = batches.iter().map(|b| b.results.len()).sum();
    assert_eq!(total, 5);
}

#[tokio::test]
async fn test_processor_empty_file() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmpfile).unwrap();
    let path = tmpfile.into_temp_path();
    let processor = BidStreamProcessor::new(10);
    let detector = NoopDetector;
    let batches = processor.process_file(&path, &detector).await.unwrap();
    assert_eq!(batches.len(), 0);
}
