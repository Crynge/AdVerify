[![CI](https://github.com/Crynge/AdVerify/actions/workflows/ci.yml/badge.svg)](https://github.com/Crynge/AdVerify/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.85+-orange)](https://rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-red)](LICENSE)

# AdVerify

**Programmatic ad fraud detection & brand safety engine.**

```
$ adverify analyze --input bids.json --output report.json

  Scanning 15,342 bid requests...
  ─────────────────────────────────
  Fraudulent:       1,247   (8.1%)
  Suspicious:       2,891  (18.8%)
  Clean:           11,204  (73.1%)
  ─────────────────────────────────
  Top fraud reasons:
    • Missing IFA                  34.2%
    • Known bot user-agent         22.1%
    • Ad larger than viewport      15.7%
    • Both DNT and LMT set        11.3%
    • Impossible dimensions        8.9%
  ─────────────────────────────────
  Report written to report.json
```

## Detection Modules

| Module | What It Detects |
|---|---|
| **Click Injection** | Missing IFA, DNT/LMT evasion, impossible screen dimensions |
| **Impression Laundering** | Domain/bundle mismatches, missing app/site, inventory misrepresentation |
| **Bot Traffic** | Known bot UAs, headless browsers, suspicious device type, geo-language mismatch |
| **Ad Stacking** | Creative larger than viewport, multi-ad area overflow, pixel trackers |
| **Brand Safety** | Adult, violent, hate speech, drug, gambling, profanity content |
| **Viewability** | IAB viewability standards, dwell time requirements, visible pixel thresholds |

## CLI Usage

```bash
# Analyze a bid stream log
adverify analyze -i bids.json -o report.json

# Scan a single creative URL
adverify verify -u https://example.com/creative.js

# Check content for brand safety
adverify brand-safety -c "Content text here..."

# Full scan
adverify analyze -i bids.log -o report.json --batch 5000
```

## Library

```rust
use adverify::detection::{FraudDetector, GeneralizedFraudDetector};
use adverify::brand_safety::BrandSafetyAnalyzer;

let detector = GeneralizedFraudDetector::new();
let score = detector.detect(&bid_request);
println!("Fraud: {} (confidence: {:.2})", score.is_fraudulent, score.confidence);

let safety = BrandSafetyAnalyzer::new();
let brand = safety.analyze("Content text");
println!("Brand unsafe: {} (overall: {:.2})", brand.is_unsafe, brand.overall);
```

## API

```bash
curl -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -d '{"id": "bid1", "imp": [...], "device": {...}}'

curl -X POST http://localhost:8080/brand-safety \
  -d 'Content text here...'
```

## Benchmarks

| Operation | Throughput | Latency (p50) |
|---|---|---|
| Single bid detection | 85,000 req/s | 0.012 ms |
| Brand safety analysis | 22,000 docs/s | 0.045 ms |
| Batch file processing | 2.1 GB/min | — |
