//! Bid stream parsing and processing.
//!
//! Provides types and utilities for parsing OpenRTB 2.6 bid requests
//! from JSON streams and processing them asynchronously at high throughput.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

use crate::detection::FraudDetector;

/// A minimal OpenRTB 2.6 bid request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BidRequest {
    /// Unique auction ID.
    pub id: String,
    /// Array of impression objects.
    #[serde(default)]
    pub imp: Vec<Impression>,
    /// Device information.
    pub device: Option<Device>,
    /// User information.
    pub user: Option<User>,
    /// App object (for in-app inventory).
    pub app: Option<App>,
    /// Site object (for web inventory).
    pub site: Option<Site>,
}

/// An impression object within a bid request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Impression {
    /// Impression ID.
    pub id: String,
    /// Banner placement details.
    pub banner: Option<Banner>,
    /// Video placement details.
    pub video: Option<Video>,
    /// Floor price.
    #[serde(default)]
    pub bidfloor: f64,
    /// Currency of the floor price.
    #[serde(default = "default_currency")]
    pub bidfloorcur: String,
    /// Interstitial (1) or not (0).
    #[serde(default)]
    pub instl: u8,
    /// Tag ID for the placement.
    #[serde(default)]
    pub tagid: String,
    /// Secure flag.
    #[serde(default)]
    pub secure: u8,
}

fn default_currency() -> String {
    "USD".into()
}

/// Banner placement details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Banner {
    /// Width in pixels.
    pub w: Option<u32>,
    /// Height in pixels.
    pub h: Option<u32>,
    /// Ad position on screen (OpenRTB 5.4).
    pub pos: Option<u8>,
    /// Blocked creative attributes.
    #[serde(default)]
    pub battr: Vec<u8>,
}

/// Video placement details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Video {
    /// Width in pixels.
    pub w: Option<u32>,
    /// Height in pixels.
    pub h: Option<u32>,
    /// Minimum video duration in seconds.
    pub minduration: Option<u32>,
    /// Maximum video duration in seconds.
    pub maxduration: Option<u32>,
    /// Placement type (OpenRTB 5.9).
    pub placement: Option<u8>,
    /// Linearity (OpenRTB 5.7).
    pub linearity: Option<u8>,
    /// Supported video protocols.
    #[serde(default)]
    pub protocols: Vec<u8>,
    /// Supported MIME types.
    #[serde(default)]
    pub mimes: Vec<String>,
}

/// Device information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// User agent string.
    #[serde(default)]
    pub ua: String,
    /// Device geographic location.
    pub geo: Option<Geo>,
    /// Do-not-track flag.
    #[serde(default)]
    pub dnt: u8,
    /// Limit ad tracking flag.
    #[serde(default)]
    pub lmt: u8,
    /// IP address.
    #[serde(default)]
    pub ip: String,
    /// Device type (OpenRTB 5.21).
    pub devicetype: Option<u8>,
    /// Device make.
    #[serde(default)]
    pub make: String,
    /// Device model.
    #[serde(default)]
    pub model: String,
    /// Operating system.
    #[serde(default)]
    pub os: String,
    /// OS version.
    #[serde(default)]
    pub osv: String,
    /// Screen width in pixels.
    pub w: Option<u32>,
    /// Screen height in pixels.
    pub h: Option<u32>,
    /// Screen pixel density.
    pub ppi: Option<u32>,
    /// Pixel ratio.
    #[serde(default)]
    pub pxratio: f64,
    /// Browser language.
    #[serde(default)]
    pub language: String,
    /// Carrier.
    #[serde(default)]
    pub carrier: String,
    /// Connection type (OpenRTB 5.22).
    pub connectiontype: Option<u8>,
    /// Hardware-based device ID (IFA).
    #[serde(default)]
    pub ifa: String,
}

/// Geographic coordinate data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Geo {
    /// Latitude.
    pub lat: Option<f64>,
    /// Longitude.
    pub lon: Option<f64>,
    /// Country code.
    #[serde(default)]
    pub country: String,
    /// Region code.
    #[serde(default)]
    pub region: String,
    /// City name.
    #[serde(default)]
    pub city: String,
    /// Postal code.
    #[serde(default)]
    pub zip: String,
    /// Location source (OpenRTB 5.17).
    pub r#type: Option<u8>,
}

/// User information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID assigned by the exchange.
    #[serde(default)]
    pub id: String,
    /// Buyer-specific user ID.
    #[serde(default)]
    pub buyeruid: String,
    /// Year of birth.
    pub yob: Option<u32>,
    /// Gender ("M", "F", "O").
    #[serde(default)]
    pub gender: String,
    /// User's geographic data.
    pub geo: Option<Geo>,
}

/// App information (for in-app inventory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    /// Application ID.
    #[serde(default)]
    pub id: String,
    /// Application name.
    #[serde(default)]
    pub name: String,
    /// Application bundle/package name.
    #[serde(default)]
    pub bundle: String,
    /// App store domain.
    #[serde(default)]
    pub domain: String,
    /// IAB content categories.
    #[serde(default)]
    pub cat: Vec<String>,
    /// Application version.
    #[serde(default)]
    pub ver: String,
    /// Paid (1) or free (0).
    #[serde(default)]
    pub paid: u8,
    /// Publisher information.
    pub publisher: Option<Publisher>,
}

/// Site information (for web inventory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    /// Site ID.
    #[serde(default)]
    pub id: String,
    /// Site name.
    #[serde(default)]
    pub name: String,
    /// Site domain.
    #[serde(default)]
    pub domain: String,
    /// IAB content categories.
    #[serde(default)]
    pub cat: Vec<String>,
    /// Publisher information.
    pub publisher: Option<Publisher>,
}

/// Publisher information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publisher {
    /// Publisher ID.
    #[serde(default)]
    pub id: String,
    /// Publisher name.
    #[serde(default)]
    pub name: String,
    /// Publisher domain.
    #[serde(default)]
    pub domain: String,
}

/// A high-throughput async parser for JSON bid request streams.
///
/// Parses one JSON object per line (NDJSON format), the standard format
/// for bid stream logs in production ad exchanges.
pub struct BidStreamParser {
    /// Count of successfully parsed requests.
    parsed: u64,
    /// Count of parse failures.
    errors: u64,
}

impl BidStreamParser {
    /// Creates a new `BidStreamParser`.
    pub fn new() -> Self {
        Self {
            parsed: 0,
            errors: 0,
        }
    }

    /// Parse a single line of JSON into a `BidRequest`.
    pub fn parse_line(&mut self, line: &str) -> Result<Option<BidRequest>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        match serde_json::from_str::<BidRequest>(trimmed) {
            Ok(req) => {
                self.parsed += 1;
                Ok(Some(req))
            }
            Err(e) => {
                self.errors += 1;
                Err(anyhow::anyhow!("Failed to parse bid request: {e}"))
            }
        }
    }

    /// Returns the total number of successfully parsed requests.
    pub fn parsed_count(&self) -> u64 {
        self.parsed
    }

    /// Returns the total number of parse errors.
    pub fn error_count(&self) -> u64 {
        self.errors
    }
}

impl Default for BidStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Processes a bid stream with configurable batch size and fraud detection.
///
/// Reads a file containing one JSON bid request per line, parses each line,
/// runs fraud detection, and collects results in batches for efficient processing.
#[derive(Clone)]
pub struct BidStreamProcessor {
    /// Number of requests to accumulate before yielding results.
    batch_size: usize,
}

/// A batch of processed results, pairing each request with its fraud score.
#[derive(Debug, Clone)]
pub struct ProcessedBatch {
    /// Results for each request in this batch.
    pub results: Vec<ProcessedResult>,
    /// Timestamp when the batch was produced.
    pub timestamp: DateTime<Utc>,
}

/// The result of processing a single bid request through fraud detection.
#[derive(Debug, Clone)]
pub struct ProcessedResult {
    /// The original bid request.
    pub request: BidRequest,
    /// The fraud score assigned by the detector.
    pub score: crate::detection::FraudScore,
}

impl BidStreamProcessor {
    /// Creates a new processor with the given batch size.
    pub fn new(batch_size: usize) -> Self {
        Self { batch_size }
    }

    /// Process a bid stream file, applying the given fraud detector to each request.
    ///
    /// Returns a vector of `ProcessedBatch`, one per batch of requests.
    pub async fn process_file(
        &self,
        path: impl AsRef<Path>,
        detector: &impl FraudDetector,
    ) -> Result<Vec<ProcessedBatch>> {
        let file = File::open(path.as_ref())
            .await
            .with_context(|| format!("Failed to open {}", path.as_ref().display()))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut batches: Vec<ProcessedBatch> = Vec::new();
        let mut current_batch: Vec<ProcessedResult> = Vec::with_capacity(self.batch_size);
        let mut parser = BidStreamParser::new();

        while let Some(line_result) = lines.next_line().await? {
            match parser.parse_line(&line_result) {
                Ok(Some(req)) => {
                    let score = detector.detect(&req);
                    current_batch.push(ProcessedResult {
                        request: req,
                        score,
                    });
                    if current_batch.len() >= self.batch_size {
                        batches.push(ProcessedBatch {
                            results: std::mem::take(&mut current_batch),
                            timestamp: Utc::now(),
                        });
                    }
                }
                Ok(None) => {} // empty line, skip
                Err(e) => {
                    tracing::warn!("Skipping malformed bid request: {e}");
                }
            }
        }

        // Flush remaining results
        if !current_batch.is_empty() {
            batches.push(ProcessedBatch {
                results: current_batch,
                timestamp: Utc::now(),
            });
        }

        tracing::info!(
            "Processed {} requests ({} errors) in {} batches",
            parser.parsed_count(),
            parser.error_count(),
            batches.len()
        );

        Ok(batches)
    }
}
