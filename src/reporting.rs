//! Reporting and data export.
//!
//! Generates summary reports from fraud detection results in JSON and CSV
//! formats, and provides structured data suitable for a web dashboard.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::bid_stream::ProcessedBatch;

/// Summary statistics for a batch of processed bid requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
    /// Total number of requests processed.
    pub total_requests: u64,
    /// Number of fraudulent requests detected.
    pub fraudulent_requests: u64,
    /// Percentage of requests flagged as fraudulent.
    pub fraud_rate: f64,
    /// Average confidence score across all requests.
    pub avg_confidence: f64,
    /// Maximum confidence score observed.
    pub max_confidence: f64,
    /// Distribution of fraud confidence in deciles (0-10, 10-20, ..., 90-100).
    pub confidence_distribution: Vec<u64>,
    /// Most common fraud reasons.
    pub top_reasons: Vec<(String, u64)>,
    /// Breakdown by detection category.
    pub category_breakdown: HashMap<String, u64>,
    /// Per-batch breakdown.
    pub batches: Vec<BatchSummary>,
}

/// Summary of a single processing batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Batch index.
    pub batch_index: usize,
    /// Number of requests in this batch.
    pub count: usize,
    /// Number of fraudulent requests in this batch.
    pub fraudulent: usize,
    /// Timestamp of the batch.
    pub timestamp: DateTime<Utc>,
}

/// Dashboard-friendly data format for potential web UI integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    /// Latest report summary.
    pub report: Report,
    /// Time series of fraud rates (for charting).
    pub fraud_rate_ts: Vec<TimeSeriesPoint>,
    /// Distribution pie chart data.
    pub category_distribution: Vec<CategoryData>,
}

/// A single point in a time series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    /// Timestamp of this data point.
    pub timestamp: DateTime<Utc>,
    /// Value at this point.
    pub value: f64,
}

/// Category data for dashboard charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryData {
    /// Category name.
    pub name: String,
    /// Count of requests flagged under this category.
    pub count: u64,
    /// Percentage of total flagged requests.
    pub percentage: f64,
}

/// Generates reports from processed bid stream data.
#[derive(Clone)]
pub struct ReportGenerator;

impl ReportGenerator {
    /// Creates a new `ReportGenerator`.
    pub fn new() -> Self {
        Self
    }

    /// Generate a summary report from processed batches.
    pub fn generate_report(&self, batches: &[ProcessedBatch]) -> Report {
        let total_requests: u64 = batches.iter().map(|b| b.results.len() as u64).sum();
        let fraudulent_requests: u64 = batches
            .iter()
            .flat_map(|b| &b.results)
            .filter(|r| r.score.is_fraudulent)
            .count() as u64;

        let fraud_rate = if total_requests > 0 {
            fraudulent_requests as f64 / total_requests as f64
        } else {
            0.0
        };

        // Confidence statistics
        let all_confidences: Vec<f64> = batches
            .iter()
            .flat_map(|b| &b.results)
            .map(|r| r.score.confidence)
            .collect();

        let avg_confidence = if all_confidences.is_empty() {
            0.0
        } else {
            all_confidences.iter().sum::<f64>() / all_confidences.len() as f64
        };

        let max_confidence = all_confidences
            .iter()
            .cloned()
            .fold(0.0_f64, f64::max);

        // Confidence distribution (deciles)
        let mut confidence_distribution = vec![0_u64; 10];
        for c in &all_confidences {
            let bucket = ((c * 10.0) as usize).min(9);
            confidence_distribution[bucket] += 1;
        }

        // Top fraud reasons
        let mut reason_counts: HashMap<String, u64> = HashMap::new();
        let mut category_breakdown: HashMap<String, u64> = HashMap::new();

        for batch in batches {
            for result in &batch.results {
                for reason in &result.score.reasons {
                    *reason_counts.entry(reason.clone()).or_default() += 1;
                }
            }
        }

        // Simple category extraction from reason prefixes
        for (reason, _count) in &reason_counts {
            let category = reason.split(':').next().unwrap_or("unknown").to_string();
            *category_breakdown.entry(category).or_default() += 1;
        }

        let mut top_reasons: Vec<(String, u64)> = reason_counts.into_iter().collect();
        top_reasons.sort_by(|a, b| b.1.cmp(&a.1));
        top_reasons.truncate(20);

        // Batch summaries
        let batches_summary: Vec<BatchSummary> = batches
            .iter()
            .enumerate()
            .map(|(idx, batch)| {
                let fraudulent = batch
                    .results
                    .iter()
                    .filter(|r| r.score.is_fraudulent)
                    .count();
                BatchSummary {
                    batch_index: idx,
                    count: batch.results.len(),
                    fraudulent,
                    timestamp: batch.timestamp,
                }
            })
            .collect();

        Report {
            generated_at: Utc::now(),
            total_requests,
            fraudulent_requests,
            fraud_rate,
            avg_confidence,
            max_confidence,
            confidence_distribution,
            top_reasons,
            category_breakdown,
            batches: batches_summary,
        }
    }

    /// Write a report to a JSON file.
    pub fn write_json(&self, path: impl AsRef<Path>, batches: &[ProcessedBatch]) -> Result<()> {
        let report = self.generate_report(batches);
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path.as_ref(), json)?;
        Ok(())
    }

    /// Write a report to a CSV file.
    ///
    /// The CSV contains one row per batch with summary statistics.
    pub fn write_csv(&self, path: impl AsRef<Path>, batches: &[ProcessedBatch]) -> Result<()> {
        let mut wtr = csv::Writer::from_path(path.as_ref())?;

        wtr.write_record(&[
            "batch_index",
            "timestamp",
            "total",
            "fraudulent",
            "fraud_rate",
        ])?;

        for (idx, batch) in batches.iter().enumerate() {
            let total = batch.results.len();
            let fraudulent = batch
                .results
                .iter()
                .filter(|r| r.score.is_fraudulent)
                .count();
            let rate = if total > 0 {
                fraudulent as f64 / total as f64
            } else {
                0.0
            };

            wtr.write_record(&[
                idx.to_string(),
                batch.timestamp.to_rfc3339(),
                total.to_string(),
                fraudulent.to_string(),
                format!("{:.4}", rate),
            ])?;
        }

        wtr.flush()?;
        Ok(())
    }

    /// Generate dashboard-ready data from processed batches.
    pub fn generate_dashboard_data(&self, batches: &[ProcessedBatch]) -> DashboardData {
        let report = self.generate_report(batches);

        let fraud_rate_ts: Vec<TimeSeriesPoint> = batches
            .iter()
            .map(|b| {
                let total = b.results.len();
                let fraudulent = b.results.iter().filter(|r| r.score.is_fraudulent).count();
                let rate = if total > 0 {
                    fraudulent as f64 / total as f64
                } else {
                    0.0
                };
                TimeSeriesPoint {
                    timestamp: b.timestamp,
                    value: rate,
                }
            })
            .collect();

        let total_flagged: u64 = report.category_breakdown.values().sum();
        let category_distribution: Vec<CategoryData> = report
            .category_breakdown
            .iter()
            .map(|(name, count)| {
                let percentage = if total_flagged > 0 {
                    *count as f64 / total_flagged as f64 * 100.0
                } else {
                    0.0
                };
                CategoryData {
                    name: name.clone(),
                    count: *count,
                    percentage,
                }
            })
            .collect();

        DashboardData {
            report,
            fraud_rate_ts,
            category_distribution,
        }
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bid_stream::ProcessedResult;
    use crate::bid_stream::BidRequest;
    use crate::detection::FraudScore;

    fn make_result(is_fraud: bool, conf: f64, reasons: Vec<String>) -> ProcessedResult {
        ProcessedResult {
            request: BidRequest {
                id: "test".into(),
                imp: vec![],
                device: None,
                user: None,
                app: None,
                site: None,
            },
            score: FraudScore {
                is_fraudulent: is_fraud,
                confidence: conf,
                reasons,
            },
        }
    }

    #[test]
    fn test_report_generation() {
        let batch = ProcessedBatch {
            results: vec![
                make_result(true, 0.9, vec!["bot".into()]),
                make_result(false, 0.1, vec![]),
                make_result(true, 0.7, vec!["click injection".into()]),
                make_result(false, 0.05, vec![]),
            ],
            timestamp: Utc::now(),
        };

        let generator = ReportGenerator::new();
        let report = generator.generate_report(&[batch]);

        assert_eq!(report.total_requests, 4);
        assert_eq!(report.fraudulent_requests, 2);
        assert!((report.fraud_rate - 0.5).abs() < 1e-6);
        assert_eq!(report.top_reasons.len(), 2);
    }

    #[test]
    fn test_empty_report() {
        let generator = ReportGenerator::new();
        let report = generator.generate_report(&[]);
        assert_eq!(report.total_requests, 0);
        assert_eq!(report.fraudulent_requests, 0);
    }

    #[test]
    fn test_dashboard_data() {
        let batch = ProcessedBatch {
            results: vec![make_result(true, 0.8, vec!["violence:war".into()])],
            timestamp: Utc::now(),
        };
        let generator = ReportGenerator::new();
        let data = generator.generate_dashboard_data(&[batch]);
        assert_eq!(data.fraud_rate_ts.len(), 1);
    }
}
