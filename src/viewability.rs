//! Viewability prediction engine.
//!
//! Predicts whether an ad creative will be viewable based on geometric
//! properties and view time. Implements the IAB standard definition:
//! ≥50% of pixels visible for ≥1 second (display) or ≥2 seconds (video).
//! All logic is pure math — no browser dependencies, WASM-compatible.

use serde::{Deserialize, Serialize};

/// The predicted viewability result for a creative placement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewabilityPrediction {
    /// Predicted probability that the ad is viewable (0.0–1.0).
    pub viewable_probability: f64,
    /// Whether the placement meets IAB viewability thresholds.
    pub meets_iab_standard: bool,
    /// Estimated percentage of pixels visible.
    pub estimated_visible_pixels_pct: f64,
    /// Estimated viewable time in seconds.
    pub estimated_view_time_secs: f64,
    /// Factors influencing the prediction.
    pub factors: Vec<String>,
}

/// Trait for viewability prediction strategies.
pub trait ViewabilityPredictor: Send + Sync {
    /// Predict viewability for a given placement configuration.
    fn predict(&self, params: &ViewabilityParams) -> ViewabilityPrediction;
}

/// Parameters describing an ad placement for viewability prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewabilityParams {
    /// Ad creative width in CSS pixels.
    pub ad_width: u32,
    /// Ad creative height in CSS pixels.
    pub ad_height: u32,
    /// Viewport width in CSS pixels.
    pub viewport_width: u32,
    /// Viewport height in CSS pixels.
    pub viewport_height: u32,
    /// Vertical scroll position of the ad (px from top of page).
    pub ad_position_y: u32,
    /// Horizontal scroll position of the ad (px from left of page).
    pub ad_position_x: u32,
    /// Ad format: "display" or "video".
    pub ad_format: String,
    /// Position type (OpenRTB 5.4): 1=Above Fold, 3=Below Fold, 7=Header, etc.
    pub position_type: Option<u8>,
    /// Expected dwell time on the page in seconds.
    pub dwell_time_secs: f64,
}

/// A geometric viewability predictor using pure mathematical calculations.
///
/// This predictor estimates viewability based on:
/// - **Overlap ratio**: What fraction of the ad is within the visible viewport.
/// - **Position scoring**: Above-fold vs below-fold placement.
/// - **Dwell consistency**: Whether the user is expected to stay long enough.
/// - **Format adjustment**: Video requires longer continuous view time.
///
/// No browser APIs or DOM queries are used — all calculations are
/// geometry-based and suitable for WASM environments.
#[derive(Clone)]
pub struct GeometricPredictor {
    /// Minimum pixel ratio threshold (IAB: 50%).
    pub min_pixel_ratio: f64,
    /// Minimum view time for display ads in seconds (IAB: 1s).
    pub min_display_time: f64,
    /// Minimum view time for video ads in seconds (IAB: 2s).
    pub min_video_time: f64,
}

impl GeometricPredictor {
    /// Creates a new `GeometricPredictor` with IAB standard thresholds.
    pub fn new() -> Self {
        Self {
            min_pixel_ratio: 0.50,
            min_display_time: 1.0,
            min_video_time: 2.0,
        }
    }

    /// Creates a predictor with custom thresholds.
    pub fn with_thresholds(
        min_pixel_ratio: f64,
        min_display_time: f64,
        min_video_time: f64,
    ) -> Self {
        Self {
            min_pixel_ratio,
            min_display_time,
            min_video_time,
        }
    }

    /// Computes the fraction of the ad that is within the visible viewport.
    ///
    /// Uses axis-aligned bounding box intersection. Returns a ratio from 0.0
    /// (fully outside viewport) to 1.0 (fully inside viewport).
    fn compute_visible_ratio(&self, params: &ViewabilityParams) -> f64 {
        let ad_right = params.ad_position_x as f64 + params.ad_width as f64;
        let ad_bottom = params.ad_position_y as f64 + params.ad_height as f64;
        let vp_right = params.viewport_width as f64;
        let vp_bottom = params.viewport_height as f64;

        // Intersection rectangle
        let overlap_left = params.ad_position_x as f64;
        let overlap_top = params.ad_position_y as f64;
        let overlap_right = ad_right.min(vp_right);
        let overlap_bottom = ad_bottom.min(vp_bottom);

        // Check if there is any overlap
        if overlap_left >= overlap_right || overlap_top >= overlap_bottom {
            return 0.0;
        }

        let overlap_width = overlap_right - overlap_left;
        let overlap_height = overlap_bottom - overlap_top;
        let overlap_area = overlap_width * overlap_height;
        let ad_area = params.ad_width as f64 * params.ad_height as f64;

        if ad_area <= 0.0 {
            return 0.0;
        }

        (overlap_area / ad_area).clamp(0.0, 1.0)
    }

    /// Computes a position-based score modifier.
    ///
    /// Above-fold placements (position_type=1) get a bonus.
    /// Below-fold placements get a penalty proportional to distance.
    fn compute_position_score(&self, params: &ViewabilityParams) -> f64 {
        match params.position_type {
            Some(1) => 1.0, // Above the fold — optimal
            Some(3) => {
                // Below the fold — penalty based on how far
                let fold_distance = params.ad_position_y as f64 - params.viewport_height as f64;
                if fold_distance > 0.0 {
                    1.0 - (fold_distance / (params.viewport_height as f64 * 3.0)).clamp(0.0, 0.5)
                } else {
                    1.0
                }
            }
            Some(7) => 1.1_f64.min(1.0), // Header — great position
            Some(4) => 0.6,              // Left/right rail — smaller, often ignored
            _ => {
                // Unknown position: estimate based on vertical offset
                if params.ad_position_y < params.viewport_height {
                    0.9
                } else {
                    0.6
                }
            }
        }
    }

    /// Computes a time-based score based on expected dwell time.
    fn compute_time_score(&self, params: &ViewabilityParams) -> f64 {
        let is_video = params.ad_format.eq_ignore_ascii_case("video");
        let threshold = if is_video {
            self.min_video_time
        } else {
            self.min_display_time
        };

        if params.dwell_time_secs >= threshold {
            // Sigmoid-like curve: smooth transition around the threshold
            1.0 / (1.0 + (-2.0 * (params.dwell_time_secs - threshold)).exp())
        } else {
            // Below threshold: rapidly diminishing score
            let ratio = params.dwell_time_secs / threshold;
            ratio * ratio // Quadratic penalty for short dwell
        }
    }
}

impl Default for GeometricPredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewabilityPredictor for GeometricPredictor {
    fn predict(&self, params: &ViewabilityParams) -> ViewabilityPrediction {
        let mut factors: Vec<String> = Vec::new();

        let visible_ratio = self.compute_visible_ratio(params);
        factors.push(format!(
            "Visible pixel ratio: {:.1}%",
            visible_ratio * 100.0
        ));

        let position_score = self.compute_position_score(params);
        factors.push(format!("Position score: {:.3}", position_score));

        let time_score = self.compute_time_score(params);
        factors.push(format!("Dwell time score: {:.3}", time_score));

        let is_video = params.ad_format.eq_ignore_ascii_case("video");
        let required_min_time = if is_video {
            self.min_video_time
        } else {
            self.min_display_time
        };

        // Combined viewability probability using geometric mean of factors
        let raw_probability = (visible_ratio * position_score * time_score).powf(1.0 / 3.0);
        let viewable_probability = raw_probability.clamp(0.0, 1.0);

        let meets_pixel_threshold = visible_ratio >= self.min_pixel_ratio;
        let meets_time_threshold = params.dwell_time_secs >= required_min_time;
        let meets_iab_standard = meets_pixel_threshold && meets_time_threshold;

        ViewabilityPrediction {
            viewable_probability,
            meets_iab_standard,
            estimated_visible_pixels_pct: visible_ratio * 100.0,
            estimated_view_time_secs: params.dwell_time_secs,
            factors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fully_visible_ad() {
        let predictor = GeometricPredictor::new();
        let params = ViewabilityParams {
            ad_width: 300,
            ad_height: 250,
            viewport_width: 1024,
            viewport_height: 768,
            ad_position_y: 100,
            ad_position_x: 100,
            ad_format: "display".into(),
            position_type: Some(1),
            dwell_time_secs: 5.0,
        };
        let pred = predictor.predict(&params);
        assert!(pred.meets_iab_standard, "Fully visible ad should meet IAB standard");
        assert!((pred.estimated_visible_pixels_pct - 100.0).abs() < 1e-6);
    }

    #[test]
    fn test_completely_hidden_ad() {
        let predictor = GeometricPredictor::new();
        let params = ViewabilityParams {
            ad_width: 300,
            ad_height: 250,
            viewport_width: 1024,
            viewport_height: 768,
            ad_position_y: 10000, // Far below fold
            ad_position_x: 100,
            ad_format: "display".into(),
            position_type: Some(3),
            dwell_time_secs: 0.1,
        };
        let pred = predictor.predict(&params);
        assert!(!pred.meets_iab_standard, "Hidden ad should not meet IAB standard");
        assert!(pred.estimated_visible_pixels_pct < 1.0);
    }

    #[test]
    fn test_partially_visible_ad() {
        let predictor = GeometricPredictor::new();
        let params = ViewabilityParams {
            ad_width: 400,
            ad_height: 300,
            viewport_width: 800,
            viewport_height: 600,
            ad_position_y: 400, // Bottom half is visible
            ad_position_x: 0,
            ad_format: "display".into(),
            position_type: None,
            dwell_time_secs: 3.0,
        };
        let pred = predictor.predict(&params);
        // Ad is at y=400 with height 300, so y range = 400-700
        // Viewport is 0-600. Overlap is 400-600 = 200px.
        // Ratio = (200*400) / (400*300) = 80000/120000 = 0.667
        assert!(
            (pred.estimated_visible_pixels_pct - 66.7).abs() < 1.0,
            "Expected ~66.7% visible, got {}",
            pred.estimated_visible_pixels_pct
        );
    }

    #[test]
    fn test_video_needs_longer_dwell() {
        let predictor = GeometricPredictor::new();
        let params = ViewabilityParams {
            ad_width: 640,
            ad_height: 480,
            viewport_width: 1920,
            viewport_height: 1080,
            ad_position_y: 200,
            ad_position_x: 200,
            ad_format: "video".into(),
            position_type: Some(1),
            dwell_time_secs: 1.5, // >1s but <2s
        };
        let pred = predictor.predict(&params);
        // Should fail because video needs ≥2s
        assert!(!pred.meets_iab_standard, "Video with 1.5s dwell should not meet IAB standard");
    }

    #[test]
    fn test_display_meets_with_1s() {
        let predictor = GeometricPredictor::new();
        let params = ViewabilityParams {
            ad_width: 300,
            ad_height: 250,
            viewport_width: 1024,
            viewport_height: 768,
            ad_position_y: 50,
            ad_position_x: 50,
            ad_format: "display".into(),
            position_type: Some(1),
            dwell_time_secs: 1.0, // Exactly at threshold
        };
        let pred = predictor.predict(&params);
        assert!(pred.meets_iab_standard, "Display ad with 1s dwell should meet IAB standard");
    }
}
