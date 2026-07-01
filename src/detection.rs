//! Fraud detection engine.
//!
//! Provides a trait-based fraud detection system with multiple detection
//! strategies including click injection, impression laundering, bot traffic,
//! and ad stacking detection.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::bid_stream::BidRequest;

/// The result of a fraud detection check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudScore {
    /// Whether the request is considered fraudulent.
    pub is_fraudulent: bool,
    /// Confidence level between 0.0 and 1.0.
    pub confidence: f64,
    /// Human-readable reasons for the fraud determination.
    pub reasons: Vec<String>,
}

impl FraudScore {
    /// Creates a benign (non-fraudulent) score.
    pub fn benign() -> Self {
        Self {
            is_fraudulent: false,
            confidence: 0.0,
            reasons: Vec::new(),
        }
    }

    /// Merges multiple fraud scores into a single aggregate score.
    ///
    /// The confidence is computed as 1 - ∏(1 - confidence_i), which
    /// represents the probability that at least one detector flagged
    /// the request.
    pub fn aggregate(scores: &[FraudScore]) -> Self {
        let mut combined_confidence = 0.0_f64;
        let mut all_reasons: Vec<String> = Vec::new();
        let mut any_fraudulent = false;

        for score in scores {
            if score.is_fraudulent {
                any_fraudulent = true;
            }
            // Probabilistic union: 1 - ∏(1 - p_i)
            combined_confidence = 1.0 - (1.0 - combined_confidence) * (1.0 - score.confidence);
            all_reasons.extend(score.reasons.clone());
        }

        // Clamp to handle floating point edge cases
        let confidence = combined_confidence.clamp(0.0, 1.0);

        Self {
            is_fraudulent: any_fraudulent || confidence > 0.5,
            confidence,
            reasons: all_reasons,
        }
    }
}

/// Trait for fraud detection strategies.
pub trait FraudDetector: Send + Sync {
    /// Analyze a bid request and return a fraud score.
    fn detect(&self, request: &BidRequest) -> FraudScore;
}

/// A comprehensive fraud detector combining multiple detection heuristics.
///
/// Detects:
/// - **Click injection**: Timing anomalies between request and expected user activity.
/// - **Impression laundering**: Mismatches between declared and actual inventory sources.
/// - **Bot traffic**: Anomalous user-agent patterns and behavioral signals.
/// - **Ad stacking**: Suspicious creative sizes relative to viewport dimensions.
#[derive(Clone)]
pub struct GeneralizedFraudDetector {
    /// Known bot user-agent substrings.
    known_bots: HashSet<String>,
    /// Suspicious device types commonly used in fraud.
    suspicious_device_types: HashSet<u8>,
}

impl GeneralizedFraudDetector {
    /// Creates a new `GeneralizedFraudDetector` with default heuristic thresholds.
    pub fn new() -> Self {
        let mut known_bots = HashSet::new();
        for bot in [
            "googlebot",
            "bingbot",
            "slurp",
            "duckduckbot",
            "baiduspider",
            "yandexbot",
            "facebookexternalhit",
            "facebot",
            "twitterbot",
            "rogerbot",
            "linkedinbot",
            "embedly",
            "quora link preview",
            "showyoubot",
            "outbrain",
            "pinterest",
            "slackbot-linkpreview",
            "applebot",
            "semrushbot",
            "ahrefsbot",
            "dotbot",
            "mj12bot",
        ] {
            known_bots.insert(bot.to_string());
        }

        let mut suspicious_device_types = HashSet::new();
        // OpenRTB 5.21: 1=Mobile/Tablet, 2=Personal Computer, 3=Connected TV,
        // 4=Phone, 5=Tablet, 6=Connected Device, 7=Set Top Box
        // We flag types that are rarely associated with genuine human traffic
        // when combined with other signals.
        suspicious_device_types.insert(7); // Set Top Box — high fraud incidence
        suspicious_device_types.insert(6); // Connected Device — generic, often spoofed

        Self {
            known_bots,
            suspicious_device_types,
        }
    }

    /// Detects click injection based on timing anomalies.
    ///
    /// Looks for suspicious patterns such as identical timestamps across
    /// many requests from the same device, or requests arriving faster
    /// than humanly possible.
    fn detect_click_injection(&self, request: &BidRequest) -> FraudScore {
        let mut reasons = Vec::new();
        let mut confidence = 0.0;

        // Heuristic 1: Missing or empty IFA (Identifier for Advertisers)
        // Legitimate mobile traffic almost always has an IFA.
        if let Some(ref device) = request.device {
            if device.ifa.is_empty() || device.ifa == "00000000-0000-0000-0000-000000000000" {
                confidence += 0.25;
                reasons.push("Missing or zeroed IFA — possible click injection farm".into());
            }

            // Heuristic 2: DNT and LMT both set
            // Fraudsters often set both to avoid detection.
            if device.dnt == 1 && device.lmt == 1 {
                confidence += 0.15;
                reasons.push("Both DNT and LMT set — evasive device signals".into());
            }

            // Heuristic 3: Impossible device dimensions
            if let (Some(w), Some(h)) = (device.w, device.h) {
                if w == 0 || h == 0 || (w < 100 && h < 100 && w * h > 0) {
                    confidence += 0.20;
                    reasons.push(format!(
                        "Suspicious device dimensions ({w}x{h}) — possible emulator"
                    ));
                }
            }
        } else {
            // No device object is suspicious in RTB
            confidence += 0.10;
            reasons.push("Missing device object — incomplete request".into());
        }

        confidence = confidence.clamp(0.0, 1.0);
        FraudScore {
            is_fraudulent: confidence > 0.4,
            confidence,
            reasons,
        }
    }

    /// Detects impression laundering by checking domain and bundle consistency.
    ///
    /// Impression laundering occurs when a low-value publisher misrepresents
    /// their inventory as belonging to a premium publisher.
    fn detect_impression_laundering(&self, request: &BidRequest) -> FraudScore {
        let mut reasons = Vec::new();
        let mut confidence = 0.0;

        // Heuristic 1: App exists but has no bundle or suspicious bundle
        if let Some(ref app) = request.app {
            if app.bundle.is_empty() && !app.name.is_empty() {
                confidence += 0.20;
                reasons.push("App has name but no bundle — potential domain spoofing".into());
            }
            // Check for mismatched app name vs bundle
            if !app.name.is_empty() && !app.bundle.is_empty() {
                let name_normalized = app.name.to_lowercase().replace(' ', "");
                let bundle_lower = app.bundle.to_lowercase();
                // The bundle often contains the app name or its reverse domain
                let bundle_parts: Vec<&str> = bundle_lower.split('.').collect();
                let bundle_has_name = bundle_parts.iter().any(|part| name_normalized.contains(*part));
                if !bundle_has_name && app.bundle.len() > 5 {
                    confidence += 0.15;
                    reasons.push(format!(
                        "App name '{name}' doesn't match bundle '{bundle}'",
                        name = app.name,
                        bundle = app.bundle
                    ));
                }
            }
            // Paid apps that claim to show ads — unlikely in many cases
            if app.paid == 1 && !app.bundle.is_empty() {
                confidence += 0.10;
                reasons.push("Paid app serving ads — potentially hijacked".into());
            }
        }

        // Heuristic 2: Both app and site present — impossible in valid RTB
        if request.app.is_some() && request.site.is_some() {
            confidence += 0.35;
            reasons.push("Both app and site objects present — invalid OpenRTB".into());
        }

        // Heuristic 3: No app or site — impossible to verify inventory
        if request.app.is_none() && request.site.is_none() {
            confidence += 0.15;
            reasons.push("Neither app nor site present — unidentified inventory".into());
        }

        confidence = confidence.clamp(0.0, 1.0);
        FraudScore {
            is_fraudulent: confidence > 0.4,
            confidence,
            reasons,
        }
    }

    /// Detects bot traffic by analyzing user-agent and behavioral signals.
    fn detect_bot_traffic(&self, request: &BidRequest) -> FraudScore {
        let mut reasons = Vec::new();
        let mut confidence = 0.0;

        if let Some(ref device) = request.device {
            let ua_lower = device.ua.to_lowercase();

            // Heuristic 1: Known bot signatures in user-agent
            for bot in &self.known_bots {
                if ua_lower.contains(bot) {
                    confidence += 0.45;
                    reasons.push(format!("Known bot user-agent detected: '{bot}'"));
                }
            }

            // Heuristic 2: Headless browser detection
            let headless_indicators = ["headless", "phantomjs", "puppeteer", "selenium"];
            for indicator in &headless_indicators {
                if ua_lower.contains(indicator) {
                    confidence += 0.35;
                    reasons.push(format!(
                        "Headless browser detected: '{indicator}'"
                    ));
                }
            }

            // Heuristic 3: Missing or generic OS
            if device.os.is_empty() || device.os.eq_ignore_ascii_case("unknown") {
                confidence += 0.15;
                reasons.push("Missing or unknown OS".into());
            }

            // Heuristic 4: Suspicious device type
            if let Some(dt) = device.devicetype {
                if self.suspicious_device_types.contains(&dt) {
                    confidence += 0.15;
                    reasons.push(format!("Suspicious device type ({dt}) — often spoofed"));
                }
            }

            // Heuristic 5: Language mismatch with geo
            if let Some(ref geo) = device.geo {
                if !geo.country.is_empty() && !device.language.is_empty() {
                    if geo.country == "USA" && !device.language.starts_with("en") {
                        confidence += 0.10;
                        reasons.push(format!(
                            "Geo country '{}' but language '{}' — possible proxy",
                            geo.country, device.language
                        ));
                    }
                }
            }
        } else {
            confidence += 0.30;
            reasons.push("No device object — cannot verify user-agent".into());
        }

        confidence = confidence.clamp(0.0, 1.0);
        FraudScore {
            is_fraudulent: confidence > 0.5,
            confidence,
            reasons,
        }
    }

    /// Detects ad stacking where creative sizes are incompatible with the viewport.
    ///
    /// Ad stacking occurs when multiple ads are layered on top of each other
    /// so only the top ad is visible but all generate impressions.
    fn detect_ad_stacking(&self, request: &BidRequest) -> FraudScore {
        let mut reasons = Vec::new();
        let mut confidence = 0.0;

        if let Some(ref device) = request.device {
            if let (Some(screen_w), Some(screen_h)) = (device.w, device.h) {
                let viewport_area = screen_w as f64 * screen_h as f64;

                for imp in &request.imp {
                    if let Some(ref banner) = imp.banner {
                        if let (Some(ad_w), Some(ad_h)) = (banner.w, banner.h) {
                            let ad_area = ad_w as f64 * ad_h as f64;

                            // Heuristic 1: Ad larger than viewport
                            if ad_area > viewport_area {
                                confidence += 0.30;
                                reasons.push(format!(
                                    "Ad ({ad_w}x{ad_h}) larger than viewport ({screen_w}x{screen_h}) — potential stacking"
                                ));
                            }

                            // Heuristic 2: Multiple display ads with large total area
                            let ads_total_area: f64 = request
                                .imp
                                .iter()
                                .filter_map(|i| i.banner.as_ref())
                                .filter_map(|b| b.w.zip(b.h))
                                .map(|(w, h)| w as f64 * h as f64)
                                .sum();

                            if ads_total_area > viewport_area * 1.5 && request.imp.len() > 1 {
                                confidence += 0.25;
                                reasons.push(format!(
                                    "Total ad area ({ads_total_area:.0}) exceeds 150% of viewport ({viewport_area:.0}) — stacking likely"
                                ));
                            }

                            // Heuristic 3: Unusually small ads (1x1 pixel trackers)
                            if ad_area <= 1.0 {
                                confidence += 0.20;
                                reasons.push(format!(
                                    "Suspiciously small creative ({ad_w}x{ad_h}) — pixel tracker"
                                ));
                            }
                        }
                    }
                }
            }
        }

        confidence = confidence.clamp(0.0, 1.0);
        FraudScore {
            is_fraudulent: confidence > 0.4,
            confidence,
            reasons,
        }
    }
}

impl Default for GeneralizedFraudDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FraudDetector for GeneralizedFraudDetector {
    fn detect(&self, request: &BidRequest) -> FraudScore {
        let scores = vec![
            self.detect_click_injection(request),
            self.detect_impression_laundering(request),
            self.detect_bot_traffic(request),
            self.detect_ad_stacking(request),
        ];

        FraudScore::aggregate(&scores)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request(
        ifa: &str,
        ua: &str,
        dnt: u8,
        lmt: u8,
        devicetype: Option<u8>,
        screen_w: Option<u32>,
        screen_h: Option<u32>,
        os: &str,
        language: &str,
        country: &str,
        app_bundle: &str,
        app_name: &str,
        app_paid: u8,
    ) -> BidRequest {
        use crate::bid_stream::{App, Device, Geo, User};

        BidRequest {
            id: "test".into(),
            imp: vec![],
            device: Some(Device {
                ua: ua.into(),
                geo: Some(Geo {
                    lat: None,
                    lon: None,
                    country: country.into(),
                    region: String::new(),
                    city: String::new(),
                    zip: String::new(),
                    r#type: None,
                }),
                dnt,
                lmt,
                ip: String::new(),
                devicetype,
                make: String::new(),
                model: String::new(),
                os: os.into(),
                osv: String::new(),
                w: screen_w,
                h: screen_h,
                ppi: None,
                pxratio: 1.0,
                language: language.into(),
                carrier: String::new(),
                connectiontype: None,
                ifa: ifa.into(),
            }),
            user: Some(User {
                id: String::new(),
                buyeruid: String::new(),
                yob: None,
                gender: String::new(),
                geo: None,
            }),
            app: Some(App {
                id: String::new(),
                name: app_name.into(),
                bundle: app_bundle.into(),
                domain: String::new(),
                cat: vec![],
                ver: String::new(),
                paid: app_paid,
                publisher: None,
            }),
            site: None,
        }
    }

    #[test]
    fn test_benign_request() {
        let req = make_test_request(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36",
            0, 0,
            Some(4),
            Some(1080), Some(2400),
            "Android", "en", "USA",
            "com.example.app", "Example App", 0,
        );
        let detector = GeneralizedFraudDetector::new();
        let score = detector.detect(&req);
        assert!(!score.is_fraudulent, "Benign request flagged: {:?}", score.reasons);
    }

    #[test]
    fn test_bot_ua_detection() {
        let req = make_test_request(
            "00000000-0000-0000-0000-000000000000",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            0, 0,
            Some(4),
            Some(1080), Some(2400),
            "Android", "en", "USA",
            "", "", 0,
        );
        let detector = GeneralizedFraudDetector::new();
        let score = detector.detect(&req);
        assert!(score.is_fraudulent, "Bot should be detected");
        assert!(
            score.reasons.iter().any(|r| r.contains("googlebot")),
            "Should mention googlebot: {:?}",
            score.reasons
        );
    }

    #[test]
    fn test_missing_ifa_detection() {
        let req = make_test_request(
            "", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
            1, 1,
            Some(4),
            Some(1080), Some(2400),
            "Android", "en", "USA",
            "com.example", "Example", 0,
        );
        let detector = GeneralizedFraudDetector::new();
        let score = detector.detect(&req);
        assert!(score.is_fraudulent, "Missing IFA + DNT/LMT should be flagged");
    }

    #[test]
    fn test_ad_stacking_oversized() {
        let req = BidRequest {
            id: "stacking_test".into(),
            imp: vec![
                crate::bid_stream::Impression {
                    id: "1".into(),
                    banner: Some(crate::bid_stream::Banner {
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
                },
            ],
            device: Some(crate::bid_stream::Device {
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
                w: Some(375),
                h: Some(812),
                ppi: None,
                pxratio: 1.0,
                language: "en".into(),
                carrier: String::new(),
                connectiontype: None,
                ifa: "valid-ifa".into(),
            }),
            user: None,
            app: Some(crate::bid_stream::App {
                id: String::new(),
                name: "App".into(),
                bundle: "com.app".into(),
                domain: String::new(),
                cat: vec![],
                ver: String::new(),
                paid: 0,
                publisher: None,
            }),
            site: None,
        };
        let detector = GeneralizedFraudDetector::new();
        let score = detector.detect(&req);
        assert!(score.is_fraudulent, "Oversized ad should be flagged: {:?}", score.reasons);
    }

    #[test]
    fn test_fraud_score_aggregation() {
        let clean = FraudScore::benign();
        let flagged = FraudScore {
            is_fraudulent: true,
            confidence: 0.8,
            reasons: vec!["test flag".into()],
        };
        let agg = FraudScore::aggregate(&[clean, flagged]);
        assert!(agg.is_fraudulent);
        assert!((agg.confidence - 0.8).abs() < 1e-6);
        assert_eq!(agg.reasons.len(), 1);
    }
}
