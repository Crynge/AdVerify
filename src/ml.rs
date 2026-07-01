//! Machine learning models for fraud detection.
//!
//! Provides a simple logistic regression classifier with online gradient
//! descent training, feature extraction from bid requests, and
//! feature normalization utilities.

use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};

use crate::bid_stream::BidRequest;

/// A logistic regression classifier for fraud detection.
///
/// Uses sigmoid activation and supports online (streaming) gradient descent
/// training, making it suitable for real-time learning from bid stream data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogisticRegression {
    /// Model weight vector.
    pub weights: Array1<f64>,
    /// Bias term.
    pub bias: f64,
    /// Learning rate for gradient descent.
    pub learning_rate: f64,
    /// L2 regularization strength.
    pub lambda: f64,
    /// Number of training steps performed.
    pub n_steps: u64,
}

impl LogisticRegression {
    /// Creates a new logistic regression model with the given number of features.
    pub fn new(n_features: usize) -> Self {
        Self {
            weights: Array1::zeros(n_features),
            bias: 0.0,
            learning_rate: 0.01,
            lambda: 0.001,
            n_steps: 0,
        }
    }

    /// Creates a model with custom hyperparameters.
    pub fn with_params(n_features: usize, learning_rate: f64, lambda: f64) -> Self {
        Self {
            weights: Array1::zeros(n_features),
            bias: 0.0,
            learning_rate,
            lambda,
            n_steps: 0,
        }
    }

    /// The sigmoid activation function.
    ///
    /// Maps any real value to the range (0, 1), representing a probability.
    pub fn sigmoid(z: f64) -> f64 {
        1.0 / (1.0 + (-z).exp())
    }

    /// Predict the probability of fraud for a given feature vector.
    pub fn predict_proba(&self, features: &Array1<f64>) -> f64 {
        let z = self.weights.dot(features) + self.bias;
        Self::sigmoid(z)
    }

    /// Make a binary prediction (fraudulent or not) for a feature vector.
    pub fn predict(&self, features: &Array1<f64>, threshold: f64) -> bool {
        self.predict_proba(features) >= threshold
    }

    /// Update the model using online gradient descent on a single example.
    ///
    /// Performs one step of gradient descent:
    /// - Computes the prediction error (predicted - actual)
    /// - Updates weights with L2 regularization: w = w - lr * (error * x + lambda * w)
    /// - Updates bias: b = b - lr * error
    pub fn partial_fit(&mut self, features: &Array1<f64>, target: f64) {
        let prediction = self.predict_proba(features);
        let error = prediction - target;

        // Gradient descent update with L2 regularization
        self.weights = &self.weights
            - self.learning_rate * (error * features + self.lambda * &self.weights);
        self.bias -= self.learning_rate * error;

        self.n_steps += 1;
    }

    /// Train on a batch of examples.
    ///
    /// Each row of `features` is one training example.
    /// `targets` must have the same number of elements as rows in `features`.
    pub fn fit(&mut self, features: &Array2<f64>, targets: &Array1<f64>) {
        assert_eq!(
            features.nrows(),
            targets.len(),
            "Number of feature rows must match number of targets"
        );
        for (row, target) in features.rows().into_iter().zip(targets.iter()) {
            self.partial_fit(&row.to_owned(), *target);
        }
    }
}

/// Extracts numerical features from `BidRequest` objects for ML models.
#[derive(Debug, Clone)]
pub struct FeatureExtractor {
    /// Mean values for normalization (fitted on training data).
    means: Option<Array1<f64>>,
    /// Standard deviations for normalization (fitted on training data).
    stds: Option<Array1<f64>>,
}

impl FeatureExtractor {
    /// Creates a new feature extractor.
    pub fn new() -> Self {
        Self {
            means: None,
            stds: None,
        }
    }

    /// Extracts a feature vector from a bid request.
    ///
    /// Features:
    /// 0. Has device (1.0 or 0.0)
    /// 1. Has user (1.0 or 0.0)
    /// 2. Has app (1.0 or 0.0)
    /// 3. Number of impressions (clamped to 10)
    /// 4. DNT flag (device.dnt)
    /// 5. LMT flag (device.lmt)
    /// 6. Has geo in device (1.0 or 0.0)
    /// 7. Device type (normalized to 0..1)
    /// 8. OS known (1.0) or unknown/empty (0.0)
    /// 9. Connection type (normalized to 0..1)
    /// 10. IFA present and non-zeroed (1.0 or 0.0)
    /// 11. App has bundle (1.0 or 0.0)
    /// 12. App bundle name match heuristic (0.0 to 1.0)
    /// 13. Has both app and site (invalid — 1.0 or 0.0)
    /// 14. Language matches geo country heuristic
    /// 15. Device width * height (normalized log scale)
    pub fn extract(&self, request: &BidRequest) -> Array1<f64> {
        let mut features = vec![0.0_f64; 16];

        // [0] Has device
        if let Some(ref device) = request.device {
            features[0] = 1.0;

            // [4] DNT
            features[4] = device.dnt as f64;
            // [5] LMT
            features[5] = device.lmt as f64;
            // [6] Has geo
            features[6] = device.geo.as_ref().map_or(0.0, |_| 1.0);
            // [7] Device type (normalized to 0..1)
            features[7] = device.devicetype.map_or(0.0, |dt| (dt as f64) / 7.0);
            // [8] OS known
            features[8] = if device.os.is_empty()
                || device.os.eq_ignore_ascii_case("unknown")
            {
                0.0
            } else {
                1.0
            };
            // [9] Connection type
            features[9] = device.connectiontype.map_or(0.0, |ct| (ct as f64) / 6.0);
            // [10] IFA present and non-zeroed
            features[10] = if device.ifa.is_empty()
                || device.ifa == "00000000-0000-0000-0000-000000000000"
            {
                0.0
            } else {
                1.0
            };
            // [15] Device area (log scale)
            if let (Some(w), Some(h)) = (device.w, device.h) {
                if w > 0 && h > 0 {
                    features[15] = ((w as f64) * (h as f64)).ln() / 20.0; // normalize
                }
            }
        }

        // [1] Has user
        features[1] = request.user.as_ref().map_or(0.0, |_| 1.0);

        // [2] Has app
        if let Some(ref app) = request.app {
            features[2] = 1.0;
            // [11] App has bundle
            features[11] = if app.bundle.is_empty() { 0.0 } else { 1.0 };
            // [12] App bundle/name match
            if !app.name.is_empty() && !app.bundle.is_empty() {
                let name_lower = app.name.to_lowercase().replace(' ', "");
                let bundle_lower = app.bundle.to_lowercase();
                let bundle_has_name = bundle_lower.contains(&name_lower)
                    || name_lower.contains(&bundle_lower);
                features[12] = if bundle_has_name { 0.0 } else { 1.0 };
            }
        }

        // [3] Number of impressions
        features[3] = (request.imp.len() as f64).min(10.0) / 10.0;

        // [13] Both app and site (invalid)
        features[13] = if request.app.is_some() && request.site.is_some() {
            1.0
        } else {
            0.0
        };

        // [14] Language/geo mismatch heuristic
        if let (Some(ref device), Some(ref geo)) = (request.device.as_ref(), request.device.as_ref().and_then(|d| d.geo.as_ref())) {
            if !geo.country.is_empty() && !device.language.is_empty() {
                let usa_countries = ["usa", "united states", "us"];
                if usa_countries.contains(&geo.country.to_lowercase().as_str())
                    && !device.language.starts_with("en")
                {
                    features[14] = 1.0;
                }
            }
        }

        Array1::from_vec(features)
    }

    /// Computes mean and standard deviation from a batch of feature vectors
    /// for normalization.
    pub fn fit_normalizer(&mut self, features: &Array2<f64>) {
        let n_samples = features.nrows() as f64;
        if n_samples == 0.0 {
            return;
        }

        let means = features.mean_axis(ndarray::Axis(0)).unwrap();
        let mut stds = Array1::zeros(means.len());

        for (i, mean) in means.iter().enumerate() {
            let variance = features
                .column(i)
                .iter()
                .map(|v| (v - mean).powi(2))
                .sum::<f64>()
                / n_samples;
            stds[i] = variance.sqrt().max(1e-8); // Avoid division by zero
        }

        self.means = Some(means);
        self.stds = Some(stds);
    }

    /// Normalize features using fitted mean and standard deviation.
    pub fn normalize(&self, features: &Array1<f64>) -> Array1<f64> {
        match (&self.means, &self.stds) {
            (Some(means), Some(stds)) => {
                let mut normalized = features.clone();
                for i in 0..normalized.len() {
                    normalized[i] = (normalized[i] - means[i]) / stds[i];
                }
                normalized
            }
            None => features.clone(),
        }
    }

    /// Extract and normalize features from a bid request.
    pub fn extract_normalized(&self, request: &BidRequest) -> Array1<f64> {
        let features = self.extract(request);
        self.normalize(&features)
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigmoid() {
        assert!((LogisticRegression::sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(LogisticRegression::sigmoid(100.0) > 0.999);
        assert!(LogisticRegression::sigmoid(-100.0) < 0.001);
    }

    #[test]
    fn test_predict_proba() {
        let model = LogisticRegression::new(3);
        let features = Array1::from_vec(vec![1.0, 2.0, 3.0]);
        let proba = model.predict_proba(&features);
        assert!((0.0..=1.0).contains(&proba), "Probability out of range: {proba}");
    }

    #[test]
    fn test_partial_fit() {
        let mut model = LogisticRegression::new(2);
        let features = Array1::from_vec(vec![1.0, 2.0]);
        let before = model.predict_proba(&features);
        model.partial_fit(&features, 1.0);
        let after = model.predict_proba(&features);
        // After training with target=1.0, probability should increase
        assert!(
            after >= before,
            "Probability should increase after positive training: {before} -> {after}"
        );
    }

    #[test]
    fn test_feature_extraction() {
        let extractor = FeatureExtractor::new();
        let request = BidRequest {
            id: "test".into(),
            imp: vec![crate::bid_stream::Impression {
                id: "1".into(),
                banner: None,
                video: None,
                bidfloor: 0.0,
                bidfloorcur: "USD".into(),
                instl: 0,
                tagid: String::new(),
                secure: 0,
            }],
            device: Some(crate::bid_stream::Device {
                ua: "Mozilla/5.0".into(),
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
                connectiontype: Some(6),
                ifa: "valid-ifa".into(),
            }),
            user: None,
            app: None,
            site: None,
        };
        let features = extractor.extract(&request);
        assert_eq!(features.len(), 16);
        assert_eq!(features[0], 1.0); // Has device
        assert_eq!(features[1], 0.0); // No user
        assert_eq!(features[2], 0.0); // No app
    }

    #[test]
    fn test_fit_normalizer() {
        let mut extractor = FeatureExtractor::new();
        let data = Array2::from_shape_vec((3, 2), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
        extractor.fit_normalizer(&data);
        assert!(extractor.means.is_some());
        assert!(extractor.stds.is_some());
    }
}
