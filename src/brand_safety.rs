//! Brand safety analysis engine.
//!
//! Analyzes textual content for brand-unsafe categories using a
//! keyword-based TF-IDF-like scoring approach.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Per-category and overall brand safety results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandSafetyScore {
    /// Score for adult/sexual content (0.0–1.0).
    pub adult: f64,
    /// Score for violent content (0.0–1.0).
    pub violence: f64,
    /// Score for hate speech (0.0–1.0).
    pub hate_speech: f64,
    /// Score for drug-related content (0.0–1.0).
    pub drugs: f64,
    /// Score for gambling content (0.0–1.0).
    pub gambling: f64,
    /// Score for profanity (0.0–1.0).
    pub profanity: f64,
    /// Overall brand safety score — higher means less safe.
    pub overall: f64,
    /// Whether the content is considered brand-unsafe.
    pub is_unsafe: bool,
    /// Specific unsafe content snippets detected.
    pub flagged_terms: Vec<String>,
}

/// Analyzes text content for brand safety using keyword-based NLP.
///
/// Each category has a set of weighted keywords. The analyzer performs
/// case-insensitive matching and computes a TF-IDF-inspired score
/// (term frequency normalized by content length, with diminishing returns
/// for repeated terms).
#[derive(Clone)]
pub struct BrandSafetyAnalyzer {
    /// Category name → (keyword, weight) pairs.
    categories: HashMap<&'static str, Vec<(&'static str, f64)>>,
}

impl BrandSafetyAnalyzer {
    /// Creates a new `BrandSafetyAnalyzer` with a comprehensive keyword lexicon.
    pub fn new() -> Self {
        let mut categories: HashMap<&'static str, Vec<(&'static str, f64)>> = HashMap::new();

        categories.insert(
            "adult",
            vec![
                ("porn", 0.9),
                ("pornography", 1.0),
                ("xxx", 0.8),
                ("adult content", 0.8),
                ("sexual", 0.6),
                ("explicit", 0.7),
                ("nude", 0.7),
                ("nudity", 0.8),
                ("sex", 0.5),
                ("erotic", 0.6),
                ("hentai", 0.8),
                ("onlyfans", 0.9),
                ("cam girl", 0.9),
                ("webcam sex", 1.0),
                ("strip club", 0.8),
                ("escort", 0.8),
                ("nsfw", 0.7),
                ("milf", 0.8),
                ("bdsm", 0.8),
                ("orgy", 0.9),
                ("incest", 1.0),
                ("barely legal", 0.9),
                ("teen porn", 1.0),
            ],
        );

        categories.insert(
            "violence",
            vec![
                ("kill", 0.6),
                ("murder", 0.9),
                ("death", 0.5),
                ("die", 0.4),
                ("shoot", 0.6),
                ("shooting", 0.8),
                ("gun", 0.5),
                ("weapon", 0.5),
                ("bomb", 0.8),
                ("explosion", 0.6),
                ("terrorist", 0.9),
                ("terrorism", 1.0),
                ("massacre", 1.0),
                ("slaughter", 0.9),
                ("behead", 1.0),
                ("torture", 0.8),
                ("abuse", 0.4),
                ("assault", 0.7),
                ("blood", 0.5),
                ("gore", 0.9),
                ("war", 0.4),
                ("genocide", 1.0),
                ("execution", 0.7),
                ("hostage", 0.7),
                ("kidnap", 0.7),
                ("riot", 0.6),
                ("stabbing", 0.7),
            ],
        );

        categories.insert(
            "hate_speech",
            vec![
                ("nazi", 0.9),
                ("white supremacist", 1.0),
                ("racial slur", 1.0),
                ("hate crime", 0.8),
                ("discrimination", 0.4),
                ("bigot", 0.7),
                ("xenophobia", 0.6),
                ("antisemite", 0.9),
                ("holocaust denial", 1.0),
                ("ethnic cleansing", 1.0),
                ("supremacy", 0.8),
                ("racial purity", 0.9),
                ("kkk", 1.0),
                ("neo-nazi", 1.0),
                ("misogyny", 0.6),
                ("homophobic", 0.7),
                ("transphobic", 0.7),
                ("racist", 0.7),
                ("fascist", 0.5),
                ("hate speech", 0.7),
                ("bigotry", 0.6),
            ],
        );

        categories.insert(
            "drugs",
            vec![
                ("cocaine", 0.9),
                ("heroin", 1.0),
                ("marijuana", 0.4),
                ("weed", 0.3),
                ("cannabis", 0.3),
                ("meth", 0.9),
                ("amphetamine", 0.6),
                ("opioid", 0.6),
                ("fentanyl", 0.9),
                ("lsd", 0.7),
                ("ecstasy", 0.7),
                ("mdma", 0.7),
                ("crack", 0.9),
                ("drug dealer", 0.9),
                ("buy weed", 0.6),
                ("order xanax", 0.8),
                ("painkiller", 0.3),
                ("recreational drug", 0.5),
                ("substance abuse", 0.5),
                ("overdose", 0.7),
                ("narcotic", 0.7),
            ],
        );

        categories.insert(
            "gambling",
            vec![
                ("casino", 0.7),
                ("poker", 0.5),
                ("bet", 0.4),
                ("betting", 0.6),
                ("slot machine", 0.7),
                ("roulette", 0.6),
                ("blackjack", 0.5),
                ("lottery", 0.4),
                ("gambling", 0.8),
                ("online casino", 0.9),
                ("sportsbook", 0.7),
                ("wagering", 0.6),
                ("play for real money", 0.8),
                ("jackpot", 0.5),
                ("bingo for cash", 0.6),
                ("bet online", 0.7),
            ],
        );

        categories.insert(
            "profanity",
            vec![
                ("fuck", 0.8),
                ("shit", 0.6),
                ("asshole", 0.6),
                ("bastard", 0.5),
                ("bitch", 0.6),
                ("cunt", 1.0),
                ("damn", 0.3),
                ("dick", 0.6),
                ("piss", 0.4),
                ("slut", 0.7),
                ("whore", 0.8),
                ("motherfucker", 0.9),
                ("cock", 0.7),
                ("bullshit", 0.5),
                ("goddamn", 0.4),
            ],
        );

        Self { categories }
    }

    /// Analyze content and return a brand safety score.
    ///
    /// Uses a TF-IDF-like approach: for each category, counts keyword
    /// occurrences weighted by their importance, then normalizes by the
    /// square root of the content length to account for document size.
    /// Multiple occurrences of the same keyword have diminishing returns
    /// via log(1 + count) scaling.
    pub fn analyze(&self, content: &str) -> BrandSafetyScore {
        let lower = content.to_lowercase();
        let words: Vec<&str> = lower.split_whitespace().collect();
        let doc_len = words.len() as f64;

        let mut flagged_terms: Vec<String> = Vec::new();
        let mut category_scores: HashMap<String, f64> = HashMap::new();

        for (category, keywords) in &self.categories {
            let mut raw_score = 0.0;

            for (keyword, weight) in keywords {
                if lower.contains(keyword) {
                    // Count occurrences
                    let count = lower.matches(keyword).count() as f64;
                    // Diminishing returns: log(1 + count) prevents a single
                    // keyword repeated 100 times from dominating
                    let tf = (1.0 + count).ln();
                    let contribution = tf * weight;

                    raw_score += contribution;

                    // Track flagged terms (limit to avoid noise)
                    if flagged_terms.len() < 50 {
                        let term = format!("{category}:{keyword}");
                        if !flagged_terms.contains(&term) {
                            flagged_terms.push(term);
                        }
                    }
                }
            }

            // Normalize by document length (inverse document frequency proxy)
            let normalized = if doc_len > 0.0 {
                (raw_score / (1.0 + doc_len.sqrt())).clamp(0.0, 1.0)
            } else {
                0.0
            };

            category_scores.insert(category.to_string(), normalized);
        }

        let adult = *category_scores.get("adult").unwrap_or(&0.0);
        let violence = *category_scores.get("violence").unwrap_or(&0.0);
        let hate_speech = *category_scores.get("hate_speech").unwrap_or(&0.0);
        let drugs = *category_scores.get("drugs").unwrap_or(&0.0);
        let gambling = *category_scores.get("gambling").unwrap_or(&0.0);
        let profanity = *category_scores.get("profanity").unwrap_or(&0.0);

        // Overall is the L2 norm of category scores (Euclidean distance)
        let overall = (adult * adult
            + violence * violence
            + hate_speech * hate_speech
            + drugs * drugs
            + gambling * gambling
            + profanity * profanity)
            .sqrt()
            .clamp(0.0, 1.0);

        // Flag as unsafe if any category exceeds 0.5 or overall exceeds 0.4
        let is_unsafe = adult > 0.5
            || violence > 0.5
            || hate_speech > 0.5
            || drugs > 0.5
            || gambling > 0.5
            || profanity > 0.5
            || overall > 0.2;

        BrandSafetyScore {
            adult,
            violence,
            hate_speech,
            drugs,
            gambling,
            profanity,
            overall,
            is_unsafe,
            flagged_terms,
        }
    }
}

impl Default for BrandSafetyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_content() {
        let analyzer = BrandSafetyAnalyzer::new();
        let score = analyzer.analyze(
            "Welcome to our cooking blog. Today we'll make a delicious pasta dish with fresh ingredients.",
        );
        assert!(!score.is_unsafe, "Safe content marked as unsafe: {score:?}");
        assert!(score.overall < 0.2, "Overall score too high for safe content");
    }

    #[test]
    fn test_adult_content() {
        let analyzer = BrandSafetyAnalyzer::new();
        let score = analyzer.analyze(
            "Check out this porn site with explicit adult content and nude videos.",
        );
        assert!(score.is_unsafe, "Adult content not flagged");
        assert!(score.adult > 0.3, "Adult score too low");
    }

    #[test]
    fn test_violent_content() {
        let analyzer = BrandSafetyAnalyzer::new();
        let score = analyzer.analyze(
            "The murder weapon was used in the shooting. The victim died from blood loss.",
        );
        assert!(score.is_unsafe, "Violent content not flagged");
        assert!(score.violence > 0.3, "Violence score too low");
    }

    #[test]
    fn test_hate_speech() {
        let analyzer = BrandSafetyAnalyzer::new();
        let score = analyzer.analyze(
            "Racist white supremacist groups continue to spread hate speech and bigotry.",
        );
        assert!(score.is_unsafe, "Hate speech not flagged");
        assert!(score.hate_speech > 0.3, "Hate speech score too low");
    }

    #[test]
    fn test_all_categories_have_keywords() {
        let analyzer = BrandSafetyAnalyzer::new();
        assert_eq!(analyzer.categories.len(), 6);
        for (name, keywords) in &analyzer.categories {
            assert!(!keywords.is_empty(), "Category '{name}' has no keywords");
        }
    }
}
