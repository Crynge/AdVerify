use adverify::brand_safety::BrandSafetyAnalyzer;

#[test]
fn test_safe_news_content() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "The Federal Reserve announced a quarter-point interest rate hike today, citing \
         continued strength in the labor market and moderate economic growth. \
         Analysts expect further adjustments in the coming quarters."
    );
    assert!(!score.is_unsafe, "News content should be safe: {:?}", score.flagged_terms);
    assert!(score.overall < 0.3, "Overall safety score too high for news: {}", score.overall);
}

#[test]
fn test_adult_content_flagged() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "Free porn videos and xxx adult content. Watch nude girls and explicit sex scenes online."
    );
    assert!(score.is_unsafe, "Adult content should be flagged");
    assert!(score.adult > 0.3, "Adult score too low: {}", score.adult);
}

#[test]
fn test_violent_content_flagged() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "The murder weapon was found at the scene of the shooting. Police confirmed \
         the victim died from multiple gunshot wounds in what appears to be a terrorist attack."
    );
    assert!(score.is_unsafe, "Violent content should be flagged");
    assert!(score.violence > 0.3, "Violence score too low: {}", score.violence);
}

#[test]
fn test_hate_speech_flagged() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "White supremacist groups and neo-nazi organizations continue to spread racist hate speech."
    );
    assert!(score.is_unsafe, "Hate speech should be flagged");
    assert!(score.hate_speech > 0.3, "Hate speech score too low: {}", score.hate_speech);
}

#[test]
fn test_drug_content_flagged() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "Buy cocaine and heroin online. We sell methamphetamine, fentanyl, and other narcotics."
    );
    assert!(score.is_unsafe, "Drug content should be flagged");
    assert!(score.drugs > 0.3, "Drug score too low: {}", score.drugs);
}

#[test]
fn test_gambling_content_flagged() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "Play at our online casino. We have the best slot machines, poker tables, and sports betting."
    );
    assert!(score.is_unsafe, "Gambling content should be flagged");
    assert!(score.gambling > 0.3, "Gambling score too low: {}", score.gambling);
}

#[test]
fn test_profanity_flagged() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "What the fuck is this shit? This is bullshit and you're an asshole."
    );
    assert!(score.is_unsafe, "Profanity should be flagged");
    assert!(score.profanity > 0.3, "Profanity score too low: {}", score.profanity);
}

#[test]
fn test_mixed_content_raises_overall() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "The casino had slot machines. Some guy was using cocaine in the bathroom. \
         A fight broke out and a shooting occurred."
    );
    assert!(score.is_unsafe, "Mixed unsafe content should be flagged");
    assert!(score.overall > 0.2, "Overall score should reflect multiple unsafe categories");
}

#[test]
fn test_empty_content_is_safe() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze("");
    assert!(!score.is_unsafe, "Empty content should be safe");
    assert_eq!(score.overall, 0.0);
}

#[test]
fn test_all_zero_for_safe_technical() {
    let analyzer = BrandSafetyAnalyzer::new();
    let score = analyzer.analyze(
        "The quick brown fox jumps over the lazy dog. \
         Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    );
    assert!(!score.is_unsafe);
    assert_eq!(score.flagged_terms.len(), 0);
}
