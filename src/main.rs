use anyhow::Result;
use clap::{Parser, Subcommand};

use adverify::bid_stream::BidStreamProcessor;
use adverify::brand_safety::BrandSafetyAnalyzer;
use adverify::detection::{FraudDetector, GeneralizedFraudDetector};
use adverify::reporting::ReportGenerator;

#[derive(Parser)]
#[command(name = "adverify", about = "Ad fraud detection & brand safety engine")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a bid stream log for fraudulent activity
    Analyze {
        /// Path to bid stream log file (one JSON bid request per line)
        #[arg(short, long)]
        input: String,
        /// Output path for the report
        #[arg(short, long, default_value = "report.json")]
        output: String,
        /// Batch size for processing
        #[arg(short, long, default_value_t = 1000)]
        batch: usize,
    },
    /// Verify a single creative URL
    Verify {
        /// Creative URL to verify
        #[arg(short, long)]
        url: String,
    },
    /// Scan publisher content for brand safety
    BrandSafety {
        /// Content text or path to content file
        #[arg(short, long)]
        content: String,
        /// If set, treat content as a file path
        #[arg(short, long)]
        file: bool,
    },
    /// Start the REST API server
    Serve {
        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "adverify=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            input,
            output,
            batch,
        } => {
            tracing::info!("Analyzing bid stream from {input} (batch size: {batch})");
            let processor = BidStreamProcessor::new(batch);
            let detector = GeneralizedFraudDetector::new();
            let results = processor.process_file(&input, &detector).await?;
            let generator = ReportGenerator::new();
            generator.write_json(&output, &results)?;
            tracing::info!("Report written to {output}");
        }
        Commands::Verify { url } => {
            tracing::info!("Verifying creative URL: {url}");
            let detector = GeneralizedFraudDetector::new();
            let client = reqwest::Client::builder()
                .use_rustls_tls()
                .build()?;
            let resp = client
                .get(&url)
                .header("User-Agent", "AdVerify/1.0")
                .send()
                .await?;
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            tracing::info!("URL {url}: status={status}, content-type={content_type}");
            let bid = adverify::bid_stream::BidRequest {
                id: "verify".into(),
                imp: vec![],
                device: None,
                user: None,
                app: None,
                site: None,
            };
            let score = detector.detect(&bid);
            println!("Fraud risk: confidence={:.4}, reasons={:?}", score.confidence, score.reasons);
        }
        Commands::BrandSafety { content, file } => {
            let text = if file {
                std::fs::read_to_string(&content)?
            } else {
                content
            };
            let analyzer = BrandSafetyAnalyzer::new();
            let score = analyzer.analyze(&text);
            println!("Brand safety score: {score:?}");
        }
        Commands::Serve { host, port } => {
            tracing::info!("Starting API server on {host}:{port}");
            serve_api(&host, port).await?;
        }
    }

    Ok(())
}

async fn serve_api(host: &str, port: u16) -> Result<()> {
    tracing::info!("API server not available in CLI binary. Use 'cargo run --bin adverify-api' to start the API server.");
    tracing::info!("Alternatively, use the library directly.");
    Ok(())
}
