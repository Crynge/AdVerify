use anyhow::Result;
use clap::{Parser, Subcommand};

use adverify::bid_stream::BidStreamProcessor;
use adverify::brand_safety::BrandSafetyAnalyzer;
use adverify::detection::GeneralizedFraudDetector;
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
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use http_body_util::Full;
    use bytes::Bytes;
    use hyper_util::server::auto::Builder as ServerBuilder;
    use hyper_util::rt::TokioExecutor;

    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    let detector = GeneralizedFraudDetector::new();
    let safety = BrandSafetyAnalyzer::new();

    let svc = service_fn(move |req: Request<Incoming>| {
        let detector = detector.clone();
        let safety = safety.clone();
        async move {
            match (req.method(), req.uri().path()) {
                (&Method::GET, "/health") => {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("{\"status\":\"ok\"}"))))
                }
                (&Method::POST, "/detect") => {
                    let body_bytes = hyper::body::to_bytes(req.into_body()).await
                        .map_err(|_| Infallible)?;
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    match serde_json::from_str::<adverify::bid_stream::BidRequest>(&body_str) {
                        Ok(bid) => {
                            let score = detector.detect(&bid);
                            let json = serde_json::to_string(&score).unwrap_or_default();
                            Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .body(Full::new(Bytes::from(json)))
                                .unwrap())
                        }
                        Err(e) => {
                            let err = format!("{{\"error\":\"{}\"}}", e);
                            Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from(err)))
                                .unwrap())
                        }
                    }
                }
                (&Method::POST, "/brand-safety") => {
                    let body_bytes = hyper::body::to_bytes(req.into_body()).await
                        .map_err(|_| Infallible)?;
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    let score = safety.analyze(&body_str);
                    let json = serde_json::to_string(&score).unwrap_or_default();
                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(json)))
                        .unwrap())
                }
                _ => {
                    let not_found = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::new(Bytes::from("{\"error\":\"not found\"}")))
                        .unwrap();
                    Ok(not_found)
                }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let server = ServerBuilder::new(TokioExecutor::new()).serve_tcp(listener, svc);
    server.await?;
    Ok(())
}
