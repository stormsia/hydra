use std::env;
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

use hydra_judge::{JudgeConfig, JudgeServer, ResponseFormat, UnauthorizedAction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let http_port = env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string());
    let https_port = env::var("HTTPS_PORT").ok();
    let secret_token =
        env::var("SECRET_TOKEN").unwrap_or_else(|_| "hydra_secret_token".to_string());

    let http_bind: SocketAddr = format!("0.0.0.0:{http_port}").parse()?;
    let mut builder = JudgeConfig::builder(http_bind, &secret_token);

    if let Some(port) = https_port {
        let https_bind: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        builder = builder.https_bind_addr(https_bind);
    }

    if let Ok(key) = env::var("SECRET_KEY") {
        builder = builder.secret_key(key);
    }

    if let (Ok(cert), Ok(key)) = (env::var("TLS_CERT_PATH"), env::var("TLS_KEY_PATH")) {
        builder = builder.tls_cert_path(cert, key);
    }

    if let Ok(fmt) = env::var("FORMAT")
        && fmt.eq_ignore_ascii_case("json")
    {
        builder = builder.default_format(ResponseFormat::Json);
    }

    if let Ok(act) = env::var("UNAUTHORIZED_ACTION")
        && act.eq_ignore_ascii_case("http_403")
    {
        builder = builder.unauthorized_action(UnauthorizedAction::Http403);
    }

    if let Ok(val) = env::var("MAX_REQUEST_BYTES")
        && let Ok(bytes) = val.parse::<usize>()
    {
        builder = builder.max_request_bytes(bytes);
    }

    if let Ok(val) = env::var("REQUEST_TIMEOUT_SECS")
        && let Ok(secs) = val.parse::<u64>()
    {
        builder = builder.request_timeout(std::time::Duration::from_secs(secs));
    }

    if let Ok(val) = env::var("MAX_CONCURRENT_CONNECTIONS")
        && let Ok(limit) = val.parse::<usize>()
    {
        builder = builder.max_concurrent_connections(limit);
    }

    let config = builder.build();
    let server = JudgeServer::new(config.clone())?;

    println!(
        "Hydra Judge running on HTTP: http://{}",
        config.http_bind_addr
    );
    if let Some(https_addr) = config.https_bind_addr {
        println!("Hydra Judge running on HTTPS: https://{}", https_addr);
    }
    println!("Secret token configured (token required in query/path/header).");

    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("\nShutdown signal received, shutting down gracefully...");
        cancel_clone.cancel();
    });

    server.run(cancel_token).await?;

    Ok(())
}
