use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

use hydra_judge::{JudgeConfig, JudgeServer, ResponseFormat, UnauthorizedAction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Hydra Judge Server Runner ===");

    let http_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let https_addr: SocketAddr = "127.0.0.1:8443".parse()?;
    let token = "hydra_secret_test_token";

    let config = JudgeConfig::builder(http_addr, token)
        .https_bind_addr(https_addr)
        .default_format(ResponseFormat::Azenv)
        .unauthorized_action(UnauthorizedAction::DropRst)
        .build();

    let server = JudgeServer::new(config)?;

    println!("Listening on HTTP:  http://127.0.0.1:8080/?token={token}");
    println!("Listening on HTTPS: https://127.0.0.1:8443/?token={token}");
    println!("(Auto-generated self-signed TLS cert active for HTTPS)");
    println!("Press Ctrl+C to terminate server.");

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("Shutting down Judge server...");
        cancel_clone.cancel();
    });

    server.run(cancel).await?;

    Ok(())
}
