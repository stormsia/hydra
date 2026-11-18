use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use hydra_checker::{CheckTarget, CheckerConfig, CheckerEngine, MockDialer, ProxyProtocol};
use hydra_judge::{JudgeConfig, JudgeServer};

#[tokio::test]
async fn test_checker_against_live_judge_server() {
    // 1. Bind and start real Judge server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let judge_addr = listener.local_addr().unwrap();
    drop(listener);

    let judge_config = JudgeConfig::builder(judge_addr, "HYDRA_PASS_TOKEN").build();
    let server = JudgeServer::new(judge_config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_task = tokio::spawn(async move {
        server.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Build hydra_checker configuration pointing to the live Judge
    let http_url = Url::parse(&format!(
        "http://127.0.0.1:{}/judge?token=HYDRA_PASS_TOKEN",
        judge_addr.port()
    ))
    .unwrap();
    let https_url = Url::parse(&format!(
        "https://127.0.0.1:{}/judge?token=HYDRA_PASS_TOKEN",
        judge_addr.port()
    ))
    .unwrap();

    let checker_cfg = CheckerConfig::builder(http_url, https_url, "HYDRA_PASS_TOKEN")
        .real_ip("198.51.100.99".parse().unwrap()) // Different IP to test anonymity
        .connect_timeout(Duration::from_millis(200))
        .handshake_timeout(Duration::from_millis(200))
        .read_write_timeout(Duration::from_millis(300))
        .build()
        .await
        .unwrap();

    // 3. Mock proxy that forwards the plain HTTP request directly to the real Judge server
    let dialer = MockDialer::new(move |_host, _port, _attempt| {
        let (client, mut proxy_server) = tokio::io::duplex(4096);
        let target_judge = judge_addr;

        tokio::spawn(async move {
            // Forward client request to real Judge server
            let mut judge_stream = TcpStream::connect(target_judge).await.unwrap();

            let mut client_buf = [0u8; 1024];
            let n = proxy_server.read(&mut client_buf).await.unwrap();
            judge_stream.write_all(&client_buf[..n]).await.unwrap();
            judge_stream.flush().await.unwrap();

            // Read response from real Judge and echo back to client
            let mut judge_buf = [0u8; 2048];
            let resp_len = judge_stream.read(&mut judge_buf).await.unwrap();
            proxy_server
                .write_all(&judge_buf[..resp_len])
                .await
                .unwrap();
            proxy_server.flush().await.unwrap();
        });

        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(checker_cfg, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 8080).with_protocol(ProxyProtocol::Http);

    let result = engine.check_single(target).await;

    assert!(
        result.is_alive,
        "Expected alive result from live Judge, got error: {:?}",
        result.error_reason
    );
    assert_eq!(result.detected_protocol, Some(ProxyProtocol::Http));
    assert_eq!(result.external_ip, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(
        result.anonymity_level,
        Some(hydra_checker::AnonymityLevel::Anonymous)
    );
    assert_eq!(result.error_reason, None);

    cancel.cancel();
    let _ = server_task.await;
}
