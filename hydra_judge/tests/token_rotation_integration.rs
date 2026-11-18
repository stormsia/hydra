use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use hydra_checker::{CheckTarget, CheckerConfig, CheckerEngine, MockDialer, ProxyProtocol};
use hydra_judge::token::{current_epoch_day, derive_token};
use hydra_judge::{JudgeConfig, JudgeServer};

#[tokio::test]
async fn test_synchronized_daily_token_rotation() {
    let shared_secret = "hydra_super_secret_preshared_key_2026";

    // 1. Start Judge server using secret_key (dynamic daily token rotation)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let judge_addr = listener.local_addr().unwrap();
    drop(listener);

    let judge_config = JudgeConfig::builder(judge_addr, "fallback_token")
        .secret_key(shared_secret)
        .build();
    let server = JudgeServer::new(judge_config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_clone = server.clone();
    let server_task = tokio::spawn(async move {
        server_clone.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify today's active token is derived identically
    let day = current_epoch_day();
    let expected_today = derive_token(shared_secret, day);
    assert_eq!(server.config().active_token(), expected_today);

    // 2. Configure hydra_checker using the SAME shared_secret and {TOKEN} template
    let http_url = Url::parse(&format!(
        "http://127.0.0.1:{}/judge?token={{TOKEN}}",
        judge_addr.port()
    ))
    .unwrap();
    let https_url = Url::parse(&format!(
        "https://127.0.0.1:{}/judge?token={{TOKEN}}",
        judge_addr.port()
    ))
    .unwrap();

    let checker_cfg = CheckerConfig::builder(http_url, https_url, "fallback_expected")
        .judge_secret_key(shared_secret)
        .real_ip("198.51.100.99".parse().unwrap())
        .connect_timeout(Duration::from_millis(200))
        .handshake_timeout(Duration::from_millis(200))
        .read_write_timeout(Duration::from_millis(300))
        .build()
        .await
        .unwrap();

    // 3. Mock proxy that forwards client requests to the real Judge server
    let dialer = MockDialer::new(move |_host, _port, _attempt| {
        let (client, mut proxy_server) = tokio::io::duplex(4096);
        let target_judge = judge_addr;

        tokio::spawn(async move {
            let mut judge_stream = TcpStream::connect(target_judge).await.unwrap();

            let mut client_buf = [0u8; 1024];
            let n = proxy_server.read(&mut client_buf).await.unwrap();
            judge_stream.write_all(&client_buf[..n]).await.unwrap();
            judge_stream.flush().await.unwrap();

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

    // Must be alive and successfully validated
    assert!(
        result.is_alive,
        "Expected alive result: {:?}",
        result.error_reason
    );
    assert_eq!(result.detected_protocol, Some(ProxyProtocol::Http));
    assert_eq!(result.external_ip, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(result.error_reason, None);

    // 4. Test yesterday's token (grace window around midnight)
    let yesterday_token = derive_token(shared_secret, day.saturating_sub(1));
    let mut stream_yesterday = TcpStream::connect(judge_addr).await.unwrap();
    let req = format!("GET /judge?token={yesterday_token} HTTP/1.1\r\nHost: target\r\n\r\n");
    stream_yesterday.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream_yesterday.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "Yesterday's token must be accepted during grace window"
    );

    // 5. Test expired / bogus token -> must be dropped via TCP RST
    let mut stream_bad = TcpStream::connect(judge_addr).await.unwrap();
    let req_bad = "GET /judge?token=bogus_token_12345 HTTP/1.1\r\nHost: target\r\n\r\n";
    stream_bad.write_all(req_bad.as_bytes()).await.unwrap();

    let mut bad_buf = [0u8; 1024];
    let bad_res = stream_bad.read(&mut bad_buf).await;
    match bad_res {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!(
            "Expected connection reset or EOF for bogus token, got: {:?}",
            other
        ),
    }

    cancel.cancel();
    let _ = server_task.await;
}
