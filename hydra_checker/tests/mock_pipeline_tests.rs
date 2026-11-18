use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use hydra_checker::{
    CheckTarget, CheckerConfig, CheckerEngine, ErrorReason, MockDialer, ProxyProtocol, TargetHost,
};

fn test_config_builder() -> hydra_checker::CheckerConfigBuilder {
    let http_url = Url::parse("http://93.184.216.34:80/judge").unwrap();
    let https_url = Url::parse("https://93.184.216.34:443/judge").unwrap();

    CheckerConfig::builder(http_url, https_url, "EXPECTED_TOKEN")
        .connect_timeout(Duration::from_millis(100))
        .handshake_timeout(Duration::from_millis(100))
        .read_write_timeout(Duration::from_millis(150))
        .concurrency_limit(10)
        .max_read_bytes(1024)
}

#[tokio::test]
async fn test_phase1_l4_refused() {
    let config = test_config_builder().build().await.unwrap();

    let dialer = MockDialer::new(|_host, _port, _attempt| Err(ErrorReason::ConnRefused));

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 8080);
    let result = engine.check_single(target).await;

    assert!(!result.is_alive);
    assert_eq!(result.error_reason, Some(ErrorReason::ConnRefused));
}

#[tokio::test]
async fn test_phase1_l4_timeout() {
    let config = test_config_builder().build().await.unwrap();

    let dialer = MockDialer::new(|_host, _port, _attempt| Err(ErrorReason::TimeoutTcp));

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 8080);
    let result = engine.check_single(target).await;

    assert!(!result.is_alive);
    assert_eq!(result.error_reason, Some(ErrorReason::TimeoutTcp));
}

#[tokio::test]
async fn test_anti_tarpit_fast_fail() {
    let config = test_config_builder()
        .handshake_timeout(Duration::from_millis(50))
        .build()
        .await
        .unwrap();

    let dialer = MockDialer::new(|_host, _port, _attempt| {
        let (client, mut server) = tokio::io::duplex(1024);
        // Tarpit: server reads SOCKS5 greeting and never responds
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let _ = server.read(&mut buf).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        Ok(client)
    });

    let dialer_clone = dialer.clone();
    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 1080);
    let result = engine.check_single(target).await;

    assert!(!result.is_alive);
    assert_eq!(result.error_reason, Some(ErrorReason::TimeoutHandshake));
    // Verify anti-tarpit did NOT attempt reconnecting for SOCKS4 or HTTP CONNECT!
    assert_eq!(
        dialer_clone.attempt_count(&TargetHost::parse("8.8.8.8"), 1080),
        1
    );
}

#[tokio::test]
async fn test_plain_http_proxy_success() {
    let config = test_config_builder()
        .real_ip("95.10.10.10".parse().unwrap())
        .build()
        .await
        .unwrap();

    let dialer = MockDialer::new(|_host, _port, _attempt| {
        let (client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("GET http://93.184.216.34/judge?token=EXPECTED_TOKEN HTTP/1.1"));

            let resp = "HTTP/1.1 200 OK\r\n\
                        Content-Type: text/plain\r\n\
                        Connection: close\r\n\
                        \r\n\
                        EXPECTED_TOKEN\n\
                        REMOTE_ADDR = 185.220.101.5\n\
                        HTTP_USER_AGENT = Mozilla/5.0\n";
            server.write_all(resp.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
        });
        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 8080).with_protocol(ProxyProtocol::Http);
    let result = engine.check_single(target).await;

    assert!(result.is_alive);
    assert_eq!(result.detected_protocol, Some(ProxyProtocol::Http));
    assert_eq!(result.external_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(
        result.anonymity_level,
        Some(hydra_checker::AnonymityLevel::Elite)
    );
    assert!(!result.supports_https);
    assert_eq!(result.error_reason, None);
}

#[tokio::test]
async fn test_read_limit_exceeded() {
    let config = test_config_builder()
        .max_read_bytes(30) // Very small read limit for test
        .build()
        .await
        .unwrap();

    let dialer = MockDialer::new(|_host, _port, _attempt| {
        let (client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server.read(&mut buf).await;

            // Send more than 30 bytes
            let large_resp = "HTTP/1.1 200 OK\r\n\
                              Content-Length: 200\r\n\
                              \r\n\
                              EXPECTED_TOKEN and lots of extra data to exceed buffer limit!";
            server.write_all(large_resp.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
        });
        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 8080).with_protocol(ProxyProtocol::Http);
    let result = engine.check_single(target).await;

    assert!(!result.is_alive);
    assert_eq!(result.error_reason, Some(ErrorReason::ReadLimitExceeded));
}

#[tokio::test]
async fn test_judge_mismatch_missing_token() {
    let config = test_config_builder().build().await.unwrap();

    let dialer = MockDialer::new(|_host, _port, _attempt| {
        let (client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server.read(&mut buf).await;

            // 200 OK but WiFi captive portal / ISP ad / missing EXPECTED_TOKEN
            let resp = "HTTP/1.1 200 OK\r\n\
                        Content-Type: text/html\r\n\
                        \r\n\
                        <html><body>Welcome to Hotel WiFi Login</body></html>";
            server.write_all(resp.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
        });
        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 8080).with_protocol(ProxyProtocol::Http);
    let result = engine.check_single(target).await;

    assert!(!result.is_alive);
    assert_eq!(result.error_reason, Some(ErrorReason::JudgeMismatch));
}

#[tokio::test]
async fn test_auto_detect_cascade_fallback_to_plain() {
    let config = test_config_builder()
        .real_ip("95.10.10.10".parse().unwrap())
        .build()
        .await
        .unwrap();

    let dialer = MockDialer::new(|_host, _port, attempt| {
        let (client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            match attempt {
                0 => {
                    // Attempt 0: SOCKS5 greeting -> reject with invalid version
                    let mut buf = [0u8; 16];
                    let _ = server.read(&mut buf).await;
                    server.write_all(&[0x00, 0x00]).await.unwrap();
                }
                1 => {
                    // Attempt 1: SOCKS4 request -> reject
                    let mut buf = [0u8; 32];
                    let _ = server.read(&mut buf).await;
                    server
                        .write_all(&[0x00, 91, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                }
                2 => {
                    // Attempt 2: HTTP CONNECT -> 403 Forbidden
                    let mut buf = [0u8; 256];
                    let _ = server.read(&mut buf).await;
                    server
                        .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                        .await
                        .unwrap();
                }
                3 => {
                    // Attempt 3: Plain HTTP -> 200 OK with Judge body!
                    let mut buf = [0u8; 512];
                    let _ = server.read(&mut buf).await;
                    let resp = "HTTP/1.1 200 OK\r\n\
                                Content-Type: text/plain\r\n\
                                Connection: close\r\n\
                                \r\n\
                                EXPECTED_TOKEN\n\
                                REMOTE_ADDR = 185.220.101.5\n";
                    server.write_all(resp.as_bytes()).await.unwrap();
                    server.flush().await.unwrap();
                }
                _ => {}
            }
        });
        Ok(client)
    });

    let dialer_clone = dialer.clone();
    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    // No expected protocol specified -> trigger Auto-Detect cascade
    let target = CheckTarget::new("8.8.8.8", 8080);
    let result = engine.check_single(target).await;

    assert!(result.is_alive);
    assert_eq!(result.detected_protocol, Some(ProxyProtocol::Http));
    assert!(!result.supports_https);
    assert_eq!(result.external_ip, Some("185.220.101.5".parse().unwrap()));
    // Assert exactly 4 attempts were made (SOCKS5 -> SOCKS4 -> CONNECT -> Plain)
    assert_eq!(
        dialer_clone.attempt_count(&TargetHost::parse("8.8.8.8"), 8080),
        4
    );
}

#[tokio::test]
async fn test_streaming_and_cancellation() {
    let config = test_config_builder()
        .concurrency_limit(5)
        .build()
        .await
        .unwrap();

    let held_servers = Arc::new(Mutex::new(Vec::new()));
    let held_clone = held_servers.clone();

    let dialer = MockDialer::new(move |_host, _port, _attempt| {
        let (client, server) = tokio::io::duplex(256);
        // Keep server endpoints alive so client tasks remain blocked waiting for replies
        held_clone.lock().unwrap().push(server);
        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let cancel_token = tokio_util::sync::CancellationToken::new();

    let mut targets = Vec::new();
    for i in 1..=20 {
        targets.push(CheckTarget::new(format!("8.8.8.{i}"), 8080));
    }

    let cancel_token_clone = cancel_token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        cancel_token_clone.cancel();
    });

    let results = engine.check_batch_with_cancel(targets, cancel_token).await;

    assert_eq!(results.len(), 20);
    let cancelled_count = results
        .iter()
        .filter(|r| r.error_reason == Some(ErrorReason::Cancelled))
        .count();

    assert!(
        cancelled_count > 0,
        "Expected cancelled tasks, found {cancelled_count}"
    );
}

#[tokio::test]
async fn test_fallback_judge_saves_proxy() {
    let config = test_config_builder()
        .real_ip("95.10.10.10".parse().unwrap())
        .build()
        .await
        .unwrap();

    let dialer = MockDialer::new(|_host, _port, attempt| {
        let (client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server.read(&mut buf).await;

            if attempt == 0 {
                // Primary judge failed: captive portal or 503
                let fail_resp = "HTTP/1.1 503 Service Unavailable\r\n\r\nPrimary judge down";
                server.write_all(fail_resp.as_bytes()).await.unwrap();
            } else {
                // Fallback judge (attempt 1) succeeds with valid AZenv response
                let ok_resp = "HTTP/1.1 200 OK\r\n\
                               Content-Type: text/plain\r\n\
                               \r\n\
                               REMOTE_ADDR = 185.220.101.5\n\
                               HTTP_USER_AGENT = Mozilla/5.0\n";
                server.write_all(ok_resp.as_bytes()).await.unwrap();
            }
            server.flush().await.unwrap();
        });
        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 8080).with_protocol(ProxyProtocol::Http);
    let result = engine.check_single(target).await;

    assert!(
        result.is_alive,
        "Expected proxy to be rescued by fallback judge!"
    );
    assert_eq!(result.detected_protocol, Some(ProxyProtocol::Http));
    assert_eq!(result.external_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(result.error_reason, None);
}
