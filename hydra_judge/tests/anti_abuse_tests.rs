use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use hydra_judge::{JudgeConfig, JudgeServer, UnauthorizedAction};

#[tokio::test]
async fn test_unauthorized_scanner_dropped_with_rst() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    let config = JudgeConfig::builder(actual_addr, "SECRET_TOKEN_XYZ")
        .unauthorized_action(UnauthorizedAction::DropRst)
        .build();
    let server = JudgeServer::new(config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_task = tokio::spawn(async move {
        server.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Shodan / Censys scanner probe: no token provided
    let mut stream = TcpStream::connect(actual_addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    // Scanner must receive 0 bytes / connection reset
    let read_res = stream.read(&mut buf).await;
    match read_res {
        Ok(0) => {}                                                     // Clean drop
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {} // TCP RST
        other => panic!("Expected connection reset or EOF, got: {:?}", other),
    }

    // 2. Legitimate probe with secret token
    let mut stream_auth = TcpStream::connect(actual_addr).await.unwrap();
    stream_auth
        .write_all(b"GET /?token=SECRET_TOKEN_XYZ HTTP/1.1\r\nHost: target\r\n\r\n")
        .await
        .unwrap();

    let n = stream_auth.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("HYDRA_TOKEN = SECRET_TOKEN_XYZ"));

    cancel.cancel();
    let _ = server_task.await;
}

#[tokio::test]
async fn test_unauthorized_scanner_http_403() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    let config = JudgeConfig::builder(actual_addr, "SECRET_TOKEN_XYZ")
        .unauthorized_action(UnauthorizedAction::Http403)
        .build();
    let server = JudgeServer::new(config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_task = tokio::spawn(async move {
        server.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send request with wrong token
    let mut stream = TcpStream::connect(actual_addr).await.unwrap();
    stream
        .write_all(b"GET /?token=WRONG_TOKEN HTTP/1.1\r\nHost: target\r\n\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"));

    cancel.cancel();
    let _ = server_task.await;
}

#[tokio::test]
async fn test_token_in_path_and_header() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    let config = JudgeConfig::builder(actual_addr, "SECRET_TOKEN_XYZ").build();
    let server = JudgeServer::new(config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_task = tokio::spawn(async move {
        server.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Token in Path segment
    let mut stream1 = TcpStream::connect(actual_addr).await.unwrap();
    stream1
        .write_all(b"GET /check/SECRET_TOKEN_XYZ HTTP/1.1\r\nHost: target\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream1.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 OK"));

    // 2. Token in X-Hydra-Token header
    let mut stream2 = TcpStream::connect(actual_addr).await.unwrap();
    stream2
        .write_all(
            b"GET /judge HTTP/1.1\r\nHost: target\r\nX-Hydra-Token: SECRET_TOKEN_XYZ\r\n\r\n",
        )
        .await
        .unwrap();
    let n = stream2.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 OK"));

    cancel.cancel();
    let _ = server_task.await;
}

#[tokio::test]
async fn test_concurrency_backpressure_rejection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    // Limit maximum concurrent active connections to exactly 1
    let config = JudgeConfig::builder(actual_addr, "SECRET_TOKEN_XYZ")
        .max_concurrent_connections(1)
        .build();
    let server = JudgeServer::new(config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_task = tokio::spawn(async move {
        server.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect Connection 1 (consumes the 1 permit)
    let mut stream1 = TcpStream::connect(actual_addr).await.unwrap();
    stream1
        .write_all(b"GET /?token=SECRET_TOKEN_XYZ HTTP/1.1\r\n")
        .await
        .unwrap();

    // While Connection 1 is still being processed, attempt Connection 2
    // Connection 2 exceeds semaphore capacity -> must be dropped with RST or EOF (at connect or read time)
    let mut buf = [0u8; 128];
    let connect_res = TcpStream::connect(actual_addr).await;
    match connect_res {
        Err(e)
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            // Dropped immediately during TCP handshake via RST
        }
        Ok(mut stream2) => {
            let res = stream2.read(&mut buf).await;
            match res {
                Ok(0) => {} // Dropped (EOF)
                Err(e)
                    if e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::ConnectionRefused => {} // TCP RST
                other => panic!(
                    "Expected connection reset or EOF due to backpressure, got: {:?}",
                    other
                ),
            }
        }
        Err(other) => panic!(
            "Expected connection reset or refused due to backpressure, got: {:?}",
            other
        ),
    }

    // Now complete Connection 1
    stream1.write_all(b"Host: test\r\n\r\n").await.unwrap();
    let n1 = stream1.read(&mut buf).await.unwrap();
    let resp1 = String::from_utf8_lossy(&buf[..n1]);
    assert!(resp1.starts_with("HTTP/1.1 200 OK"));

    cancel.cancel();
    let _ = server_task.await;
}
