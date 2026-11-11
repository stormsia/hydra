use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use hydra_judge::{JudgeConfig, JudgeServer};

#[tokio::test]
async fn test_azenv_reflection_and_remote_addr() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    let config = JudgeConfig::builder(actual_addr, "TOKEN_123").build();
    let server = JudgeServer::new(config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_task = tokio::spawn(async move {
        server.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(actual_addr).await.unwrap();
    let req = "GET /?token=TOKEN_123 HTTP/1.1\r\n\
               Host: judge.local\r\n\
               User-Agent: CustomBot/2.0\r\n\
               Via: 1.1 proxy.local\r\n\
               X-Forwarded-For: 203.0.113.199\r\n\
               \r\n";

    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("Content-Type: text/plain"));
    assert!(resp.contains("REMOTE_ADDR = 127.0.0.1"));
    assert!(resp.contains("HTTP_VIA = 1.1 proxy.local"));
    assert!(resp.contains("HTTP_USER_AGENT = CustomBot/2.0"));
    assert!(resp.contains("HTTP_X_FORWARDED_FOR = 203.0.113.199"));
    assert!(resp.contains("HYDRA_TOKEN = TOKEN_123"));

    cancel.cancel();
    let _ = server_task.await;
}

#[tokio::test]
async fn test_json_reflection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    let config = JudgeConfig::builder(actual_addr, "TOKEN_JSON").build();
    let server = JudgeServer::new(config).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let server_task = tokio::spawn(async move {
        server.run(cancel_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(actual_addr).await.unwrap();
    let req = "GET /?token=TOKEN_JSON&format=json HTTP/1.1\r\n\
               Host: judge.local\r\n\
               User-Agent: JsonClient\r\n\
               Via: 1.1 squid\r\n\
               \r\n";

    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("Content-Type: application/json"));

    // Extract body after \r\n\r\n
    let body = resp.split("\r\n\r\n").nth(1).unwrap();
    let json: serde_json::Value = serde_json::from_str(body).unwrap();

    assert_eq!(json["origin"], "127.0.0.1");
    assert_eq!(json["token"], "TOKEN_JSON");
    assert_eq!(json["headers"]["Via"], "1.1 squid");

    cancel.cancel();
    let _ = server_task.await;
}
