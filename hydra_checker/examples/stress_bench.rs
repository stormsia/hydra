use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use hydra_checker::{CheckTarget, CheckerConfig, CheckerEngine, MockDialer, ProxyProtocol};

#[tokio::main]
async fn main() {
    println!("=== Hydra Checker Stress Benchmark ===");

    let total_targets = 10_000;
    let concurrency_limit = 1_000;

    let http_url = Url::parse("http://93.184.216.34:80/judge").unwrap();
    let https_url = Url::parse("https://93.184.216.34:443/judge").unwrap();

    let config = CheckerConfig::builder(http_url, https_url, "TOKEN")
        .concurrency_limit(concurrency_limit)
        .connect_timeout(Duration::from_millis(50))
        .handshake_timeout(Duration::from_millis(50))
        .read_write_timeout(Duration::from_millis(50))
        .build()
        .await
        .unwrap();

    let checked_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = checked_counter.clone();

    // High-speed mock dialer simulating fast proxy responses
    let dialer = MockDialer::new(move |_host, _port, _attempt| {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = server.read(&mut buf).await;
            let resp = "HTTP/1.1 200 OK\r\n\
                        Connection: close\r\n\
                        \r\n\
                        TOKEN\n\
                        REMOTE_ADDR = 185.220.101.5\n";
            let _ = server.write_all(resp.as_bytes()).await;
            let _ = server.flush().await;
        });
        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();

    let targets = (0..total_targets)
        .map(|i| {
            let octet3 = (i / 256) % 250 + 1;
            let octet4 = (i % 254) + 1;
            CheckTarget::new(format!("185.220.{octet3}.{octet4}"), 8080)
                .with_protocol(ProxyProtocol::Http)
        })
        .collect::<Vec<_>>();

    println!(
        "Starting validation of {total_targets} proxies with concurrency={concurrency_limit}..."
    );
    let start = Instant::now();

    let target_stream = stream::iter(targets);
    let mut results_stream = engine.check_stream(target_stream);

    let mut alive_count = 0;
    while let Some(res) = results_stream.next().await {
        if res.is_alive {
            alive_count += 1;
        }
        counter_clone.fetch_add(1, Ordering::Relaxed);
    }

    let elapsed = start.elapsed();
    let rps = (total_targets as f64) / elapsed.as_secs_f64();

    println!("Completed {total_targets} checks in {:.2?}", elapsed);
    println!("Alive proxies: {alive_count} / {total_targets}");
    println!("Throughput: {:.0} checks/sec", rps);
}
