use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::JudgeConfig;
use crate::error::JudgeError;
use crate::metrics::JudgeMetrics;
use crate::server::connection::{ConnectionStream, handle_connection};
use crate::tls::build_server_tls_config;

pub mod connection;
pub mod security;

/// Multi-protocol authorized echo server (HTTP + HTTPS)
#[derive(Clone)]
pub struct JudgeServer {
    config: Arc<JudgeConfig>,
    metrics: Arc<JudgeMetrics>,
    tls_acceptor: Option<TlsAcceptor>,
    connection_semaphore: Arc<tokio::sync::Semaphore>,
}

impl JudgeServer {
    pub fn new(config: JudgeConfig) -> Result<Self, JudgeError> {
        let tls_acceptor = if config.https_bind_addr.is_some() {
            let server_config = build_server_tls_config(&config)?;
            Some(TlsAcceptor::from(server_config))
        } else {
            None
        };

        let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(
            config.max_concurrent_connections,
        ));

        Ok(Self {
            config: Arc::new(config),
            metrics: JudgeMetrics::new(),
            tls_acceptor,
            connection_semaphore,
        })
    }

    #[inline]
    pub fn metrics(&self) -> &Arc<JudgeMetrics> {
        &self.metrics
    }

    #[inline]
    pub fn config(&self) -> &JudgeConfig {
        &self.config
    }

    /// Run the server until cancellation token is triggered
    pub async fn run(&self, cancel_token: CancellationToken) -> Result<(), JudgeError> {
        let mut tasks = Vec::new();

        // 1. Spawn HTTP listener
        let http_listener = TcpListener::bind(self.config.http_bind_addr).await?;
        let config_http = Arc::clone(&self.config);
        let metrics_http = Arc::clone(&self.metrics);
        let token_http = cancel_token.clone();
        let sem_http = Arc::clone(&self.connection_semaphore);

        let http_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = token_http.cancelled() => break,
                    accept_res = http_listener.accept() => {
                        let (socket, peer_addr) = match accept_res {
                            Ok(res) => res,
                            Err(_) => {
                                // J6: Protect against 100% CPU spin on EMFILE / ENFILE
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                continue;
                            }
                        };

                        // Socket buffer tuning (8KB RX, 4KB TX) to reduce OS kernel RAM churn by ~80%
                        let sock_ref = socket2::SockRef::from(&socket);
                        let _ = sock_ref.set_recv_buffer_size(8192);
                        let _ = sock_ref.set_send_buffer_size(4096);

                        // J1: Enable TCP_NODELAY immediately to eliminate 40-200ms Nagle delays
                        let _ = socket.set_nodelay(true);

                        // Concurrency Semaphore Backpressure (DoS/OOM prevention)
                        let permit = match sem_http.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                // Concurrency limit exceeded: instantly reject with TCP RST (0 RAM, 0 CPU)
                                let _ = socket2::SockRef::from(&socket).set_linger(Some(Duration::ZERO));
                                drop(socket);
                                metrics_http.inc_blocked();
                                continue;
                            }
                        };

                        let cfg = Arc::clone(&config_http);
                        let m = Arc::clone(&metrics_http);

                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(ConnectionStream::Plain(socket), peer_addr, cfg, m).await;
                        });
                    }
                }
            }
        });
        tasks.push(http_task);

        // 2. Spawn HTTPS listener if configured
        if let (Some(https_addr), Some(tls_acceptor)) =
            (self.config.https_bind_addr, self.tls_acceptor.clone())
        {
            let https_listener = TcpListener::bind(https_addr).await?;
            let config_https = Arc::clone(&self.config);
            let metrics_https = Arc::clone(&self.metrics);
            let token_https = cancel_token.clone();
            let sem_https = Arc::clone(&self.connection_semaphore);

            let https_task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = token_https.cancelled() => break,
                        accept_res = https_listener.accept() => {
                            let (socket, peer_addr) = match accept_res {
                                Ok(res) => res,
                                Err(_) => {
                                    // J6: Protect against 100% CPU spin on EMFILE / ENFILE
                                    tokio::time::sleep(Duration::from_millis(10)).await;
                                    continue;
                                }
                            };

                            // Socket buffer tuning (8KB RX, 4KB TX)
                            let sock_ref = socket2::SockRef::from(&socket);
                            let _ = sock_ref.set_recv_buffer_size(8192);
                            let _ = sock_ref.set_send_buffer_size(4096);

                            // J1: Enable TCP_NODELAY immediately
                            let _ = socket.set_nodelay(true);

                            // Concurrency Semaphore Backpressure
                            let permit = match sem_https.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    let _ = socket2::SockRef::from(&socket).set_linger(Some(Duration::ZERO));
                                    drop(socket);
                                    metrics_https.inc_blocked();
                                    continue;
                                }
                            };

                            let acceptor = tls_acceptor.clone();
                            let cfg = Arc::clone(&config_https);
                            let m = Arc::clone(&metrics_https);

                            tokio::spawn(async move {
                                let _permit = permit;
                                // J5: Mitigate TLS Slowloris attack by enforcing handshake timeout
                                let accept_fut = acceptor.accept(socket);
                                match tokio::time::timeout(cfg.request_timeout, accept_fut).await {
                                    Ok(Ok(tls_stream)) => {
                                        handle_connection(ConnectionStream::Tls(Box::new(tls_stream)), peer_addr, cfg, m).await;
                                    }
                                    _ => {
                                        m.inc_blocked();
                                    }
                                }
                            });
                        }
                    }
                }
            });
            tasks.push(https_task);
        }

        // Wait for all listeners to finish on cancellation
        for task in tasks {
            let _ = task.await;
        }

        Ok(())
    }
}
