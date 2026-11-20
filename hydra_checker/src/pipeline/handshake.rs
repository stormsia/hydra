use compact_str::CompactString;
use std::time::{Duration, Instant};
use tokio_rustls::TlsConnector;

use crate::config::CheckerConfig;
use crate::error::ErrorReason;
use crate::judge::{JudgeEndpoint, JudgePayload};
use crate::models::{CheckTarget, ProxyProtocol};
use crate::pipeline::l7_judge::{execute_l7_judge_plain, execute_l7_judge_tls};
use crate::protocols::TunnelTarget;
use crate::protocols::http_connect::handshake_http_connect;
use crate::protocols::socks4::handshake_socks4;
use crate::protocols::socks5::handshake_socks5;
use crate::transport::Dialer;

pub struct HandshakeSuccess {
    pub detected_protocol: ProxyProtocol,
    pub supports_https: bool,
    pub judge_payload: JudgePayload,
    pub handshake_rtt_ms: u64,
}

/// Phase 2: Execute explicit protocol handshake or Auto-Detect cascade with Judge selection & Fallback
pub async fn execute_handshake_cascade<D: Dialer>(
    dialer: &D,
    stream: D::Stream,
    target: &CheckTarget,
    config: &CheckerConfig,
    tls_connector: &TlsConnector,
) -> Result<HandshakeSuccess, ErrorReason> {
    // 1. Resolve Primary Judge
    let override_opt = target.config_override.as_ref();
    let has_override = override_opt.is_some_and(|o| {
        o.judge_https_url.is_some()
            || o.judge_http_url.is_some()
            || o.judge_expected_token.is_some()
    });

    let primary_judge = if has_override {
        let override_https = override_opt
            .and_then(|o| o.judge_https_url.clone())
            .unwrap_or_else(|| config.judge_https_url.clone());
        let override_http = override_opt
            .and_then(|o| o.judge_http_url.clone())
            .unwrap_or_else(|| config.judge_http_url.clone());
        let override_token = override_opt.and_then(|o| o.judge_expected_token.clone());

        JudgeEndpoint {
            id: CompactString::new("override"),
            name: CompactString::new("Override Judge"),
            http_url: override_http,
            https_url: override_https,
            expected_token: override_token,
            is_builtin: false,
            priority: 0,
            supports_anonymity: true,
            enabled: true,
        }
    } else {
        match config.judge_pool.select_judge() {
            Some(j) => j,
            None => return Err(ErrorReason::InternalError),
        }
    };

    // 2. Primary cascade attempt
    match run_cascade_attempt(
        dialer,
        Some(stream),
        target,
        config,
        tls_connector,
        &primary_judge,
    )
    .await
    {
        Ok(success) => {
            config
                .judge_pool
                .record_success(primary_judge.id.as_str(), success.handshake_rtt_ms, None);
            Ok(success)
        }
        Err(err) => {
            // Check if fallback to secondary judge is warranted
            let is_judge_error = matches!(
                err,
                ErrorReason::JudgeMismatch
                    | ErrorReason::InvalidResponse
                    | ErrorReason::TimeoutReadWrite
            );

            if is_judge_error && !has_override {
                let fallbacks = config.judge_pool.fallback_judges(&primary_judge.id);

                if let Some(fallback_judge) = fallbacks.first() {
                    let connect_timeout = target
                        .config_override
                        .as_ref()
                        .and_then(|o| o.connect_timeout)
                        .unwrap_or(config.connect_timeout);

                    if let Ok(fresh_stream) = dialer
                        .connect(&target.host, target.port, connect_timeout, config)
                        .await
                        && let Ok(fb_success) = run_cascade_attempt(
                            dialer,
                            Some(fresh_stream),
                            target,
                            config,
                            tls_connector,
                            fallback_judge,
                        )
                        .await
                    {
                        config.judge_pool.record_success(
                            fallback_judge.id.as_str(),
                            fb_success.handshake_rtt_ms,
                            None,
                        );
                        return Ok(fb_success);
                    }
                }
            }

            Err(err)
        }
    }
}

async fn execute_judge_for_stream<S>(
    stream: S,
    judge: &JudgeEndpoint,
    tls_connector: &TlsConnector,
    config: &CheckerConfig,
    read_write_timeout: Duration,
    auth: Option<&crate::models::ProxyAuth>,
) -> Result<(JudgePayload, bool), ErrorReason>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if judge.https_url.scheme() == "https" {
        let payload = execute_l7_judge_tls(
            stream,
            tls_connector,
            &judge.https_url,
            judge.expected_token.as_deref(),
            judge.is_builtin,
            config,
            read_write_timeout,
        )
        .await?;
        Ok((payload, true))
    } else {
        let payload = execute_l7_judge_plain(
            stream,
            &judge.http_url,
            auth,
            judge.expected_token.as_deref(),
            judge.is_builtin,
            config,
            read_write_timeout,
        )
        .await?;
        Ok((payload, false))
    }
}

async fn run_cascade_attempt<D: Dialer>(
    dialer: &D,
    mut initial_stream: Option<D::Stream>,
    target: &CheckTarget,
    config: &CheckerConfig,
    tls_connector: &TlsConnector,
    judge: &JudgeEndpoint,
) -> Result<HandshakeSuccess, ErrorReason> {
    let connect_timeout = target
        .config_override
        .as_ref()
        .and_then(|o| o.connect_timeout)
        .unwrap_or(config.connect_timeout);

    let handshake_timeout = target
        .config_override
        .as_ref()
        .and_then(|o| o.handshake_timeout)
        .unwrap_or(config.handshake_timeout);

    let read_write_timeout = target
        .config_override
        .as_ref()
        .and_then(|o| o.read_write_timeout)
        .unwrap_or(config.read_write_timeout);

    let target_judge_url = if judge.https_url.scheme() == "https" {
        &judge.https_url
    } else {
        &judge.http_url
    };
    let judge_addr = if judge.is_builtin {
        if judge.https_url.scheme() == "https" {
            config.judge_https_addr
        } else {
            config.judge_http_addr
        }
    } else {
        None
    };
    let tunnel_target =
        TunnelTarget::from_url(target_judge_url, judge_addr).ok_or(ErrorReason::InternalError)?;

    // Mode A: Explicit Protocol Specified
    if let Some(protocol) = target.expected_protocol {
        let mut stream = match initial_stream.take() {
            Some(s) => s,
            None => {
                dialer
                    .connect(&target.host, target.port, connect_timeout, config)
                    .await?
            }
        };

        return match protocol {
            ProxyProtocol::Socks5 => {
                let start_hs = Instant::now();
                tokio::time::timeout(
                    handshake_timeout,
                    handshake_socks5(&mut stream, &tunnel_target, target.auth.as_ref()),
                )
                .await
                .map_err(|_| ErrorReason::TimeoutHandshake)??;
                let elapsed = start_hs.elapsed();
                if elapsed > handshake_timeout {
                    return Err(ErrorReason::TimeoutHandshake);
                }
                let hs_rtt = elapsed.as_millis() as u64;

                let (judge_payload, supports_https) = execute_judge_for_stream(
                    stream,
                    judge,
                    tls_connector,
                    config,
                    read_write_timeout,
                    target.auth.as_ref(),
                )
                .await?;

                Ok(HandshakeSuccess {
                    detected_protocol: ProxyProtocol::Socks5,
                    supports_https,
                    judge_payload,
                    handshake_rtt_ms: hs_rtt,
                })
            }
            ProxyProtocol::Socks4 | ProxyProtocol::Socks4a => {
                let start_hs = Instant::now();
                tokio::time::timeout(
                    handshake_timeout,
                    handshake_socks4(&mut stream, &tunnel_target, target.auth.as_ref()),
                )
                .await
                .map_err(|_| ErrorReason::TimeoutHandshake)??;
                let elapsed = start_hs.elapsed();
                if elapsed > handshake_timeout {
                    return Err(ErrorReason::TimeoutHandshake);
                }
                let hs_rtt = elapsed.as_millis() as u64;

                let (judge_payload, supports_https) = execute_judge_for_stream(
                    stream,
                    judge,
                    tls_connector,
                    config,
                    read_write_timeout,
                    target.auth.as_ref(),
                )
                .await?;

                Ok(HandshakeSuccess {
                    detected_protocol: protocol,
                    supports_https,
                    judge_payload,
                    handshake_rtt_ms: hs_rtt,
                })
            }
            ProxyProtocol::Https => {
                let start_hs = Instant::now();
                let prefixed = tokio::time::timeout(
                    handshake_timeout,
                    handshake_http_connect(stream, &tunnel_target, target.auth.as_ref()),
                )
                .await
                .map_err(|_| ErrorReason::TimeoutHandshake)??;
                let elapsed = start_hs.elapsed();
                if elapsed > handshake_timeout {
                    return Err(ErrorReason::TimeoutHandshake);
                }
                let hs_rtt = elapsed.as_millis() as u64;

                let judge_payload = execute_l7_judge_tls(
                    prefixed,
                    tls_connector,
                    &judge.https_url,
                    judge.expected_token.as_deref(),
                    judge.is_builtin,
                    config,
                    read_write_timeout,
                )
                .await?;

                Ok(HandshakeSuccess {
                    detected_protocol: ProxyProtocol::Https,
                    supports_https: true,
                    judge_payload,
                    handshake_rtt_ms: hs_rtt,
                })
            }
            ProxyProtocol::Http => {
                // If judge has HTTPS, try HTTP CONNECT first to verify HTTPS capability
                if judge.https_url.scheme() == "https" {
                    let start_hs = Instant::now();
                    let connect_res = tokio::time::timeout(
                        handshake_timeout,
                        handshake_http_connect(stream, &tunnel_target, target.auth.as_ref()),
                    )
                    .await;

                    if let Ok(Ok(prefixed_stream)) = connect_res {
                        let elapsed = start_hs.elapsed();
                        if elapsed <= handshake_timeout {
                            let hs_rtt = elapsed.as_millis() as u64;
                            if let Ok(judge_payload) = execute_l7_judge_tls(
                                prefixed_stream,
                                tls_connector,
                                &judge.https_url,
                                judge.expected_token.as_deref(),
                                judge.is_builtin,
                                config,
                                read_write_timeout,
                            )
                            .await
                            {
                                return Ok(HandshakeSuccess {
                                    detected_protocol: ProxyProtocol::Http,
                                    supports_https: true,
                                    judge_payload,
                                    handshake_rtt_ms: hs_rtt,
                                });
                            }
                        }
                    }

                    // CONNECT or TLS failed, fallback to fresh connection for plain HTTP check
                    let fresh_stream = dialer
                        .connect(&target.host, target.port, connect_timeout, config)
                        .await?;
                    let judge_payload = execute_l7_judge_plain(
                        fresh_stream,
                        &judge.http_url,
                        target.auth.as_ref(),
                        judge.expected_token.as_deref(),
                        judge.is_builtin,
                        config,
                        read_write_timeout,
                    )
                    .await?;

                    Ok(HandshakeSuccess {
                        detected_protocol: ProxyProtocol::Http,
                        supports_https: false,
                        judge_payload,
                        handshake_rtt_ms: 0,
                    })
                } else {
                    let judge_payload = execute_l7_judge_plain(
                        stream,
                        &judge.http_url,
                        target.auth.as_ref(),
                        judge.expected_token.as_deref(),
                        judge.is_builtin,
                        config,
                        read_write_timeout,
                    )
                    .await?;

                    Ok(HandshakeSuccess {
                        detected_protocol: ProxyProtocol::Http,
                        supports_https: false,
                        judge_payload,
                        handshake_rtt_ms: 0,
                    })
                }
            }
        };
    }

    // Mode B: Auto-Detect Cascade (SOCKS5 -> SOCKS4 -> HTTP CONNECT -> HTTP Plain)
    // 1. Candidate 1: SOCKS5 (using initial stream)
    let mut stream = match initial_stream.take() {
        Some(s) => s,
        None => {
            dialer
                .connect(&target.host, target.port, connect_timeout, config)
                .await?
        }
    };

    let start_hs = Instant::now();
    let socks5_result = tokio::time::timeout(
        handshake_timeout,
        handshake_socks5(&mut stream, &tunnel_target, target.auth.as_ref()),
    )
    .await;

    match socks5_result {
        Ok(Ok(())) => {
            let elapsed = start_hs.elapsed();
            if elapsed > handshake_timeout {
                return Err(ErrorReason::TimeoutHandshake);
            }
            let hs_rtt = elapsed.as_millis() as u64;
            if let Ok((judge_payload, supports_https)) = execute_judge_for_stream(
                stream,
                judge,
                tls_connector,
                config,
                read_write_timeout,
                target.auth.as_ref(),
            )
            .await
            {
                return Ok(HandshakeSuccess {
                    detected_protocol: ProxyProtocol::Socks5,
                    supports_https,
                    judge_payload,
                    handshake_rtt_ms: hs_rtt,
                });
            }
        }
        // Anti-Tarpit: If SOCKS5 handshake timed out or proxy explicitly demands auth, fail fast!
        Err(_) => return Err(ErrorReason::TimeoutHandshake),
        Ok(Err(ErrorReason::AuthRequired)) => return Err(ErrorReason::AuthRequired),
        // Signature mismatch / rejected -> drop stream (sends TCP RST) & continue cascade
        Ok(Err(_)) => drop(stream),
    }

    // 2. Candidate 2: SOCKS4 / SOCKS4a (fresh L4 connection)
    let mut stream = dialer
        .connect(&target.host, target.port, connect_timeout, config)
        .await?;

    let start_hs = Instant::now();
    let socks4_result = tokio::time::timeout(
        handshake_timeout,
        handshake_socks4(&mut stream, &tunnel_target, target.auth.as_ref()),
    )
    .await;

    match socks4_result {
        Ok(Ok(())) => {
            let elapsed = start_hs.elapsed();
            if elapsed > handshake_timeout {
                return Err(ErrorReason::TimeoutHandshake);
            }
            let hs_rtt = elapsed.as_millis() as u64;
            if let Ok((judge_payload, supports_https)) = execute_judge_for_stream(
                stream,
                judge,
                tls_connector,
                config,
                read_write_timeout,
                target.auth.as_ref(),
            )
            .await
            {
                return Ok(HandshakeSuccess {
                    detected_protocol: ProxyProtocol::Socks4,
                    supports_https,
                    judge_payload,
                    handshake_rtt_ms: hs_rtt,
                });
            }
        }
        Err(_) => return Err(ErrorReason::TimeoutHandshake),
        Ok(Err(ErrorReason::AuthRequired)) => return Err(ErrorReason::AuthRequired),
        Ok(Err(_)) => drop(stream),
    }

    // 3. Candidate 3: HTTP CONNECT (fresh L4 connection)
    let stream = dialer
        .connect(&target.host, target.port, connect_timeout, config)
        .await?;

    let start_hs = Instant::now();
    let connect_result = tokio::time::timeout(
        handshake_timeout,
        handshake_http_connect(stream, &tunnel_target, target.auth.as_ref()),
    )
    .await;

    match connect_result {
        Ok(Ok(prefixed_stream)) => {
            let elapsed = start_hs.elapsed();
            if elapsed > handshake_timeout {
                return Err(ErrorReason::TimeoutHandshake);
            }
            let hs_rtt = elapsed.as_millis() as u64;
            if let Ok(judge_payload) = execute_l7_judge_tls(
                prefixed_stream,
                tls_connector,
                &judge.https_url,
                judge.expected_token.as_deref(),
                judge.is_builtin,
                config,
                read_write_timeout,
            )
            .await
            {
                return Ok(HandshakeSuccess {
                    detected_protocol: ProxyProtocol::Https,
                    supports_https: true,
                    judge_payload,
                    handshake_rtt_ms: hs_rtt,
                });
            }
        }
        Err(_) => return Err(ErrorReason::TimeoutHandshake),
        Ok(Err(ErrorReason::AuthRequired)) => return Err(ErrorReason::AuthRequired),
        Ok(Err(_)) => {}
    }

    // 4. Candidate 4: Fallback to HTTP Plain (fresh L4 connection)
    let stream = dialer
        .connect(&target.host, target.port, connect_timeout, config)
        .await?;

    let plain_result = execute_l7_judge_plain(
        stream,
        &judge.http_url,
        target.auth.as_ref(),
        judge.expected_token.as_deref(),
        judge.is_builtin,
        config,
        read_write_timeout,
    )
    .await;

    match plain_result {
        Ok(judge_payload) => Ok(HandshakeSuccess {
            detected_protocol: ProxyProtocol::Http,
            supports_https: false,
            judge_payload,
            handshake_rtt_ms: 0,
        }),
        Err(_) => Err(ErrorReason::HandshakeFailed),
    }
}
