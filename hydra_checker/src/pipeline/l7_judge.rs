use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use url::Url;

use crate::config::CheckerConfig;
use crate::error::ErrorReason;
use crate::judge::{JudgePayload, parse_judge_response};
use crate::models::ProxyAuth;
use crate::protocols::http_plain::build_plain_http_request;

/// Phase 3: L7 End-to-End Validation over TLS Tunnel
pub async fn execute_l7_judge_tls<S>(
    stream: S,
    tls_connector: &TlsConnector,
    judge_url: &Url,
    expected_token: Option<&str>,
    is_builtin: bool,
    config: &CheckerConfig,
    timeout: Duration,
) -> Result<JudgePayload, ErrorReason>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Retrieve cached pre-rendered request (C4: eliminates URL parse & template allocations)
    let (_effective_url, server_name_str, req_bytes) = config.get_judge_tls_request_for(judge_url, is_builtin, expected_token);
    let server_name = ServerName::try_from(server_name_str)
        .map_err(|_| ErrorReason::TlsHandshakeFailed)?;

    // Step 1: Perform TLS handshake over established tunnel
    let tls_stream = tokio::time::timeout(
        timeout,
        tls_connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| ErrorReason::TimeoutHandshake)?
    .map_err(|_| ErrorReason::TlsHandshakeFailed)?;

    // Step 2: Write request and read bounded response (C1, C7: Content-Length bounded, stack-allocated)
    send_and_verify_judge(tls_stream, &req_bytes, expected_token, is_builtin, config, timeout).await
}

/// Phase 3: L7 End-to-End Validation for Plain HTTP forward proxies
pub async fn execute_l7_judge_plain<S>(
    stream: S,
    judge_url: &Url,
    auth: Option<&ProxyAuth>,
    expected_token: Option<&str>,
    is_builtin: bool,
    config: &CheckerConfig,
    timeout: Duration,
) -> Result<JudgePayload, ErrorReason>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let effective_url = config.format_judge_url_for(judge_url, is_builtin);
    let token_to_send = if is_builtin {
        Some(config.active_judge_token())
    } else {
        expected_token.map(|t| compact_str::CompactString::new(t))
    };
    let req_bytes = build_plain_http_request(
        &effective_url,
        auth,
        token_to_send.as_ref().map(|s| s.as_str()),
    );
    send_and_verify_judge(stream, &req_bytes, expected_token, is_builtin, config, timeout).await
}

/// Common HTTP response reader with strict `max_read_bytes` limit, stack buffer (C7),
/// and Content-Length-driven completion (C1) preventing Keep-Alive hanging.
async fn send_and_verify_judge<S>(
    mut stream: S,
    req_bytes: &[u8],
    expected_token: Option<&str>,
    is_builtin: bool,
    config: &CheckerConfig,
    timeout: Duration,
) -> Result<JudgePayload, ErrorReason>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_read = config.max_read_bytes;

    tokio::time::timeout(timeout, async {
        // Write request
        stream
            .write_all(req_bytes)
            .await
            .map_err(|_| ErrorReason::TimeoutReadWrite)?;
        stream.flush().await.map_err(|_| ErrorReason::TimeoutReadWrite)?;

        // C7: Use stack buffer for normal responses (<= 4096 bytes) with zero heap churn
        let mut stack_buf = [0u8; 4096];
        let mut heap_buf: Option<Vec<u8>> = None;
        let mut total_read = 0;
        let mut expected_total: Option<usize> = None;

        loop {
            let max_allowed = max_read.saturating_add(1);

            let n = if let Some(ref mut h) = heap_buf {
                let current_len = h.len();
                if current_len >= max_allowed {
                    return Err(ErrorReason::ReadLimitExceeded);
                }
                let space = (max_allowed - current_len).min(2048);
                h.resize(current_len + space, 0);
                let n = stream
                    .read(&mut h[current_len..])
                    .await
                    .map_err(|_| ErrorReason::TimeoutReadWrite)?;
                h.truncate(current_len + n);
                n
            } else {
                if total_read >= 4096 {
                    if total_read >= max_allowed {
                        return Err(ErrorReason::ReadLimitExceeded);
                    }
                    let mut v = Vec::with_capacity(max_allowed.min(16384));
                    v.extend_from_slice(&stack_buf[..total_read]);
                    heap_buf = Some(v);
                    continue;
                }
                let space = (4096 - total_read).min(max_allowed - total_read);
                if space == 0 {
                    return Err(ErrorReason::ReadLimitExceeded);
                }
                let n = stream
                    .read(&mut stack_buf[total_read..total_read + space])
                    .await
                    .map_err(|_| ErrorReason::TimeoutReadWrite)?;
                total_read += n;
                n
            };

            if n == 0 {
                break;
            }

            let current_bytes = if let Some(ref h) = heap_buf {
                h.as_slice()
            } else {
                &stack_buf[..total_read]
            };

            if current_bytes.len() > max_read {
                return Err(ErrorReason::ReadLimitExceeded);
            }

            // C1: Extract Content-Length from headers to exit as soon as full payload is received
            if expected_total.is_none() {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut resp = httparse::Response::new(&mut headers);
                if let Ok(httparse::Status::Complete(header_len)) = resp.parse(current_bytes) {
                    for h in resp.headers.iter() {
                        if h.name.eq_ignore_ascii_case("content-length") {
                            if let Ok(val_str) = std::str::from_utf8(h.value) {
                                if let Ok(content_len) = val_str.trim().parse::<usize>() {
                                    expected_total = Some(header_len + content_len);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if let Some(expected) = expected_total {
                if current_bytes.len() >= expected {
                    break;
                }
            } else if current_bytes.ends_with(b"0\r\n\r\n") {
                // Chunked transfer termination
                break;
            }
        }

        let full_response = if let Some(ref h) = heap_buf {
            h.as_slice()
        } else {
            &stack_buf[..total_read]
        };

        if full_response.len() > max_read {
            return Err(ErrorReason::ReadLimitExceeded);
        }

        // Parse HTTP response headers
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);

        let header_len = match resp.parse(full_response) {
            Ok(httparse::Status::Complete(len)) => len,
            _ => return Err(ErrorReason::InvalidResponse),
        };

        if resp.code != Some(200) {
            return Err(ErrorReason::InvalidResponse);
        }

        // Verify body presence and token
        let body_bytes = &full_response[header_len..];
        let body_str = std::str::from_utf8(body_bytes).map_err(|_| ErrorReason::InvalidResponse)?;

        // Validates token (accounting for dynamic daily rotation and midnight drift for builtin, or explicit expected token)
        if is_builtin {
            if !config.is_token_matched(body_str) {
                return Err(ErrorReason::JudgeMismatch);
            }
        } else if let Some(token) = expected_token {
            if !body_str.contains(token) {
                return Err(ErrorReason::JudgeMismatch);
            }
        }

        // Parse exit IP and headers for anonymity
        let payload = parse_judge_response(body_str, config.real_ip)?;

        // Reject if exit IP is missing
        if payload.exit_ip.is_none() {
            return Err(ErrorReason::InvalidResponse);
        }

        // Reject if exit IP matches our real IP (transparent loop or proxy bypassed)
        if let Some(real_ip) = config.real_ip {
            if payload.exit_ip == Some(real_ip) {
                return Err(ErrorReason::JudgeMismatch);
            }
        }

        Ok(payload)
    })
    .await
    .map_err(|_| ErrorReason::TimeoutReadWrite)?
}