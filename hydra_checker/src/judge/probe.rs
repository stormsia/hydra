use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use url::Url;

use super::endpoint::JudgeEndpoint;
use super::parse_judge_response;

/// Direct probe function to verify availability of a Judge endpoint
pub async fn probe_judge_endpoint(
    endpoint: &JudgeEndpoint,
    timeout: Duration,
    tls_connector: &TlsConnector,
) -> Result<u64, String> {
    // 1. Try HTTPS if available
    if endpoint.https_url.scheme() == "https" {
        match probe_single_url(
            &endpoint.https_url,
            endpoint.expected_token.as_deref(),
            timeout,
            Some(tls_connector),
        )
        .await
        {
            Ok(lat) => return Ok(lat),
            Err(e) => {
                // If HTTPS failed, fallback to probing HTTP endpoint if distinct
                if endpoint.http_url != endpoint.https_url {
                    return probe_single_url(
                        &endpoint.http_url,
                        endpoint.expected_token.as_deref(),
                        timeout,
                        None,
                    )
                    .await;
                }
                return Err(e);
            }
        }
    }

    // 2. Otherwise probe plain HTTP
    probe_single_url(
        &endpoint.http_url,
        endpoint.expected_token.as_deref(),
        timeout,
        None,
    )
    .await
}

async fn probe_single_url(
    url: &Url,
    expected_token: Option<&str>,
    timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> Result<u64, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "Missing host in judge URL".to_string())?;
    let is_https = url.scheme() == "https";
    let default_port = if is_https { 443 } else { 80 };
    let port = url.port().unwrap_or(default_port);

    let start = Instant::now();

    tokio::time::timeout(timeout, async {
        // Resolve host to socket address (avoid blocking by using spawn_blocking or to_socket_addrs)
        let host_for_resolve = host.to_string();
        let addrs = tokio::task::spawn_blocking(move || {
            (host_for_resolve.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
        })
        .await
        .map_err(|e| format!("DNS task join error: {e}"))?
        .map_err(|e| format!("DNS resolution failed for {host}:{port}: {e}"))?;

        let addr = addrs
            .into_iter()
            .next()
            .ok_or_else(|| format!("No IP found for {host}"))?;

        let tcp_stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("TCP connect failed to {addr}: {e}"))?;

        let path = url.path();
        let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
        let port_hdr = if port != default_port {
            format!(":{port}")
        } else {
            String::new()
        };

        let mut req_str = format!(
            "GET {path}{query} HTTP/1.1\r\n\
             Host: {host}{port_hdr}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HydraHealthCheck/1.0\r\n\
             Connection: close\r\n"
        );

        if let Some(token) = expected_token {
            req_str.push_str(&format!("X-Hydra-Token: {token}\r\n"));
        }
        req_str.push_str("\r\n");
        let req_bytes = req_str.into_bytes();

        let mut resp_buf = [0u8; 8192];
        let mut total_read = 0;

        if is_https {
            let connector =
                tls_connector.ok_or_else(|| "Missing TLS connector for HTTPS probe".to_string())?;
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| format!("Invalid server name: {e}"))?;
            let mut tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| format!("TLS handshake failed: {e}"))?;

            tls_stream
                .write_all(&req_bytes)
                .await
                .map_err(|e| format!("Write failed: {e}"))?;
            tls_stream
                .flush()
                .await
                .map_err(|e| format!("Flush failed: {e}"))?;

            while total_read < resp_buf.len() {
                let n = tls_stream
                    .read(&mut resp_buf[total_read..])
                    .await
                    .map_err(|e| format!("Read failed: {e}"))?;
                if n == 0 {
                    break;
                }
                total_read += n;
            }
        } else {
            let mut stream = tcp_stream;
            stream
                .write_all(&req_bytes)
                .await
                .map_err(|e| format!("Write failed: {e}"))?;
            stream
                .flush()
                .await
                .map_err(|e| format!("Flush failed: {e}"))?;

            while total_read < resp_buf.len() {
                let n = stream
                    .read(&mut resp_buf[total_read..])
                    .await
                    .map_err(|e| format!("Read failed: {e}"))?;
                if n == 0 {
                    break;
                }
                total_read += n;
            }
        }

        if total_read == 0 {
            return Err("Empty response from judge".to_string());
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        let header_len = match resp.parse(&resp_buf[..total_read]) {
            Ok(httparse::Status::Complete(len)) => len,
            Ok(httparse::Status::Partial) => {
                return Err("Partial HTTP response from judge".to_string());
            }
            Err(e) => return Err(format!("HTTP parse error: {e}")),
        };

        let status_code = resp.code.unwrap_or(0);
        if status_code != 200 {
            return Err(format!("Judge returned non-200 HTTP status: {status_code}"));
        }

        let body_str = std::str::from_utf8(&resp_buf[header_len..total_read])
            .map_err(|e| format!("Invalid UTF-8 body: {e}"))?;

        if let Some(token) = expected_token {
            if !body_str.contains(token) {
                return Err("Response does not contain expected token".to_string());
            }
        } else {
            let payload = parse_judge_response(body_str, None)
                .map_err(|e| format!("Failed to parse judge payload: {e:?}"))?;
            if payload.exit_ip.is_none() {
                return Err("Judge payload does not contain an exit IP".to_string());
            }
        }

        Ok(start.elapsed().as_millis() as u64)
    })
    .await
    .map_err(|_| "Judge probe timed out".to_string())?
}
