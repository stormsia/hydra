use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::config::{JudgeConfig, ResponseFormat, UnauthorizedAction};
use crate::formatters::build_echo_response;
use crate::metrics::JudgeMetrics;
use crate::server::security::is_authorized;

/// Concrete transport stream: Plain TCP or TLS-wrapped TCP
pub enum ConnectionStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl ConnectionStream {
    /// For unauthorized or malicious probes: set SO_LINGER=0 to immediately emit TCP RST upon drop,
    /// releasing OS resources without staying in TIME_WAIT / FIN_WAIT.
    pub fn abort_with_rst(&self) {
        match self {
            Self::Plain(tcp) => {
                let _ = socket2::SockRef::from(tcp).set_linger(Some(std::time::Duration::ZERO));
            }
            Self::Tls(tls) => {
                let (tcp, _) = tls.get_ref();
                let _ = socket2::SockRef::from(tcp).set_linger(Some(std::time::Duration::ZERO));
            }
        }
    }
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Handle a single incoming HTTP or HTTPS client connection
pub async fn handle_connection(
    mut stream: ConnectionStream,
    peer_addr: SocketAddr,
    config: Arc<JudgeConfig>,
    metrics: Arc<JudgeMetrics>,
) {
    metrics.inc_total();

    let res = tokio::time::timeout(
        config.request_timeout,
        process_request(&mut stream, peer_addr, &config, &metrics),
    )
    .await;

    metrics.dec_active();

    match res {
        Ok(Ok(())) => {
            // Orderly shutdown to avoid TIME_WAIT socket accumulation on Judge:
            // Judge sends 'Connection: close'. Compliant clients/checkers close immediately upon reading response.
            // A brief timed read gives the client up to 20ms to send FIN first:
            // when client sends FIN first, client enters TIME_WAIT and Judge transitions directly to CLOSED (0 TIME_WAIT).
            let mut eof_buf = [0u8; 1];
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(20),
                stream.read(&mut eof_buf),
            )
            .await;
            let _ = stream.shutdown().await;
        }
        Ok(Err(())) | Err(_) => {
            // Dropped due to unauthorized access or timeout: send TCP RST (0 TIME_WAIT)
            stream.abort_with_rst();
        }
    }
}

async fn process_request(
    stream: &mut ConnectionStream,
    peer_addr: SocketAddr,
    config: &JudgeConfig,
    metrics: &JudgeMetrics,
) -> Result<(), ()> {
    // 1. Read request headers into stack buffer
    let mut buf = [0u8; 4096];
    let mut total_read = 0;

    let headers_len = loop {
        let n = stream.read(&mut buf[total_read..]).await.map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        total_read += n;

        if buf[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
            break total_read;
        }

        if total_read >= config.max_request_bytes {
            // Request headers exceeded limit
            metrics.inc_blocked();
            return Err(());
        }
    };

    // 2. Parse request line and headers via zero-copy httparse
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    if req.parse(&buf[..headers_len]).map_err(|_| ())?.is_partial() {
        return Err(());
    }

    let path_and_query = req.path.unwrap_or("/");

    // Collect headers as (&str, &str)
    let mut parsed_headers: Vec<(&str, &str)> = Vec::with_capacity(32);
    for h in req.headers.iter() {
        if let Ok(val) = std::str::from_utf8(h.value) {
            parsed_headers.push((h.name, val));
        }
    }

    // 3. Security Token Guard: Check authorization with dynamic token rotation
    let authorized = is_authorized(path_and_query, &parsed_headers, &config.token_provider);

    if !authorized {
        metrics.inc_blocked();
        return match config.unauthorized_action {
            UnauthorizedAction::DropRst => {
                // Drop connection instantly with TCP RST
                stream.abort_with_rst();
                Err(())
            }
            UnauthorizedAction::Http403 => {
                let resp = b"HTTP/1.1 403 Forbidden\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\
                             \r\n";
                let _ = stream.write_all(resp).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                Err(())
            }
        };
    }

    // 4. Extract real L3/L4 TCP Peer IP (normalize IPv4-mapped IPv6)
    let peer_ip = match peer_addr.ip() {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
    };

    // 5. Determine response format (Query parameter ?format= or Accept header)
    let format = if path_and_query.contains("format=json") {
        ResponseFormat::Json
    } else if path_and_query.contains("format=azenv") {
        ResponseFormat::Azenv
    } else if parsed_headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("accept") && v.contains("application/json"))
    {
        ResponseFormat::Json
    } else {
        config.default_format
    };

    // 6. Build reflected echo response body with today's active token
    let active_token = config.active_token();
    let (body, content_type) = build_echo_response(
        peer_ip,
        &parsed_headers,
        active_token.as_str(),
        format,
    );

    let body_bytes = body.as_bytes();
    let resp_header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Server: HydraJudge/1.0\r\n\
         \r\n",
        body_bytes.len()
    );

    // 7. Single write syscall combining header + body (J2 optimization)
    let mut full_resp = Vec::with_capacity(resp_header.len() + body_bytes.len());
    full_resp.extend_from_slice(resp_header.as_bytes());
    full_resp.extend_from_slice(body_bytes);

    stream.write_all(&full_resp).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())?;

    metrics.inc_authorized(body_bytes.len());

    Ok(())
}