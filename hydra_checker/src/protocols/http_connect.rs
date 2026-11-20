use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ErrorReason;
use crate::models::ProxyAuth;
use crate::protocols::TunnelTarget;
use crate::transport::PrefixedStream;

/// Maximum bytes allowed for HTTP CONNECT response headers before failing
const MAX_CONNECT_HEADER_BYTES: usize = 1024;

/// Execute HTTP CONNECT tunneling handshake.
///
/// Iteratively reads until `\r\n\r\n` is encountered, parsing the status code
/// via `httparse`. Intermediate 1xx informational responses (such as `100 Continue`)
/// are safely advanced past until the final status code is received.
///
/// Any bytes read past `\r\n\r\n` for a successful 2xx response are strictly preserved
/// in a zero-overhead `PrefixedStream` for subsequent TLS or HTTP processing.
///
/// On status codes >= 400 (e.g. 407, 403, 502), the connection is immediately dropped
/// without attempting to read any response body.
pub async fn handshake_http_connect<S>(
    mut stream: S,
    target: &TunnelTarget,
    auth: Option<&ProxyAuth>,
) -> Result<PrefixedStream<S>, ErrorReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host_header = target.host_header();

    let mut req = format!(
        "CONNECT {host_header} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Proxy-Connection: close\r\n"
    );

    if let Some(auth) = auth {
        let credentials = format!("{}:{}", auth.username, auth.password);
        let encoded = BASE64.encode(credentials);
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&encoded);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|_| ErrorReason::HandshakeFailed)?;
    stream
        .flush()
        .await
        .map_err(|_| ErrorReason::HandshakeFailed)?;

    // Iterative read into stack buffer until `\r\n\r\n` (strictly delineated header drain)
    let mut buf = [0u8; MAX_CONNECT_HEADER_BYTES];
    let mut total_read = 0;

    let (headers_len, status_code) = loop {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);

        if total_read > 0 {
            match resp.parse(&buf[..total_read]) {
                Ok(httparse::Status::Complete(len)) => {
                    let status = resp.code.ok_or(ErrorReason::HandshakeFailed)?;
                    if (100..200).contains(&status) {
                        // Pattern A-3: Advance past intermediate 1xx informational response (e.g. 100 Continue)
                        buf.copy_within(len..total_read, 0);
                        total_read -= len;
                        continue;
                    }
                    break (len, status);
                }
                Ok(httparse::Status::Partial) => {
                    if total_read == MAX_CONNECT_HEADER_BYTES {
                        // Header too large / tarpit
                        return Err(ErrorReason::HandshakeFailed);
                    }
                }
                Err(_) => return Err(ErrorReason::HandshakeFailed),
            }
        }

        let n = stream
            .read(&mut buf[total_read..])
            .await
            .map_err(|_| ErrorReason::HandshakeFailed)?;

        if n == 0 {
            // Premature EOF before receiving full headers
            return Err(ErrorReason::HandshakeFailed);
        }

        total_read += n;
    };

    match status_code {
        200..=299 => {
            // Pattern A-3: Tunnel established successfully; strictly preserve any bytes beyond \r\n\r\n
            let leftover = if total_read > headers_len {
                buf[headers_len..total_read].to_vec()
            } else {
                Vec::new()
            };

            Ok(PrefixedStream::new(stream, leftover))
        }
        // Pattern A-4: Terminal CONNECT rejection & immediate socket drop without body drain
        407 => Err(ErrorReason::AuthRequired),
        _ => Err(ErrorReason::HandshakeFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_http_connect_100_continue_intermediate_pattern_a3() {
        let (client, mut server) = duplex(512);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await;
            // Send 100 Continue, then 200 OK, followed by extra TLS bytes
            server
                .write_all(
                    b"HTTP/1.1 100 Continue\r\n\r\n\
                      HTTP/1.1 200 Connection Established\r\n\r\n\
                      EXTRA_TLS_BYTES",
                )
                .await
                .unwrap();
        });

        let target = TunnelTarget::Addr(SocketAddr::from(([93, 184, 216, 34], 443)));
        let mut prefixed = handshake_http_connect(client, &target, None)
            .await
            .expect("HTTP CONNECT should succeed after 100 Continue");

        // Verify that the extra bytes beyond \r\n\r\n were safely preserved in PrefixedStream
        let mut leftover = [0u8; 15];
        prefixed.read_exact(&mut leftover).await.unwrap();
        assert_eq!(&leftover, b"EXTRA_TLS_BYTES");
    }

    #[tokio::test]
    async fn test_http_connect_407_auth_required_pattern_a4() {
        let (client, mut server) = duplex(512);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await;
            server
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")
                .await
                .unwrap();
        });

        let target = TunnelTarget::Addr(SocketAddr::from(([93, 184, 216, 34], 443)));
        let err = handshake_http_connect(client, &target, None).await.unwrap_err();
        assert_eq!(err, ErrorReason::AuthRequired);
    }

    #[tokio::test]
    async fn test_http_connect_403_drops_without_body_pattern_a4() {
        let (client, mut server) = duplex(512);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await;
            server
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 50\r\n\r\n")
                .await
                .unwrap();
        });

        let target = TunnelTarget::Addr(SocketAddr::from(([93, 184, 216, 34], 443)));
        let err = handshake_http_connect(client, &target, None).await.unwrap_err();
        assert_eq!(err, ErrorReason::HandshakeFailed);
    }
}
