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
/// via `httparse`. Any bytes read past `\r\n\r\n` are safely preserved in a
/// zero-overhead `PrefixedStream` for subsequent TLS or HTTP processing.
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

    // Iterative read into stack buffer until `\r\n\r\n`
    let mut buf = [0u8; MAX_CONNECT_HEADER_BYTES];
    let mut total_read = 0;

    let (headers_len, status_code) = loop {
        let n = stream
            .read(&mut buf[total_read..])
            .await
            .map_err(|_| ErrorReason::HandshakeFailed)?;

        if n == 0 {
            // Premature EOF before receiving full headers
            return Err(ErrorReason::HandshakeFailed);
        }

        total_read += n;

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(&buf[..total_read]) {
            Ok(httparse::Status::Complete(len)) => {
                let status = resp.code.ok_or(ErrorReason::HandshakeFailed)?;
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
    };

    match status_code {
        200..=299 => {
            // Tunnel established successfully
            let leftover = if total_read > headers_len {
                buf[headers_len..total_read].to_vec()
            } else {
                Vec::new()
            };

            Ok(PrefixedStream::new(stream, leftover))
        }
        407 => Err(ErrorReason::AuthRequired),
        _ => Err(ErrorReason::HandshakeFailed),
    }
}
