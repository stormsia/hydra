use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ErrorReason;
use crate::models::ProxyAuth;
use crate::protocols::TunnelTarget;

/// Strictly typed error enum for SOCKS5 handshake outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Error {
    /// Remote server returned an HTTP response (starts with "HTTP/" or "HT")
    HttpDetected,
    /// Protocol handshake failed or transport error before SOCKS5 confirmation
    HandshakeFailed,
    /// Proxy authentication required (0xFF or auth subnegotiation rejected)
    AuthRequired,
    /// SOCKS5 protocol confirmed (greeting accepted and CONNECT header[0] == 0x05),
    /// but CONNECT command rejected by proxy with non-zero REP (header[1] != 0x00).
    ConnectRejected {
        rep: u8,
        reason: ErrorReason,
    },
}

impl From<Socks5Error> for ErrorReason {
    fn from(err: Socks5Error) -> Self {
        match err {
            Socks5Error::HttpDetected => ErrorReason::HttpDetected,
            Socks5Error::HandshakeFailed => ErrorReason::HandshakeFailed,
            Socks5Error::AuthRequired => ErrorReason::AuthRequired,
            Socks5Error::ConnectRejected { reason, .. } => reason,
        }
    }
}

/// Execute SOCKS5 handshake (RFC 1928) and User/Pass Authentication (RFC 1929).
pub async fn handshake_socks5<S>(
    stream: &mut S,
    target: &TunnelTarget,
    auth: Option<&ProxyAuth>,
) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Greeting
    if auth.is_some() {
        // Offer NO AUTH (0x00) and USER/PASS (0x02)
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|_| Socks5Error::HandshakeFailed)?;
    } else {
        // Offer NO AUTH (0x00)
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|_| Socks5Error::HandshakeFailed)?;
    }
    stream
        .flush()
        .await
        .map_err(|_| Socks5Error::HandshakeFailed)?;

    // Step 2: Read method selection
    let mut method_resp = [0u8; 2];
    stream
        .read_exact(&mut method_resp)
        .await
        .map_err(|_| Socks5Error::HandshakeFailed)?;

    // Pattern A-1: Cross-Protocol Leap (SOCKS5 -> HTTP)
    // Detect if remote web/proxy server responded with HTTP status (e.g. "HTTP/1.1 400 Bad Request")
    if method_resp[0].eq_ignore_ascii_case(&b'H') && method_resp[1].eq_ignore_ascii_case(&b'T') {
        let mut rest = [0u8; 3];
        if let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_millis(200),
            stream.read_exact(&mut rest),
        )
        .await
            && rest.eq_ignore_ascii_case(b"TP/")
        {
            return Err(Socks5Error::HttpDetected);
        }
        return Err(Socks5Error::HttpDetected);
    }

    if method_resp[0] != 0x05 {
        return Err(Socks5Error::HandshakeFailed);
    }

    match method_resp[1] {
        0x00 => {
            // No auth required
        }
        0x02 => {
            // Username/Password authentication requested
            let auth = auth.ok_or(Socks5Error::AuthRequired)?;
            let u_bytes = auth.username.as_bytes();
            let p_bytes = auth.password.as_bytes();

            if u_bytes.len() > 255 || p_bytes.len() > 255 {
                return Err(Socks5Error::HandshakeFailed);
            }

            let mut req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
            req.push(0x01); // Auth subnegotiation version
            req.push(u_bytes.len() as u8);
            req.extend_from_slice(u_bytes);
            req.push(p_bytes.len() as u8);
            req.extend_from_slice(p_bytes);

            stream
                .write_all(&req)
                .await
                .map_err(|_| Socks5Error::HandshakeFailed)?;
            stream
                .flush()
                .await
                .map_err(|_| Socks5Error::HandshakeFailed)?;

            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .await
                .map_err(|_| Socks5Error::HandshakeFailed)?;

            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                return Err(Socks5Error::AuthRequired);
            }
        }
        0xFF => return Err(Socks5Error::AuthRequired),
        _ => return Err(Socks5Error::HandshakeFailed),
    }

    // Step 3: Send CONNECT request
    let mut connect_req = [0u8; 512];
    connect_req[0] = 0x05; // Version
    connect_req[1] = 0x01; // CMD: CONNECT
    connect_req[2] = 0x00; // Reserved

    let len = match target {
        TunnelTarget::Addr(addr) => match addr.ip() {
            IpAddr::V4(v4) => {
                connect_req[3] = 0x01; // ATYP: IPv4
                connect_req[4..8].copy_from_slice(&v4.octets());
                connect_req[8..10].copy_from_slice(&addr.port().to_be_bytes());
                10
            }
            IpAddr::V6(v6) => {
                connect_req[3] = 0x04; // ATYP: IPv6
                connect_req[4..20].copy_from_slice(&v6.octets());
                connect_req[20..22].copy_from_slice(&addr.port().to_be_bytes());
                22
            }
        },
        TunnelTarget::Domain(domain, port) => {
            let d_bytes = domain.as_bytes();
            if d_bytes.len() > 255 {
                return Err(Socks5Error::HandshakeFailed);
            }
            connect_req[3] = 0x03; // ATYP: Domain name
            connect_req[4] = d_bytes.len() as u8;
            connect_req[5..5 + d_bytes.len()].copy_from_slice(d_bytes);
            let port_offset = 5 + d_bytes.len();
            connect_req[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
            port_offset + 2
        }
    };

    stream
        .write_all(&connect_req[..len])
        .await
        .map_err(|_| Socks5Error::HandshakeFailed)?;
    stream
        .flush()
        .await
        .map_err(|_| Socks5Error::HandshakeFailed)?;

    // Step 4: Read CONNECT response header
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| Socks5Error::HandshakeFailed)?;

    if header[0] != 0x05 {
        return Err(Socks5Error::HandshakeFailed);
    }

    if header[1] != 0x00 {
        // Pattern A-2: SOCKS5 Protocol Lock-in
        let reason = match header[1] {
            0x05 => ErrorReason::ConnRefused,
            0x03 | 0x04 => ErrorReason::NetworkUnreachable,
            _ => ErrorReason::HandshakeFailed,
        };
        return Err(Socks5Error::ConnectRejected {
            rep: header[1],
            reason,
        });
    }

    // Step 5: Read and discard bound address/port to leave stream clean
    match header[3] {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut discard = [0u8; 6];
            stream
                .read_exact(&mut discard)
                .await
                .map_err(|_| Socks5Error::HandshakeFailed)?;
        }
        0x03 => {
            // Domain: 1 byte len, then len bytes, then 2 bytes port
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|_| Socks5Error::HandshakeFailed)?;
            let d_len = len_buf[0] as usize;
            // Use stack buffer instead of heap vec (max domain length is 255 + 2 bytes port = 257)
            let mut discard = [0u8; 257];
            stream
                .read_exact(&mut discard[..d_len + 2])
                .await
                .map_err(|_| Socks5Error::HandshakeFailed)?;
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut discard = [0u8; 18];
            stream
                .read_exact(&mut discard)
                .await
                .map_err(|_| Socks5Error::HandshakeFailed)?;
        }
        _ => return Err(Socks5Error::HandshakeFailed),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_socks5_http_detected_pattern_a1() {
        let (mut client, mut server) = duplex(512);
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let _ = server.read(&mut buf).await;
            // Server responds with HTTP 400 Bad Request
            server
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let target = TunnelTarget::Addr(SocketAddr::from(([93, 184, 216, 34], 80)));
        let err = handshake_socks5(&mut client, &target, None).await.unwrap_err();
        assert_eq!(err, Socks5Error::HttpDetected);
    }

    #[tokio::test]
    async fn test_socks5_connect_rejected_pattern_a2() {
        let (mut client, mut server) = duplex(512);
        tokio::spawn(async move {
            // 1. Read greeting [0x05, 0x01, 0x00]
            let mut greet = [0u8; 3];
            server.read_exact(&mut greet).await.unwrap();
            // Respond with NO AUTH
            server.write_all(&[0x05, 0x00]).await.unwrap();

            // 2. Read CONNECT request (10 bytes for IPv4)
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            // Respond with REP = 0x03 (Network Unreachable)
            server
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let target = TunnelTarget::Addr(SocketAddr::from(([93, 184, 216, 34], 80)));
        let err = handshake_socks5(&mut client, &target, None).await.unwrap_err();
        assert_eq!(
            err,
            Socks5Error::ConnectRejected {
                rep: 0x03,
                reason: ErrorReason::NetworkUnreachable
            }
        );
    }

    #[tokio::test]
    async fn test_socks5_auth_required() {
        let (mut client, mut server) = duplex(512);
        tokio::spawn(async move {
            let mut greet = [0u8; 3];
            server.read_exact(&mut greet).await.unwrap();
            // Respond with 0xFF (No acceptable methods)
            server.write_all(&[0x05, 0xFF]).await.unwrap();
        });

        let target = TunnelTarget::Addr(SocketAddr::from(([93, 184, 216, 34], 80)));
        let err = handshake_socks5(&mut client, &target, None).await.unwrap_err();
        assert_eq!(err, Socks5Error::AuthRequired);
    }
}
