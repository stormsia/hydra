use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ErrorReason;
use crate::models::ProxyAuth;
use crate::protocols::TunnelTarget;

/// Execute SOCKS4 (IPv4) or SOCKS4a (Domain name) handshake.
pub async fn handshake_socks4<S>(
    stream: &mut S,
    target: &TunnelTarget,
    auth: Option<&ProxyAuth>,
) -> Result<(), ErrorReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let userid = auth
        .map(|a| a.username.as_bytes())
        .unwrap_or(b"hydra");

    // Zero-allocation stack buffer for SOCKS4/SOCKS4a handshake request
    let mut stack_buf = [0u8; 128];
    let mut len = 0;

    stack_buf[0] = 0x04; // VN: 4
    stack_buf[1] = 0x01; // CD: CONNECT (1)
    len += 2;

    let packet_bytes: &[u8] = match target {
        TunnelTarget::Addr(addr) => match addr.ip() {
            IpAddr::V4(v4) => {
                stack_buf[len..len + 2].copy_from_slice(&addr.port().to_be_bytes());
                len += 2;
                stack_buf[len..len + 4].copy_from_slice(&v4.octets());
                len += 4;
                stack_buf[len..len + userid.len()].copy_from_slice(userid);
                len += userid.len();
                stack_buf[len] = 0x00; // Null terminator
                len += 1;
                &stack_buf[..len]
            }
            IpAddr::V6(_) => {
                // SOCKS4 doesn't support raw IPv6; reject
                return Err(ErrorReason::HandshakeFailed);
            }
        },
        TunnelTarget::Domain(domain, port) => {
            let required_len = 2 + 2 + 4 + userid.len() + 1 + domain.len() + 1;
            if required_len <= 128 {
                stack_buf[len..len + 2].copy_from_slice(&port.to_be_bytes());
                len += 2;
                stack_buf[len..len + 4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                len += 4;
                stack_buf[len..len + userid.len()].copy_from_slice(userid);
                len += userid.len();
                stack_buf[len] = 0x00;
                len += 1;
                stack_buf[len..len + domain.len()].copy_from_slice(domain.as_bytes());
                len += domain.len();
                stack_buf[len] = 0x00;
                len += 1;
                &stack_buf[..len]
            } else {
                let mut v = Vec::with_capacity(required_len);
                v.push(0x04);
                v.push(0x01);
                v.extend_from_slice(&port.to_be_bytes());
                v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                v.extend_from_slice(userid);
                v.push(0x00);
                v.extend_from_slice(domain.as_bytes());
                v.push(0x00);
                return send_and_read_socks4_reply(stream, &v).await;
            }
        }
    };

    send_and_read_socks4_reply(stream, packet_bytes).await
}

async fn send_and_read_socks4_reply<S>(
    stream: &mut S,
    packet: &[u8],
) -> Result<(), ErrorReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(packet).await.map_err(|_| ErrorReason::HandshakeFailed)?;
    stream.flush().await.map_err(|_| ErrorReason::HandshakeFailed)?;

    // SOCKS4 reply is exactly 8 bytes:
    // [VN (0 or 4), CD (result code), DSTPORT (2 bytes), DSTIP (4 bytes)]
    let mut reply = [0u8; 8];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|_| ErrorReason::HandshakeFailed)?;

    // 90: request granted
    // 91: request rejected or failed
    // 92: request rejected because SOCKS server cannot connect to identd on the client
    // 93: request rejected because the client program and identd report different user-ids
    match reply[1] {
        90 => Ok(()),
        91 => Err(ErrorReason::HandshakeFailed),
        92 | 93 => Err(ErrorReason::AuthRequired),
        _ => Err(ErrorReason::HandshakeFailed),
    }
}
