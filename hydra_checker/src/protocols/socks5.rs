use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ErrorReason;
use crate::models::ProxyAuth;
use crate::protocols::TunnelTarget;

/// Execute SOCKS5 handshake (RFC 1928) and User/Pass Authentication (RFC 1929).
pub async fn handshake_socks5<S>(
    stream: &mut S,
    target: &TunnelTarget,
    auth: Option<&ProxyAuth>,
) -> Result<(), ErrorReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Greeting
    if auth.is_some() {
        // Offer NO AUTH (0x00) and USER/PASS (0x02)
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|_| ErrorReason::HandshakeFailed)?;
    } else {
        // Offer NO AUTH (0x00)
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|_| ErrorReason::HandshakeFailed)?;
    }
    stream
        .flush()
        .await
        .map_err(|_| ErrorReason::HandshakeFailed)?;

    // Step 2: Read method selection
    let mut method_resp = [0u8; 2];
    stream
        .read_exact(&mut method_resp)
        .await
        .map_err(|_| ErrorReason::HandshakeFailed)?;

    if method_resp[0] != 0x05 {
        return Err(ErrorReason::HandshakeFailed);
    }

    match method_resp[1] {
        0x00 => {
            // No auth required
        }
        0x02 => {
            // Username/Password authentication requested
            let auth = auth.ok_or(ErrorReason::AuthRequired)?;
            let u_bytes = auth.username.as_bytes();
            let p_bytes = auth.password.as_bytes();

            if u_bytes.len() > 255 || p_bytes.len() > 255 {
                return Err(ErrorReason::HandshakeFailed);
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
                .map_err(|_| ErrorReason::HandshakeFailed)?;
            stream
                .flush()
                .await
                .map_err(|_| ErrorReason::HandshakeFailed)?;

            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .await
                .map_err(|_| ErrorReason::HandshakeFailed)?;

            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                return Err(ErrorReason::AuthRequired);
            }
        }
        0xFF => return Err(ErrorReason::AuthRequired),
        _ => return Err(ErrorReason::HandshakeFailed),
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
                return Err(ErrorReason::HandshakeFailed);
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
        .map_err(|_| ErrorReason::HandshakeFailed)?;
    stream
        .flush()
        .await
        .map_err(|_| ErrorReason::HandshakeFailed)?;

    // Step 4: Read CONNECT response header
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| ErrorReason::HandshakeFailed)?;

    if header[0] != 0x05 {
        return Err(ErrorReason::HandshakeFailed);
    }

    if header[1] != 0x00 {
        return match header[1] {
            0x05 => Err(ErrorReason::ConnRefused),
            0x03 | 0x04 => Err(ErrorReason::NetworkUnreachable),
            _ => Err(ErrorReason::HandshakeFailed),
        };
    }

    // Step 5: Read and discard bound address/port to leave stream clean
    match header[3] {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut discard = [0u8; 6];
            stream
                .read_exact(&mut discard)
                .await
                .map_err(|_| ErrorReason::HandshakeFailed)?;
        }
        0x03 => {
            // Domain: 1 byte len, then len bytes, then 2 bytes port
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|_| ErrorReason::HandshakeFailed)?;
            let d_len = len_buf[0] as usize;
            // Use stack buffer instead of heap vec (max domain length is 255 + 2 bytes port = 257)
            let mut discard = [0u8; 257];
            stream
                .read_exact(&mut discard[..d_len + 2])
                .await
                .map_err(|_| ErrorReason::HandshakeFailed)?;
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut discard = [0u8; 18];
            stream
                .read_exact(&mut discard)
                .await
                .map_err(|_| ErrorReason::HandshakeFailed)?;
        }
        _ => return Err(ErrorReason::HandshakeFailed),
    }

    Ok(())
}
