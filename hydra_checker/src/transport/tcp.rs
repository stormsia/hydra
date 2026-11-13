use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::config::CheckerConfig;
use crate::error::ErrorReason;
use crate::models::TargetHost;
use crate::net_filter::validate_target_ip;
use crate::transport::Dialer;

/// Production TCP Dialer with zero-copy IP resolution, SO_LINGER=0,
/// and local interface binding.
#[derive(Debug, Clone, Default)]
pub struct TcpDialer;

impl TcpDialer {
    #[inline]
    pub fn new() -> Self {
        Self
    }
}

impl Dialer for TcpDialer {
    type Stream = TcpStream;

    async fn connect(
        &self,
        host: &TargetHost,
        port: u16,
        timeout: Duration,
        config: &CheckerConfig,
    ) -> Result<Self::Stream, ErrorReason> {
        // Step 1: Pre-flight resolution & bogon validation
        let target_addr: SocketAddr = match host {
            TargetHost::Ip(ip) => {
                validate_target_ip(*ip, config)?;
                SocketAddr::new(*ip, port)
            }
            TargetHost::Domain(domain) => {
                // Resolve hostname with timeout
                let host_port = format!("{domain}:{port}");
                let mut resolved = tokio::time::timeout(
                    timeout,
                    tokio::net::lookup_host(host_port),
                )
                .await
                .map_err(|_| ErrorReason::TimeoutTcp)?
                .map_err(|e| map_io_error(&e))?;

                let first_addr = resolved.next().ok_or(ErrorReason::NetworkUnreachable)?;

                // Immediately validate resolved IP to prevent DNS Rebinding to bogons/LAN
                validate_target_ip(first_addr.ip(), config)?;
                first_addr
            }
        };

        // Step 2: Create raw socket via socket2 for fine-grained kernel control
        let domain = match target_addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| map_io_error(&e))?;

        socket.set_nonblocking(true).map_err(|e| map_io_error(&e))?;

        // Crucial high-load setting: SO_LINGER=0
        // Forces the kernel to emit TCP RST on drop, instantly reclaiming the port
        // and bypassing the 60s TIME_WAIT state that exhausts ephemeral ports.
        let _ = socket.set_linger(Some(Duration::ZERO));
        let _ = socket.set_tcp_nodelay(true);

        // Limit kernel socket buffers (16KB RX, 4KB TX) to avoid gigabytes of RAM exhaustion
        // under tens of thousands of concurrent connections
        let _ = socket.set_recv_buffer_size(16384);
        let _ = socket.set_send_buffer_size(4096);

        // Optional local interface binding
        if let Some(bind_ip) = config.local_bind_ip {
            // Only bind if the address family matches
            if (bind_ip.is_ipv4() && target_addr.is_ipv4())
                || (bind_ip.is_ipv6() && target_addr.is_ipv6())
            {
                let bind_addr = SocketAddr::new(bind_ip, 0);
                let _ = socket.bind(&bind_addr.into());
            }
        }

        // Convert to tokio::net::TcpSocket
        let std_socket: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_socket);

        // Step 3: Connect with timeout
        tokio::time::timeout(timeout, tokio_socket.connect(target_addr))
            .await
            .map_err(|_| ErrorReason::TimeoutTcp)?
            .map_err(|e| map_io_error(&e))
    }
}

#[inline]
fn map_io_error(e: &io::Error) -> ErrorReason {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => ErrorReason::ConnRefused,
        io::ErrorKind::TimedOut => ErrorReason::TimeoutTcp,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
            ErrorReason::ConnRefused
        }
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
            ErrorReason::NetworkUnreachable
        }
        _ => ErrorReason::ConnRefused,
    }
}
