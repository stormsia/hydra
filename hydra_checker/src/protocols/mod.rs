use compact_str::CompactString;
use std::net::SocketAddr;
use url::Url;

pub mod http_connect;
pub mod http_plain;
pub mod socks4;
pub mod socks5;

/// Destination target for proxy tunnels (SOCKS4, SOCKS5, HTTP CONNECT)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelTarget {
    Addr(SocketAddr),
    Domain(CompactString, u16),
}

impl TunnelTarget {
    #[inline]
    pub fn from_url(url: &Url, pre_resolved: Option<SocketAddr>) -> Option<Self> {
        let port = url.port_or_known_default()?;
        if let Some(addr) = pre_resolved {
            return Some(Self::Addr(addr));
        }

        let host = url.host_str()?;
        if let Ok(ip) = host.parse() {
            Some(Self::Addr(SocketAddr::new(ip, port)))
        } else {
            Some(Self::Domain(CompactString::new(host), port))
        }
    }

    #[inline]
    pub fn host_header(&self) -> CompactString {
        match self {
            Self::Addr(addr) => compact_str::format_compact!("{addr}"),
            Self::Domain(domain, port) => compact_str::format_compact!("{domain}:{port}"),
        }
    }
}
