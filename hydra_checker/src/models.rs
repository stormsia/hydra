use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use url::Url;

use crate::error::ErrorReason;

/// Target host representation with zero-allocation for IP addresses
/// and stack-inlined small string storage for domain names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetHost {
    Ip(IpAddr),
    Domain(CompactString),
}

impl TargetHost {
    /// Parse from a string slice. If it can be parsed as an IP address,
    /// stores as `Ip(IpAddr)` with zero heap allocations.
    #[inline]
    pub fn parse(s: &str) -> Self {
        if let Ok(ip) = s.parse::<IpAddr>() {
            Self::Ip(ip)
        } else {
            Self::Domain(CompactString::new(s))
        }
    }

    /// Return host as Cow<'_, str> with zero-copy for domains
    #[inline]
    pub fn to_cow(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Ip(ip) => std::borrow::Cow::Owned(ip.to_string()),
            Self::Domain(d) => std::borrow::Cow::Borrowed(d.as_str()),
        }
    }
}

impl std::fmt::Display for TargetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

impl From<IpAddr> for TargetHost {
    #[inline]
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl From<&str> for TargetHost {
    #[inline]
    fn from(s: &str) -> Self {
        Self::parse(s)
    }
}

impl From<String> for TargetHost {
    #[inline]
    fn from(s: String) -> Self {
        Self::parse(&s)
    }
}

/// Authentication credentials for private proxies
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: CompactString,
    pub password: CompactString,
}

impl ProxyAuth {
    #[inline]
    pub fn new(username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        Self {
            username: CompactString::new(username),
            password: CompactString::new(password),
        }
    }
}

/// Proxy protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    Http,
    Https,
    Socks4,
    Socks4a,
    Socks5,
}

impl ProxyProtocol {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks4 => "socks4",
            Self::Socks4a => "socks4a",
            Self::Socks5 => "socks5",
        }
    }
}

impl std::fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Optional per-check configuration override
#[derive(Debug, Clone, Default)]
pub struct CheckConfigOverride {
    pub connect_timeout: Option<Duration>,
    pub handshake_timeout: Option<Duration>,
    pub read_write_timeout: Option<Duration>,
    pub judge_http_url: Option<Url>,
    pub judge_https_url: Option<Url>,
    pub judge_expected_token: Option<CompactString>,
}

/// Incoming proxy check request contract
#[derive(Debug, Clone)]
pub struct CheckTarget {
    pub host: TargetHost,
    pub port: u16,
    pub expected_protocol: Option<ProxyProtocol>,
    pub auth: Option<ProxyAuth>,
    pub config_override: Option<Box<CheckConfigOverride>>,
}

impl CheckTarget {
    #[inline]
    pub fn new(host: impl Into<TargetHost>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            expected_protocol: None,
            auth: None,
            config_override: None,
        }
    }

    #[inline]
    pub fn with_protocol(mut self, protocol: ProxyProtocol) -> Self {
        self.expected_protocol = Some(protocol);
        self
    }

    #[inline]
    pub fn with_auth(mut self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        self.auth = Some(ProxyAuth::new(username, password));
        self
    }

    #[inline]
    pub fn with_override(mut self, config_override: CheckConfigOverride) -> Self {
        self.config_override = Some(Box::new(config_override));
        self
    }
}

/// Anonymity level determined by Judge response headers and IP matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnonymityLevel {
    /// Proxy revealed the caller's real IP address in headers (e.g. X-Forwarded-For)
    Transparent,
    /// Real IP is hidden, but proxy headers (Via, Proxy-Connection, etc.) reveal proxy usage
    Anonymous,
    /// Neither real IP nor proxy headers are visible to the Judge server
    Elite,
}

impl AnonymityLevel {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transparent => "transparent",
            Self::Anonymous => "anonymous",
            Self::Elite => "elite",
        }
    }
}

impl std::fmt::Display for AnonymityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Detailed stage RTT telemetry (in milliseconds)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CheckMetrics {
    /// Time spent establishing raw L4 TCP connection
    pub tcp_connect_rtt_ms: u64,
    /// Time spent negotiating protocol tunnel (and TLS where applicable)
    pub handshake_rtt_ms: u64,
    /// Total elapsed time from check start to Judge verification
    pub total_rtt_ms: u64,
}

/// Outgoing diagnostic result contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub target_host: TargetHost,
    pub target_port: u16,
    pub is_alive: bool,
    pub detected_protocol: Option<ProxyProtocol>,
    pub anonymity_level: Option<AnonymityLevel>,
    pub external_ip: Option<IpAddr>,
    pub metrics: CheckMetrics,
    pub supports_https: bool,
    pub error_reason: Option<ErrorReason>,
}

impl CheckResult {
    /// Helper to construct a failed check result
    #[inline]
    pub fn failure(
        target_host: TargetHost,
        target_port: u16,
        error_reason: ErrorReason,
        metrics: CheckMetrics,
    ) -> Self {
        Self {
            target_host,
            target_port,
            is_alive: false,
            detected_protocol: None,
            anonymity_level: None,
            external_ip: None,
            metrics,
            supports_https: false,
            error_reason: Some(error_reason),
        }
    }
}
