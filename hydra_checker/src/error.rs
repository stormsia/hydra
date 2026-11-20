use serde::{Deserialize, Serialize};
use std::fmt;

/// Strictly typed, deterministic error reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorReason {
    /// Target IP is loopback, private RFC1918, link-local, self-IP, or Judge-IP
    BogonOrReservedIp,
    /// L4 TCP SYN/SYN-ACK timed out
    TimeoutTcp,
    /// TCP connection actively refused by target port
    ConnRefused,
    /// Network or host unreachable at L3/L4
    NetworkUnreachable,
    /// Protocol handshake or negotiation timed out (anti-tarpit)
    TimeoutHandshake,
    /// Protocol handshake failed (signature mismatch, SOCKS error code, non-200 CONNECT)
    HandshakeFailed,
    /// Proxy authentication required (HTTP 407 or SOCKS5 0xFF)
    AuthRequired,
    /// TLS handshake failed (certificate invalid, MITM proxy, alert)
    TlsHandshakeFailed,
    /// Reading/writing L7 HTTP request/response to Judge timed out
    TimeoutReadWrite,
    /// Proxy returned more bytes than `max_read_bytes` limit (tarpit / zip-bomb prevention)
    ReadLimitExceeded,
    /// HTTP response malformed or unexpected HTTP status from Judge
    InvalidResponse,
    /// Judge response missing expected token or echoed our own real IP as exit IP
    JudgeMismatch,
    /// Operation was cancelled via external CancellationToken or context shutdown
    Cancelled,
    /// Unrecoverable internal system error
    InternalError,
    /// Remote returned HTTP response when SOCKS protocol was expected
    HttpDetected,
}

impl ErrorReason {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BogonOrReservedIp => "BOGON_OR_RESERVED_IP",
            Self::TimeoutTcp => "TIMEOUT_TCP",
            Self::ConnRefused => "CONN_REFUSED",
            Self::NetworkUnreachable => "NETWORK_UNREACHABLE",
            Self::TimeoutHandshake => "TIMEOUT_HANDSHAKE",
            Self::HandshakeFailed => "HANDSHAKE_FAILED",
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::TlsHandshakeFailed => "TLS_HANDSHAKE_FAILED",
            Self::TimeoutReadWrite => "TIMEOUT_READ_WRITE",
            Self::ReadLimitExceeded => "READ_LIMIT_EXCEEDED",
            Self::InvalidResponse => "INVALID_RESPONSE",
            Self::JudgeMismatch => "JUDGE_MISMATCH",
            Self::Cancelled => "CANCELLED",
            Self::InternalError => "INTERNAL_ERROR",
            Self::HttpDetected => "HTTP_DETECTED",
        }
    }
}

impl fmt::Display for ErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Standard error type for hydra_checker operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckerError {
    pub reason: ErrorReason,
    pub detail: Option<compact_str::CompactString>,
}

impl CheckerError {
    #[inline]
    pub fn new(reason: ErrorReason) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    #[inline]
    pub fn with_detail(reason: ErrorReason, detail: impl AsRef<str>) -> Self {
        Self {
            reason,
            detail: Some(compact_str::CompactString::new(detail)),
        }
    }
}

impl fmt::Display for CheckerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(detail) = &self.detail {
            write!(f, "{}: {}", self.reason.as_str(), detail)
        } else {
            write!(f, "{}", self.reason.as_str())
        }
    }
}

impl std::error::Error for CheckerError {}

impl From<ErrorReason> for CheckerError {
    #[inline]
    fn from(reason: ErrorReason) -> Self {
        Self::new(reason)
    }
}
