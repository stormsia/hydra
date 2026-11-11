use compact_str::CompactString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::token::DailyTokenProvider;

/// Output formats supported by the Judge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseFormat {
    #[default]
    Azenv,
    Json,
}

/// Action to perform when an incoming connection fails token authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnauthorizedAction {
    /// Instantly drop the connection via TCP RST (SO_LINGER=0).
    /// Best against scanners (Shodan/Censys) as it sends 0 bytes and uses 0 CPU.
    #[default]
    DropRst,
    /// Send a clean HTTP 403 Forbidden with Connection: close
    Http403,
}

/// Global configuration for the Judge server
#[derive(Debug, Clone)]
pub struct JudgeConfig {
    pub http_bind_addr: SocketAddr,
    pub https_bind_addr: Option<SocketAddr>,
    pub secret_token: CompactString,
    pub secret_key: Option<CompactString>,
    pub token_provider: DailyTokenProvider,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_cert_der: Option<Vec<u8>>,
    pub tls_key_der: Option<Vec<u8>>,
    pub default_format: ResponseFormat,
    pub unauthorized_action: UnauthorizedAction,
    pub max_request_bytes: usize,
    pub request_timeout: Duration,
    /// Maximum concurrent active connections allowed (Semaphore backpressure against DoS/OOM)
    pub max_concurrent_connections: usize,
}

impl JudgeConfig {
    pub fn builder(
        http_bind_addr: SocketAddr,
        secret_token: impl AsRef<str>,
    ) -> JudgeConfigBuilder {
        JudgeConfigBuilder::new(http_bind_addr, secret_token)
    }

    #[inline]
    pub fn active_token(&self) -> CompactString {
        self.token_provider.active_token()
    }
}

/// Builder for `JudgeConfig`
#[derive(Debug, Clone)]
pub struct JudgeConfigBuilder {
    http_bind_addr: SocketAddr,
    https_bind_addr: Option<SocketAddr>,
    secret_token: CompactString,
    secret_key: Option<CompactString>,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    tls_cert_der: Option<Vec<u8>>,
    tls_key_der: Option<Vec<u8>>,
    default_format: ResponseFormat,
    unauthorized_action: UnauthorizedAction,
    max_request_bytes: usize,
    request_timeout: Duration,
    max_concurrent_connections: usize,
}

impl JudgeConfigBuilder {
    pub fn new(http_bind_addr: SocketAddr, secret_token: impl AsRef<str>) -> Self {
        Self {
            http_bind_addr,
            https_bind_addr: None,
            secret_token: CompactString::new(secret_token),
            secret_key: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_cert_der: None,
            tls_key_der: None,
            default_format: ResponseFormat::Azenv,
            unauthorized_action: UnauthorizedAction::DropRst,
            max_request_bytes: 4096,
            request_timeout: Duration::from_secs(3),
            max_concurrent_connections: 10_000,
        }
    }

    #[inline]
    pub fn secret_key(mut self, key: impl AsRef<str>) -> Self {
        self.secret_key = Some(CompactString::new(key));
        self
    }

    #[inline]
    pub fn https_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.https_bind_addr = Some(addr);
        self
    }

    #[inline]
    pub fn tls_cert_path(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self.tls_key_path = Some(key_path.into());
        self
    }

    #[inline]
    pub fn tls_cert_der(mut self, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        self.tls_cert_der = Some(cert_der);
        self.tls_key_der = Some(key_der);
        self
    }

    #[inline]
    pub fn default_format(mut self, format: ResponseFormat) -> Self {
        self.default_format = format;
        self
    }

    #[inline]
    pub fn unauthorized_action(mut self, action: UnauthorizedAction) -> Self {
        self.unauthorized_action = action;
        self
    }

    #[inline]
    pub fn max_request_bytes(mut self, bytes: usize) -> Self {
        self.max_request_bytes = bytes.max(512);
        self
    }

    #[inline]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    #[inline]
    pub fn max_concurrent_connections(mut self, limit: usize) -> Self {
        self.max_concurrent_connections = limit.max(1);
        self
    }

    pub fn build(self) -> JudgeConfig {
        let token_provider = if let Some(key) = &self.secret_key {
            DailyTokenProvider::new_dynamic(key.as_str())
        } else {
            DailyTokenProvider::new_static(self.secret_token.as_str())
        };

        JudgeConfig {
            http_bind_addr: self.http_bind_addr,
            https_bind_addr: self.https_bind_addr,
            secret_token: self.secret_token,
            secret_key: self.secret_key,
            token_provider,
            tls_cert_path: self.tls_cert_path,
            tls_key_path: self.tls_key_path,
            tls_cert_der: self.tls_cert_der,
            tls_key_der: self.tls_key_der,
            default_format: self.default_format,
            unauthorized_action: self.unauthorized_action,
            max_request_bytes: self.max_request_bytes,
            request_timeout: self.request_timeout,
            max_concurrent_connections: self.max_concurrent_connections,
        }
    }
}
