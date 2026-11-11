use compact_str::CompactString;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use url::Url;

use crate::error::{CheckerError, ErrorReason};
use crate::judge::{JudgeEndpoint, JudgePool, JudgeSelectionStrategy};
use crate::token::{DailyTokenProvider, current_epoch_day};

#[derive(Debug, Clone)]
pub struct CachedTlsRequest {
    pub day: u64,
    pub effective_url: Url,
    pub server_name: String,
    pub request_bytes: Vec<u8>,
}

/// Global configuration for the proxy checker engine
#[derive(Debug, Clone)]
pub struct CheckerConfig {
    /// Unencrypted HTTP Judge endpoint (used for Plain HTTP proxy checks & fallback)
    pub judge_http_url: Url,
    /// Pre-resolved SocketAddr for HTTP Judge (avoids runtime DNS lookups)
    pub judge_http_addr: Option<SocketAddr>,
    /// HTTPS Judge endpoint (used for SOCKS5, SOCKS4/4a, and HTTP CONNECT tunnel checks)
    pub judge_https_url: Url,
    /// Pre-resolved SocketAddr for HTTPS Judge (enables pure IPv4 SOCKS4 checks)
    pub judge_https_addr: Option<SocketAddr>,
    /// Static secret marker/signature in Judge response body (or fallback)
    pub judge_expected_token: CompactString,
    /// Optional shared secret key for synchronized daily token derivation
    pub judge_secret_key: Option<CompactString>,
    /// Optional daily token provider initialized from judge_secret_key
    pub token_provider: Option<DailyTokenProvider>,
    /// Optional DER-encoded Root CA / Server certificate for self-hosted HTTPS Judge
    pub judge_ca_cert_der: Option<Vec<u8>>,
    /// Maximum time for L4 TCP connection establishment (SYN/SYN-ACK)
    pub connect_timeout: Duration,
    /// Maximum time for protocol handshake / tunnel negotiation and TLS
    pub handshake_timeout: Duration,
    /// Maximum time for sending HTTP request to Judge and receiving response
    pub read_write_timeout: Duration,
    /// Maximum concurrent active proxy checks
    pub concurrency_limit: usize,
    /// Optional local network interface IP to bind outgoing sockets
    pub local_bind_ip: Option<IpAddr>,
    /// Caller's real public IP (used to classify Transparent proxies & prevent self-scans)
    pub real_ip: Option<IpAddr>,
    /// Maximum allowed bytes to read from Judge response (Default: 8192 bytes)
    pub max_read_bytes: usize,
    /// Dynamic pool of Judge endpoints with live health tracking and fallback
    pub judge_pool: Arc<JudgePool>,
    /// Cached daily TLS request template (avoids URL formatting overhead on every check)
    cached_tls_req: Arc<RwLock<CachedTlsRequest>>,
}

impl CheckerConfig {
    /// Create a new builder with the required Judge parameters
    pub fn builder(
        judge_http_url: Url,
        judge_https_url: Url,
        judge_expected_token: impl AsRef<str>,
    ) -> CheckerConfigBuilder {
        CheckerConfigBuilder::new(judge_http_url, judge_https_url, judge_expected_token)
    }

    /// Load CheckerConfig from environment variables with sensible defaults
    pub async fn from_env() -> Result<Self, CheckerError> {
        let http_url_str = std::env::var("JUDGE_HTTP_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let https_url_str = std::env::var("JUDGE_HTTPS_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let expected_token = std::env::var("JUDGE_SECRET_TOKEN")
            .unwrap_or_else(|_| "hydra_secret_token".to_string());

        let http_url = Url::parse(&http_url_str)
            .map_err(|_| CheckerError::new(ErrorReason::InternalError))?;
        let https_url = Url::parse(&https_url_str)
            .map_err(|_| CheckerError::new(ErrorReason::InternalError))?;

        let mut builder = Self::builder(http_url, https_url, expected_token);

        if let Ok(key) = std::env::var("JUDGE_SECRET_KEY") {
            builder = builder.judge_secret_key(key);
        }

        if let Ok(conc) = std::env::var("CHECKER_CONCURRENCY").and_then(|v| v.parse::<usize>().map_err(|_| std::env::VarError::NotPresent)) {
            builder = builder.concurrency_limit(conc);
        }

        if let Ok(timeout) = std::env::var("CHECKER_CONNECT_TIMEOUT_MS").and_then(|v| v.parse::<u64>().map_err(|_| std::env::VarError::NotPresent)) {
            builder = builder.connect_timeout(Duration::from_millis(timeout));
        }

        if let Ok(timeout) = std::env::var("CHECKER_HANDSHAKE_TIMEOUT_MS").and_then(|v| v.parse::<u64>().map_err(|_| std::env::VarError::NotPresent)) {
            builder = builder.handshake_timeout(Duration::from_millis(timeout));
        }

        if let Ok(timeout) = std::env::var("CHECKER_READ_WRITE_TIMEOUT_MS").and_then(|v| v.parse::<u64>().map_err(|_| std::env::VarError::NotPresent)) {
            builder = builder.read_write_timeout(Duration::from_millis(timeout));
        }

        if let Ok(bytes) = std::env::var("CHECKER_MAX_READ_BYTES").and_then(|v| v.parse::<usize>().map_err(|_| std::env::VarError::NotPresent)) {
            builder = builder.max_read_bytes(bytes);
        }

        if let Ok(ip_str) = std::env::var("CHECKER_LOCAL_BIND_IP") {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                builder = builder.local_bind_ip(ip);
            }
        }

        if let Ok(ip_str) = std::env::var("CHECKER_REAL_IP") {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                builder = builder.real_ip(ip);
            }
        }

        if let Ok(val) = std::env::var("ENABLE_THIRD_PARTY_JUDGES") {
            let enable = val.eq_ignore_ascii_case("true") || val == "1";
            builder = builder.enable_third_party_judges(enable);
        }

        if let Ok(val) = std::env::var("JUDGE_SELECTION_STRATEGY") {
            if val.eq_ignore_ascii_case("round_robin") || val.eq_ignore_ascii_case("roundrobin") {
                builder = builder.judge_selection_strategy(JudgeSelectionStrategy::RoundRobin);
            } else if val.eq_ignore_ascii_case("priority") {
                builder = builder.judge_selection_strategy(JudgeSelectionStrategy::Priority);
            } else if val.eq_ignore_ascii_case("lowest_latency") || val.eq_ignore_ascii_case("latency") {
                builder = builder.judge_selection_strategy(JudgeSelectionStrategy::LowestLatency);
            }
        }

        builder.build().await
    }

    /// Retrieve the currently active token (dynamic daily token or static token)
    #[inline]
    pub fn active_judge_token(&self) -> CompactString {
        if let Some(provider) = &self.token_provider {
            provider.current_token()
        } else {
            self.judge_expected_token.clone()
        }
    }

    /// Format Judge URL by replacing `{TOKEN}` placeholder or appending `?token=` parameter
    pub fn format_judge_url(&self, url: &Url) -> Url {
        let token = self.active_judge_token();
        let url_str = url.as_str();

        if url_str.contains("{TOKEN}") {
            let replaced = url_str.replace("{TOKEN}", token.as_str());
            if let Ok(u) = Url::parse(&replaced) {
                return u;
            }
        }

        // If URL doesn't have token query param and no secret path, append ?token=
        let mut u = url.clone();
        let query = u.query().unwrap_or_default();
        if !query.contains("token=") {
            let new_query = if query.is_empty() {
                format!("token={token}")
            } else {
                format!("{query}&token={token}")
            };
            u.set_query(Some(&new_query));
        }

        u
    }

    /// Check if response body contains valid expected token (accounting for daily rotation & midnight drift)
    pub fn is_token_matched(&self, body: &str) -> bool {
        if let Some(provider) = &self.token_provider {
            provider.is_token_in_body(body)
        } else {
            body.contains(self.judge_expected_token.as_str())
        }
    }

    /// Retrieve or build pre-rendered TLS HTTP request (cached per day for default judge URL)
    pub fn get_judge_tls_request(&self, judge_url: &Url) -> (Url, String, Vec<u8>) {
        let is_default = judge_url == &self.judge_https_url;
        let day = current_epoch_day();

        if is_default {
            {
                let guard = self.cached_tls_req.read().unwrap();
                if guard.day == day {
                    return (
                        guard.effective_url.clone(),
                        guard.server_name.clone(),
                        guard.request_bytes.clone(),
                    );
                }
            }

            let mut guard = self.cached_tls_req.write().unwrap();
            if guard.day != day {
                let effective_url = self.format_judge_url(judge_url);
                let active_token = self.active_judge_token();
                let host_str = effective_url.host_str().unwrap_or("localhost");
                let path = effective_url.path();
                let query = effective_url.query().map(|q| format!("?{q}")).unwrap_or_default();
                let port_str = match effective_url.port() {
                    Some(p) if p != 443 => format!(":{p}"),
                    _ => String::new(),
                };

                let req = format!(
                    "GET {path}{query} HTTP/1.1\r\n\
                     Host: {host_str}{port_str}\r\n\
                     User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
                     X-Hydra-Token: {active_token}\r\n\
                     Connection: close\r\n\
                     \r\n"
                );

                *guard = CachedTlsRequest {
                    day,
                    effective_url: effective_url.clone(),
                    server_name: host_str.to_string(),
                    request_bytes: req.into_bytes(),
                };
            }

            return (
                guard.effective_url.clone(),
                guard.server_name.clone(),
                guard.request_bytes.clone(),
            );
        }

        // Custom override URL: dynamic formatting fallback
        let effective_url = self.format_judge_url(judge_url);
        let active_token = self.active_judge_token();
        let host_string = effective_url.host_str().unwrap_or("localhost").to_string();
        let path = effective_url.path();
        let query = effective_url.query().map(|q| format!("?{q}")).unwrap_or_default();
        let port_str = match effective_url.port() {
            Some(p) if p != 443 => format!(":{p}"),
            _ => String::new(),
        };

        let req = format!(
            "GET {path}{query} HTTP/1.1\r\n\
             Host: {host_string}{port_str}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
             X-Hydra-Token: {active_token}\r\n\
             Connection: close\r\n\
             \r\n"
        );

        (effective_url, host_string, req.into_bytes())
    }

    /// Format judge URL, only injecting token query params if is_builtin or URL explicitly has {TOKEN}
    pub fn format_judge_url_for(&self, url: &Url, is_builtin: bool) -> Url {
        if !is_builtin && !url.as_str().contains("{TOKEN}") {
            return url.clone();
        }
        self.format_judge_url(url)
    }

    /// Retrieve or build pre-rendered TLS HTTP request for any judge (builtin or third-party)
    pub fn get_judge_tls_request_for(
        &self,
        judge_url: &Url,
        is_builtin: bool,
        expected_token: Option<&str>,
    ) -> (Url, String, Vec<u8>) {
        if is_builtin && judge_url == &self.judge_https_url {
            return self.get_judge_tls_request(judge_url);
        }

        let effective_url = self.format_judge_url_for(judge_url, is_builtin);
        let host_string = effective_url.host_str().unwrap_or("localhost").to_string();
        let path = effective_url.path();
        let query = effective_url.query().map(|q| format!("?{q}")).unwrap_or_default();
        let port_str = match effective_url.port() {
            Some(p) if p != 443 => format!(":{p}"),
            _ => String::new(),
        };

        let mut req = format!(
            "GET {path}{query} HTTP/1.1\r\n\
             Host: {host_string}{port_str}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
             Connection: close\r\n"
        );

        if is_builtin {
            let active_token = self.active_judge_token();
            req.push_str(&format!("X-Hydra-Token: {active_token}\r\n"));
        } else if let Some(token) = expected_token {
            req.push_str(&format!("X-Hydra-Token: {token}\r\n"));
        }
        req.push_str("\r\n");

        (effective_url, host_string, req.into_bytes())
    }
}

/// Builder for `CheckerConfig` with sensible high-performance defaults
#[derive(Debug, Clone)]
pub struct CheckerConfigBuilder {
    judge_http_url: Url,
    judge_http_addr: Option<SocketAddr>,
    judge_https_url: Url,
    judge_https_addr: Option<SocketAddr>,
    judge_expected_token: CompactString,
    judge_secret_key: Option<CompactString>,
    judge_ca_cert_der: Option<Vec<u8>>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    read_write_timeout: Duration,
    concurrency_limit: usize,
    local_bind_ip: Option<IpAddr>,
    real_ip: Option<IpAddr>,
    max_read_bytes: usize,
    enable_third_party_judges: bool,
    judge_selection_strategy: JudgeSelectionStrategy,
    custom_judges: Vec<JudgeEndpoint>,
    custom_judge_pool: Option<Arc<JudgePool>>,
}

impl CheckerConfigBuilder {
    pub fn new(
        judge_http_url: Url,
        judge_https_url: Url,
        judge_expected_token: impl AsRef<str>,
    ) -> Self {
        Self {
            judge_http_url,
            judge_http_addr: None,
            judge_https_url,
            judge_https_addr: None,
            judge_expected_token: CompactString::new(judge_expected_token),
            judge_secret_key: None,
            judge_ca_cert_der: None,
            connect_timeout: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(4),
            read_write_timeout: Duration::from_secs(5),
            concurrency_limit: 5000,
            local_bind_ip: None,
            real_ip: None,
            max_read_bytes: 8192,
            enable_third_party_judges: true,
            judge_selection_strategy: JudgeSelectionStrategy::LowestLatency,
            custom_judges: Vec::new(),
            custom_judge_pool: None,
        }
    }

    #[inline]
    pub fn judge_secret_key(mut self, key: impl AsRef<str>) -> Self {
        self.judge_secret_key = Some(CompactString::new(key));
        self
    }

    #[inline]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    #[inline]
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    #[inline]
    pub fn read_write_timeout(mut self, timeout: Duration) -> Self {
        self.read_write_timeout = timeout;
        self
    }

    #[inline]
    pub fn concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit.max(1);
        self
    }

    #[inline]
    pub fn local_bind_ip(mut self, ip: IpAddr) -> Self {
        self.local_bind_ip = Some(ip);
        self
    }

    #[inline]
    pub fn real_ip(mut self, ip: IpAddr) -> Self {
        self.real_ip = Some(ip);
        self
    }

    #[inline]
    pub fn max_read_bytes(mut self, max_bytes: usize) -> Self {
        self.max_read_bytes = max_bytes.max(1);
        self
    }

    #[inline]
    pub fn judge_ca_cert_der(mut self, cert_der: Vec<u8>) -> Self {
        self.judge_ca_cert_der = Some(cert_der);
        self
    }

    #[inline]
    pub fn judge_http_addr(mut self, addr: SocketAddr) -> Self {
        self.judge_http_addr = Some(addr);
        self
    }

    #[inline]
    pub fn judge_https_addr(mut self, addr: SocketAddr) -> Self {
        self.judge_https_addr = Some(addr);
        self
    }

    #[inline]
    pub fn enable_third_party_judges(mut self, enable: bool) -> Self {
        self.enable_third_party_judges = enable;
        self
    }

    #[inline]
    pub fn judge_selection_strategy(mut self, strategy: JudgeSelectionStrategy) -> Self {
        self.judge_selection_strategy = strategy;
        self
    }

    #[inline]
    pub fn add_judge(mut self, judge: JudgeEndpoint) -> Self {
        self.custom_judges.push(judge);
        self
    }

    #[inline]
    pub fn judge_pool(mut self, pool: Arc<JudgePool>) -> Self {
        self.custom_judge_pool = Some(pool);
        self
    }

    /// Asynchronously resolve Judge hostnames to SocketAddrs and build the config
    pub async fn build(mut self) -> Result<CheckerConfig, CheckerError> {
        // Resolve HTTP Judge if not explicitly set
        if self.judge_http_addr.is_none() {
            if let Some(host) = self.judge_http_url.host_str() {
                let port = self.judge_http_url.port().unwrap_or(80);
                if let Ok(ip) = host.parse::<IpAddr>() {
                    self.judge_http_addr = Some(SocketAddr::new(ip, port));
                } else {
                    let host_owned = host.to_string();
                    let resolved = tokio::task::spawn_blocking(move || {
                        format!("{host_owned}:{port}")
                            .to_socket_addrs()
                            .ok()
                            .and_then(|mut iter| iter.next())
                    })
                    .await
                    .map_err(|_| CheckerError::new(ErrorReason::InternalError))?;

                    self.judge_http_addr = resolved;
                }
            }
        }

        // Resolve HTTPS Judge if not explicitly set
        if self.judge_https_addr.is_none() {
            if let Some(host) = self.judge_https_url.host_str() {
                let port = self.judge_https_url.port().unwrap_or(443);
                if let Ok(ip) = host.parse::<IpAddr>() {
                    self.judge_https_addr = Some(SocketAddr::new(ip, port));
                } else {
                    let host_owned = host.to_string();
                    let resolved = tokio::task::spawn_blocking(move || {
                        format!("{host_owned}:{port}")
                            .to_socket_addrs()
                            .ok()
                            .and_then(|mut iter| iter.next())
                    })
                    .await
                    .map_err(|_| CheckerError::new(ErrorReason::InternalError))?;

                    self.judge_https_addr = resolved;
                }
            }
        }

        let token_provider = self
            .judge_secret_key
            .as_ref()
            .map(|key| DailyTokenProvider::new(key.as_str()));

        let cached_tls_req = Arc::new(RwLock::new(CachedTlsRequest {
            day: 0,
            effective_url: self.judge_https_url.clone(),
            server_name: self.judge_https_url.host_str().unwrap_or("localhost").to_string(),
            request_bytes: Vec::new(),
        }));

        let judge_pool = if let Some(pool) = self.custom_judge_pool {
            pool
        } else {
            let builtin = JudgeEndpoint::builtin(
                self.judge_http_url.clone(),
                self.judge_https_url.clone(),
                Some(self.judge_expected_token.clone()),
            );
            let mut third_party = if self.enable_third_party_judges {
                JudgeEndpoint::default_third_party_judges()
            } else {
                Vec::new()
            };
            third_party.extend(self.custom_judges);
            Arc::new(JudgePool::new(builtin, third_party, self.judge_selection_strategy))
        };

        Ok(CheckerConfig {
            judge_http_url: self.judge_http_url,
            judge_http_addr: self.judge_http_addr,
            judge_https_url: self.judge_https_url,
            judge_https_addr: self.judge_https_addr,
            judge_expected_token: self.judge_expected_token,
            judge_secret_key: self.judge_secret_key,
            token_provider,
            judge_ca_cert_der: self.judge_ca_cert_der,
            connect_timeout: self.connect_timeout,
            handshake_timeout: self.handshake_timeout,
            read_write_timeout: self.read_write_timeout,
            concurrency_limit: self.concurrency_limit,
            local_bind_ip: self.local_bind_ip,
            real_ip: self.real_ip,
            max_read_bytes: self.max_read_bytes,
            judge_pool,
            cached_tls_req,
        })
    }
}
