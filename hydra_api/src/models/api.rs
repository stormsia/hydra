use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};

use super::db::ProxyState;

fn default_connect_timeout() -> u32 {
    3000
}
fn default_handshake_timeout() -> u32 {
    4000
}
fn default_rw_timeout() -> u32 {
    5000
}
fn default_recheck_alive() -> u32 {
    60
}
fn default_recheck_dead() -> u32 {
    1800
}
fn default_max_strikes() -> u32 {
    3
}
fn default_stability_window_min() -> u32 {
    5
}
fn default_dead_backoff_mult() -> f32 {
    1.5
}

/// Timeout policy and verification schedule for proxy servers
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
#[schema(example = json!({
    "connect_timeout_ms": 3000,
    "handshake_timeout_ms": 4000,
    "rw_timeout_ms": 5000,
    "recheck_alive_sec": 60,
    "recheck_dead_sec": 1800,
    "max_dead_strikes": 3,
    "stability_window_min": 5,
    "dead_backoff_mult": 1.5
}))]
pub struct CheckPolicyDto {
    /// Maximum TCP connection establishment timeout (in milliseconds)
    #[serde(default = "default_connect_timeout")]
    #[schema(example = 3000, minimum = 100, maximum = 60000, default = 3000)]
    pub connect_timeout_ms: u32,

    /// Maximum timeout for completing SSL/TLS or protocol handshake (in milliseconds)
    #[serde(default = "default_handshake_timeout")]
    #[schema(example = 4000, minimum = 100, maximum = 60000, default = 4000)]
    pub handshake_timeout_ms: u32,

    /// Read/write I/O timeout during judge validation (in milliseconds)
    #[serde(default = "default_rw_timeout")]
    #[schema(example = 5000, minimum = 100, maximum = 60000, default = 5000)]
    pub rw_timeout_ms: u32,

    /// Interval for periodic background rechecks of alive proxies (in seconds)
    #[serde(default = "default_recheck_alive")]
    #[schema(example = 60, minimum = 10, maximum = 86400, default = 60)]
    pub recheck_alive_sec: u32,

    /// Interval for rechecking quarantined proxies in cooldown (in seconds)
    #[serde(default = "default_recheck_dead")]
    #[schema(example = 1800, minimum = 30, maximum = 604800, default = 1800)]
    pub recheck_dead_sec: u32,

    /// Number of consecutive failures before marking proxy as dead_permanent
    #[serde(default = "default_max_strikes")]
    #[schema(example = 3, minimum = 1, maximum = 50, default = 3)]
    pub max_dead_strikes: u32,

    /// Time window for calculating stability percentage (in minutes, default: 5)
    #[serde(
        default = "default_stability_window_min",
        alias = "stability_window",
        alias = "window_min",
        alias = "window_minutes"
    )]
    #[schema(example = 5, minimum = 1, maximum = 1440, default = 5)]
    pub stability_window_min: u32,

    /// Exponential backoff multiplier for rechecking failed proxies in quarantine (cooldown)
    #[serde(
        default = "default_dead_backoff_mult",
        alias = "backoff_multiplier",
        alias = "recheck_dead_multiplier",
        alias = "dead_multiplier",
        alias = "recheck_dead_mult",
        alias = "multiplier"
    )]
    #[schema(example = 1.5, minimum = 1.0, maximum = 10.0, default = 1.5)]
    pub dead_backoff_mult: f32,
}

impl Default for CheckPolicyDto {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout(),
            handshake_timeout_ms: default_handshake_timeout(),
            rw_timeout_ms: default_rw_timeout(),
            recheck_alive_sec: default_recheck_alive(),
            recheck_dead_sec: default_recheck_dead(),
            max_dead_strikes: default_max_strikes(),
            stability_window_min: default_stability_window_min(),
            dead_backoff_mult: default_dead_backoff_mult(),
        }
    }
}

/// Structured proxy parameters for import
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "ip": "185.220.101.5",
    "port": 1080,
    "protocol": "socks5",
    "auth_user": "myuser",
    "auth_pass": "mypassword",
    "ignore_protocol": false
}))]
pub struct ProxyInputObject {
    /// Proxy host IP address (IPv4 or IPv6)
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub ip: String,

    /// Connection port (1..=65535)
    #[schema(example = 1080, minimum = 1, maximum = 65535)]
    pub port: u16,

    /// Expected proxy protocol (e.g., socks5, http, socks4)
    #[schema(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Username for private proxy authentication
    #[schema(example = "myuser", max_length = 128)]
    pub auth_user: Option<String>,

    /// Password for private proxy authentication
    #[schema(example = "mypassword", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Ignore specified protocol and force auto-detection cascade (SOCKS5 -> SOCKS4 -> HTTP)
    #[serde(default, alias = "ignore_type")]
    #[schema(example = false, default = false)]
    pub ignore_protocol: Option<bool>,
}

/// Item of import array: text string in any supported format or structured JSON object
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum ProxyInputItem {
    /// Text string in supported formats:
    /// - `protocol://user:pass@ip:port`
    /// - `ip:port:user:pass`
    /// - `user:pass@ip:port`
    /// - `protocol://ip:port`
    /// - `ip:port`
    /// - `[ipv6]:port`
    #[schema(example = "socks5://user:pass@185.220.101.5:1080")]
    String(String),

    /// Structured object with explicit host, port, and authentication fields
    Object(ProxyInputObject),
}

impl From<String> for ProxyInputItem {
    fn from(s: String) -> Self {
        ProxyInputItem::String(s)
    }
}

impl From<&str> for ProxyInputItem {
    fn from(s: &str) -> Self {
        ProxyInputItem::String(s.to_string())
    }
}

/// Request for batch importing raw proxy addresses
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "source": "premium_pool_v1",
    "source_url": "https://provider.example.com/api/feed.txt",
    "remark": "Primary corporate subnet proxies",
    "revive_dead": true,
    "ignore_protocol": false,
    "policy": {
        "connect_timeout_ms": 2500,
        "handshake_timeout_ms": 3500,
        "rw_timeout_ms": 4000,
        "recheck_alive_sec": 45,
        "recheck_dead_sec": 900,
        "max_dead_strikes": 3,
        "stability_window_min": 5,
        "dead_backoff_mult": 1.5
    },
    "proxies": [
        "socks5://user:pass@185.220.101.5:1080",
        "195.154.255.3:8080",
        "194.67.210.88:9050:vendor_user:vendor_pass",
        {
            "ip": "185.220.101.6",
            "port": 1080,
            "protocol": "socks5",
            "auth_user": "myuser",
            "auth_pass": "mypassword",
            "ignore_protocol": false
        }
    ]
}))]
pub struct ImportBatchRequest {
    /// Unique code name for the import source (e.g., "free_spys_ru", "vendor_pack_1")
    #[schema(example = "premium_pool_v1", min_length = 1, max_length = 128)]
    pub source: String,

    /// URL of external feed or source API (if applicable)
    #[schema(
        example = "https://provider.example.com/api/feed.txt",
        max_length = 2048
    )]
    pub source_url: Option<String>,

    /// User note or comment for the source
    #[schema(example = "Primary corporate subnet proxies", max_length = 512)]
    pub remark: Option<String>,

    /// Whether to reset failure counters and resurrect dead_permanent proxies
    #[serde(default)]
    #[schema(example = true, default = false)]
    pub revive_dead: bool,

    /// Whether to ignore provided protocol: if true, forces cascade auto-detection (SOCKS5 -> SOCKS4 -> HTTP)
    #[serde(default, alias = "ignore_type")]
    #[schema(example = false, default = false)]
    pub ignore_protocol: bool,

    /// Custom check policy for imported pool
    #[serde(default)]
    pub policy: CheckPolicyDto,

    /// Array of proxies. Supports both formatted text strings (with or without auth):
    /// - `protocol://user:pass@ip:port`
    /// - `ip:port:user:pass`
    /// - `user:pass@ip:port`
    /// - `protocol://ip:port`
    /// - `ip:port`
    /// - `[ipv6]:port`
    ///
    /// and structured JSON objects `{"ip": "...", "port": ..., "auth_user": "...", "auth_pass": "..."}`
    #[schema(example = json!(["socks5://user:pass@185.220.101.5:1080", "195.154.255.3:8080"]))]
    pub proxies: Vec<ProxyInputItem>,
}

/// Filter and pagination parameters for proxy query
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
pub struct ProxyFilterQuery {
    /// Filter by current lifecycle state
    #[param(example = "alive")]
    pub state: Option<ProxyState>,

    /// Two-letter ISO 3166-1 alpha-2 country code or comma-separated list (e.g., "DE" or "DE,NL,FR")
    #[param(example = "DE,NL,FR", min_length = 2, max_length = 128)]
    pub country: Option<String>,

    /// Exclude countries from query (comma-separated ISO 3166-1 alpha-2 codes, e.g., "RU,CN")
    #[param(example = "RU,CN", min_length = 2, max_length = 128)]
    pub exclude_country: Option<String>,

    /// Proxy network protocol (e.g., "socks5", "http", "socks4")
    #[param(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Anonymity level (elite, anonymous, transparent)
    #[param(example = "elite", max_length = 16)]
    pub anon: Option<String>,

    /// Whether proxy supports CONNECT tunneling for HTTPS
    #[param(example = true)]
    pub supports_https: Option<bool>,

    /// Filter by authentication requirement (true: private with credentials only, false: public only)
    #[param(example = false)]
    pub has_auth: Option<bool>,

    /// Maximum allowed total RTT in milliseconds
    #[param(example = 350, minimum = 1, maximum = 60000)]
    pub max_rtt: Option<u32>,

    /// Minimum uptime percentage (0.0 — 100.0)
    #[param(example = 95.0, minimum = 0.0, maximum = 100.0)]
    pub min_uptime: Option<f32>,

    /// Minimum stability percentage within rolling window of N minutes (0.0 — 100.0)
    #[param(example = 90.0, minimum = 0.0, maximum = 100.0)]
    pub min_stability: Option<f32>,

    /// Filter by stability calculation window size (in minutes)
    #[param(example = 5, minimum = 1, maximum = 1440)]
    pub stability_window_min: Option<u32>,

    /// Filter by import source name
    #[param(example = "premium_pool_v1", min_length = 1, max_length = 128)]
    pub source: Option<String>,

    /// Maximum records in response (default: 50, pass 0 for unlimited pool export for Gateway)
    #[param(example = 50, minimum = 0, maximum = 100000, default = 50)]
    pub limit: Option<u32>,

    /// Offset for pagination
    #[param(example = 0, minimum = 0, default = 0)]
    pub offset: Option<u32>,
}

/// Request to report proxy failure from client application (single or batch)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "185.220.101.5:1080:myuser:mypassword",
    "ids": ["185.220.101.5:1080:myuser:mypassword", "195.154.255.3:8080"],
    "reason": "Connection reset by peer during target handshake"
}))]
pub struct ReportFailRequest {
    /// Single proxy identifier (format: `ip:port` or `ip:port:login:pwd`)
    #[schema(example = "185.220.101.5:1080:myuser:mypassword", max_length = 256)]
    pub id: Option<String>,

    /// Array of proxy identifiers for batch failure reporting
    #[schema(example = json!(["185.220.101.5:1080:myuser:mypassword", "195.154.255.3:8080"]))]
    pub ids: Option<Vec<String>>,

    /// Reason or error message recorded by client
    #[schema(
        example = "Connection reset by peer during target handshake",
        min_length = 1,
        max_length = 1024
    )]
    pub reason: String,
}

/// Result of recording client proxy failure report
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "status": "reported",
    "affected_count": 2,
    "reported_ids": ["185.220.101.5:1080:myuser:mypassword", "195.154.255.3:8080"],
    "proxy_id": "185.220.101.5:1080:myuser:mypassword"
}))]
pub struct ReportFailResponse {
    /// Operation confirmation status
    #[schema(example = "reported", min_length = 1, max_length = 64)]
    pub status: String,

    /// Number of proxies successfully transitioned to quarantine (cooldown)
    #[schema(example = 2, minimum = 0)]
    pub affected_count: usize,

    /// Array of proxy IDs for which failure was recorded
    pub reported_ids: Vec<String>,

    /// Proxy ID (retained for backward compatibility on single requests)
    #[schema(example = "185.220.101.5:1080:myuser:mypassword")]
    pub proxy_id: Option<String>,
}

/// Request for partial proxy update
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "remark": "Reserved for scraper worker #4",
    "auth_user": "myuser",
    "auth_pass": "mypassword",
    "ignore_protocol": false,
    "force_recheck": true,
    "policy": {
        "connect_timeout_ms": 2000,
        "handshake_timeout_ms": 3000,
        "rw_timeout_ms": 4000,
        "recheck_alive_sec": 30,
        "recheck_dead_sec": 600,
        "max_dead_strikes": 2,
        "stability_window_min": 5,
        "dead_backoff_mult": 1.5
    }
}))]
pub struct PatchProxyRequest {
    /// Updated comment / note for proxy
    #[schema(example = "Reserved for scraper worker #4", max_length = 512)]
    pub remark: Option<String>,

    /// Username for private proxy authentication
    #[schema(example = "myuser", max_length = 128)]
    pub auth_user: Option<String>,

    /// Password for private proxy authentication
    #[schema(example = "mypassword", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Reset protocol to auto-detection (cascade SOCKS5 -> SOCKS4 -> HTTP)
    #[serde(default, alias = "ignore_type")]
    #[schema(example = false, default = false)]
    pub ignore_protocol: Option<bool>,

    /// Updated timeout and verification policy
    pub policy: Option<CheckPolicyDto>,

    /// Force immediate check schedule for proxy
    #[schema(example = true, default = false)]
    pub force_recheck: Option<bool>,
}

/// Result of raw proxy batch processing
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "source_id": 1,
    "total_received": 100,
    "inserted_new": 78,
    "updated_existing": 20,
    "revived": 5,
    "invalid_format": 2
}))]
pub struct ImportBatchResponse {
    /// Source primary key in database
    #[schema(example = 1, minimum = 1)]
    pub source_id: i64,

    /// Total lines/items provided in request
    #[schema(example = 100, minimum = 0)]
    pub total_received: usize,

    /// Number of new unique proxies added to queue
    #[schema(example = 78, minimum = 0)]
    pub inserted_new: usize,

    /// Number of existing proxies linked to new source
    #[schema(example = 20, minimum = 0)]
    pub updated_existing: usize,

    /// Number of revived proxies (transitioned from dead_permanent to cold_queue)
    #[schema(example = 5, minimum = 0)]
    pub revived: usize,

    /// Number of rejected lines with invalid format or bogon IP
    #[schema(example = 2, minimum = 0)]
    pub invalid_format: usize,
}

/// Concise proxy summary for query lists and selections
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "185.220.101.5:1080:user:secret123",
    "ip": "185.220.101.5",
    "port": 1080,
    "url": "socks5://user:secret123@185.220.101.5:1080",
    "protocol": "socks5",
    "has_auth": true,
    "auth_user": "user",
    "auth_pass": "secret123",
    "state": "alive",
    "supports_https": true,
    "out_ip": "185.220.101.5",
    "country": "DE",
    "asn": 24940,
    "asn_org": "Hetzner Online GmbH",
    "anon": "elite",
    "rtt_tcp_ms": 42,
    "rtt_handshake_ms": 68,
    "rtt_total_ms": 110,
    "uptime_pct": 98.5,
    "stability_pct": 100.0,
    "stability_window_min": 5,
    "checks_total": 450,
    "checks_success": 445,
    "dead_strikes": 0,
    "last_error": null,
    "remark": "High performance German node",
    "first_seen_at": 1731200000,
    "last_checked_at": 1731256800,
    "next_check_at": 1731256860
}))]
pub struct ProxyShortItem {
    /// Full unique proxy identifier (`ip:port` or `ip:port:login:pwd`)
    #[schema(
        example = "185.220.101.5:1080:user:secret123",
        min_length = 3,
        max_length = 256
    )]
    pub id: String,

    /// Proxy host IP address
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub ip: String,

    /// Connection port
    #[schema(example = 1080, minimum = 1, maximum = 65535)]
    pub port: u16,

    /// Formatted connection URL (includes credentials when present)
    #[schema(
        example = "socks5://user:secret123@185.220.101.5:1080",
        min_length = 7,
        max_length = 512
    )]
    pub url: String,

    /// Detected network protocol (socks5, socks4, http) or null if pending in cold_queue
    #[schema(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Whether credentials (username/password) are present
    #[schema(example = true)]
    pub has_auth: bool,

    /// Username for proxy authentication (if private)
    #[schema(example = "user", max_length = 128)]
    pub auth_user: Option<String>,

    /// Password for proxy authentication (if private)
    #[schema(example = "secret123", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Current lifecycle state in pool (cold_queue, alive, cooldown, dead_permanent)
    pub state: ProxyState,

    /// Whether CONNECT tunneling for HTTPS is supported
    #[schema(example = true)]
    pub supports_https: bool,

    /// Real outgoing IP address observed by verification Judge
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub out_ip: Option<String>,

    /// Two-letter ISO country code
    #[schema(example = "DE", min_length = 2, max_length = 2)]
    pub country: Option<String>,

    /// Autonomous System Number (BGP ASN)
    #[schema(example = 24940, minimum = 1)]
    pub asn: Option<u32>,

    /// Autonomous System / ISP organization name
    #[schema(example = "Hetzner Online GmbH", max_length = 256)]
    pub asn_org: Option<String>,

    /// Anonymity level: elite, anonymous, transparent, or null if pending check
    #[schema(example = "elite", max_length = 16)]
    pub anon: Option<String>,

    /// Base TCP connection latency (RTT in milliseconds)
    #[schema(example = 42, minimum = 0)]
    pub rtt_tcp_ms: Option<u32>,

    /// Protocol handshake completion latency (in milliseconds)
    #[schema(example = 68, minimum = 0)]
    pub rtt_handshake_ms: Option<u32>,

    /// Total end-to-end latency to receive judge response (in milliseconds)
    #[schema(example = 110, minimum = 0)]
    pub rtt_total_ms: Option<u32>,

    /// All-time success check rate percentage
    #[schema(example = 98.5, minimum = 0.0, maximum = 100.0)]
    pub uptime_pct: f32,

    /// Stability percentage within rolling window of N minutes (0.0 — 100.0)
    #[schema(example = 100.0, minimum = 0.0, maximum = 100.0)]
    pub stability_pct: f32,

    /// Time window for stability calculation (in minutes)
    #[schema(example = 5, minimum = 1, maximum = 1440, default = 5)]
    pub stability_window_min: u32,

    /// Total number of checks performed
    #[schema(example = 450, minimum = 0)]
    pub checks_total: u64,

    /// Number of successful checks
    #[schema(example = 445, minimum = 0)]
    pub checks_success: u64,

    /// Current consecutive failure count
    #[schema(example = 0, minimum = 0)]
    pub dead_strikes: u32,

    /// Last recorded error message (if any)
    #[schema(example = "Connection timeout after 3000ms", max_length = 1024)]
    pub last_error: Option<String>,

    /// User note / tag
    #[schema(example = "High performance German node", max_length = 512)]
    pub remark: Option<String>,

    /// Unix timestamp of initial discovery (in seconds)
    #[schema(example = 1731200000, minimum = 0)]
    pub first_seen_at: i64,

    /// Unix timestamp of last completed check (in seconds)
    #[schema(example = 1731256800, minimum = 0)]
    pub last_checked_at: Option<i64>,

    /// Unix timestamp of scheduled next check (in seconds)
    #[schema(example = 1731256860, minimum = 0)]
    pub next_check_at: i64,
}

/// Detailed proxy card with full history, metrics, and linked sources
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "185.220.101.5:1080:user:secret123",
    "ip": "185.220.101.5",
    "port": 1080,
    "url": "socks5://user:secret123@185.220.101.5:1080",
    "has_auth": true,
    "auth_user": "user",
    "auth_pass": "secret123",
    "state": "alive",
    "protocol": "socks5",
    "supports_https": true,
    "out_ip": "185.220.101.5",
    "country": "DE",
    "asn": 24940,
    "asn_org": "Hetzner Online GmbH",
    "anon": "elite",
    "metrics": {
        "rtt_tcp_ms": 42,
        "rtt_handshake_ms": 68,
        "rtt_total_ms": 110
    },
    "policy": {
        "connect_timeout_ms": 3000,
        "handshake_timeout_ms": 4000,
        "rw_timeout_ms": 5000,
        "recheck_alive_sec": 60,
        "recheck_dead_sec": 1800,
        "max_dead_strikes": 3,
        "stability_window_min": 5,
        "dead_backoff_mult": 1.5
    },
    "stats": {
        "checks_total": 450,
        "checks_success": 445,
        "uptime_pct": 98.88,
        "stability_pct": 100.0,
        "dead_strikes": 0,
        "last_error": null,
        "first_seen_at": 1731200000,
        "last_checked_at": 1731256800,
        "next_check_at": 1731256860
    },
    "meta": {
        "remark": "High performance German node",
        "sources": ["premium_pool_v1", "backup_tor_feed"]
    }
}))]
pub struct ProxyFullDetails {
    /// Full unique identifier in `ip:port` or `ip:port:login:pwd` format
    #[schema(
        example = "185.220.101.5:1080:user:secret123",
        min_length = 3,
        max_length = 256
    )]
    pub id: String,

    /// Inbound host IP address
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub ip: String,

    /// Connection port
    #[schema(example = 1080, minimum = 1, maximum = 65535)]
    pub port: u16,

    /// Formatted connection URL
    #[schema(
        example = "socks5://user:secret123@185.220.101.5:1080",
        min_length = 7,
        max_length = 512
    )]
    pub url: String,

    /// Whether credentials (username/password) are present
    #[schema(example = true)]
    pub has_auth: bool,

    /// Username for authentication
    #[schema(example = "user", max_length = 128)]
    pub auth_user: Option<String>,

    /// Password for authentication
    #[schema(example = "secret123", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Current proxy state in pool
    pub state: ProxyState,

    /// Confirmed network protocol
    #[schema(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Whether proxy supports CONNECT tunneling for HTTPS
    #[schema(example = true)]
    pub supports_https: bool,

    /// Outbound IP address observed by target servers
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub out_ip: Option<String>,

    /// Two-letter ISO country code
    #[schema(example = "DE", min_length = 2, max_length = 2)]
    pub country: Option<String>,

    /// Autonomous System Number (ASN)
    #[schema(example = 24940, minimum = 1)]
    pub asn: Option<u32>,

    /// Organization owning the Autonomous System
    #[schema(example = "Hetzner Online GmbH", max_length = 256)]
    pub asn_org: Option<String>,

    /// Anonymity level (elite, anonymous, transparent)
    #[schema(example = "elite", max_length = 16)]
    pub anon: Option<String>,

    /// Network latencies (RTT metrics)
    pub metrics: ProxyMetricsDto,

    /// Proxy check policy
    pub policy: CheckPolicyDto,

    /// Check and availability statistics
    pub stats: ProxyStatsDto,

    /// User metadata and linked sources
    pub meta: ProxyMetaDto,
}

/// Network and response latencies (RTT metrics)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "rtt_tcp_ms": 42,
    "rtt_handshake_ms": 68,
    "rtt_total_ms": 110
}))]
pub struct ProxyMetricsDto {
    /// Base TCP connect latency to proxy (ms)
    #[schema(example = 42, minimum = 0)]
    pub rtt_tcp_ms: Option<u32>,

    /// Protocol handshake latency (ms)
    #[schema(example = 68, minimum = 0)]
    pub rtt_handshake_ms: Option<u32>,

    /// Total end-to-end RTT from connect start to valid judge response (ms)
    #[schema(example = 110, minimum = 0)]
    pub rtt_total_ms: Option<u32>,
}

/// Success statistics and check timings for proxy
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "checks_total": 450,
    "checks_success": 445,
    "uptime_pct": 98.88,
    "stability_pct": 100.0,
    "dead_strikes": 0,
    "last_error": null,
    "first_seen_at": 1731200000,
    "last_checked_at": 1731256800,
    "next_check_at": 1731256860
}))]
pub struct ProxyStatsDto {
    /// Total number of checks performed
    #[schema(example = 450, minimum = 0)]
    pub checks_total: u64,

    /// Number of successful checks
    #[schema(example = 445, minimum = 0)]
    pub checks_success: u64,

    /// Uptime availability percentage
    #[schema(example = 98.88, minimum = 0.0, maximum = 100.0)]
    pub uptime_pct: f32,

    /// Stability percentage within rolling window of N minutes (0.0 — 100.0)
    #[schema(example = 100.0, minimum = 0.0, maximum = 100.0)]
    pub stability_pct: f32,

    /// Current consecutive failure count
    #[schema(example = 0, minimum = 0)]
    pub dead_strikes: u32,

    /// Last recorded error message (if any)
    #[schema(example = "Connection timeout after 3000ms", max_length = 1024)]
    pub last_error: Option<String>,

    /// Unix timestamp of first addition to system
    #[schema(example = 1731200000, minimum = 0)]
    pub first_seen_at: i64,

    /// Unix timestamp of last check
    #[schema(example = 1731256800, minimum = 0)]
    pub last_checked_at: Option<i64>,

    /// Unix timestamp of scheduled next check
    #[schema(example = 1731256860, minimum = 0)]
    pub next_check_at: i64,
}

/// Detailed information on proxy source association
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "name": "premium_pool_v1",
    "added_at": 1731200000
}))]
pub struct ProxySourceMetaDto {
    /// Source name
    #[schema(example = "premium_pool_v1")]
    pub name: String,

    /// Unix timestamp when proxy was discovered from this source
    #[schema(example = 1731200000, minimum = 0)]
    pub added_at: i64,
}

/// Metadata and association with sources
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "remark": "High performance German node",
    "sources": ["premium_pool_v1", "backup_tor_feed"],
    "source_details": [
        {"name": "premium_pool_v1", "added_at": 1731200000},
        {"name": "backup_tor_feed", "added_at": 1731210000}
    ]
}))]
pub struct ProxyMetaDto {
    /// User note / tag
    #[schema(example = "High performance German node", max_length = 512)]
    pub remark: Option<String>,

    /// List of source names where proxy was discovered
    #[schema(example = json!(["premium_pool_v1", "backup_tor_feed"]))]
    pub sources: Vec<String>,

    /// Detailed list of sources with discovery timestamps
    pub source_details: Vec<ProxySourceMetaDto>,
}

/// Quality and performance metrics for a proxy source
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": 1,
    "name": "premium_pool_v1",
    "url": "https://provider.example.com/api/feed.txt",
    "remark": "Primary corporate subnet proxies",
    "total_proxies": 1000,
    "alive_proxies": 850,
    "cold_queue_proxies": 50,
    "cooldown_proxies": 70,
    "dead_proxies": 30,
    "yield_pct": 85.0,
    "avg_rtt_ms": 145,
    "created_at": 1731200000,
    "last_added_at": 1731250000,
    "last_checked_at": 1731256800
}))]
pub struct SourceStatsItem {
    /// Source primary identifier
    #[schema(example = 1, minimum = 1)]
    pub id: i64,

    /// Unique source name
    #[schema(example = "premium_pool_v1", min_length = 1, max_length = 128)]
    pub name: String,

    /// Source feed/API URL (if configured)
    #[schema(
        example = "https://provider.example.com/api/feed.txt",
        max_length = 2048
    )]
    pub url: Option<String>,

    /// Source note/remark
    #[schema(example = "Primary corporate subnet proxies", max_length = 512)]
    pub remark: Option<String>,

    /// Total proxies associated with source
    #[schema(example = 1000, minimum = 0)]
    pub total_proxies: u64,

    /// Number of working (alive) proxies
    #[schema(example = 850, minimum = 0)]
    pub alive_proxies: u64,

    /// Number of proxies in initial cold queue
    #[schema(example = 50, minimum = 0)]
    pub cold_queue_proxies: u64,

    /// Number of quarantined proxies in cooldown
    #[schema(example = 70, minimum = 0)]
    pub cooldown_proxies: u64,

    /// Number of permanently dead proxies
    #[schema(example = 30, minimum = 0)]
    pub dead_proxies: u64,

    /// Yield percentage of alive proxies (alive / total * 100)
    #[schema(example = 85.0, minimum = 0.0, maximum = 100.0)]
    pub yield_pct: f32,

    /// Average latency (RTT) across all alive proxies of this source (ms)
    #[schema(example = 145, minimum = 0)]
    pub avg_rtt_ms: Option<u32>,

    /// Unix timestamp of source creation in database
    #[schema(example = 1731200000, minimum = 0)]
    pub created_at: i64,

    /// Unix timestamp of last proxy import into this source
    #[schema(example = 1731250000, minimum = 0)]
    pub last_added_at: Option<i64>,

    /// Unix timestamp of last check for any proxy in this source
    #[schema(example = 1731256800, minimum = 0)]
    pub last_checked_at: Option<i64>,
}

/// Proxy availability statistics by ASN / provider
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "asn": 24940,
    "asn_org": "Hetzner Online GmbH",
    "alive_count": 3200,
    "avg_rtt_ms": 85
}))]
pub struct AsnStatsDto {
    /// Autonomous System Number (ASN)
    #[schema(example = 24940, minimum = 1)]
    pub asn: u32,

    /// Autonomous System / ISP organization name
    #[schema(example = "Hetzner Online GmbH", max_length = 256)]
    pub asn_org: Option<String>,

    /// Number of alive proxies in this Autonomous System
    #[schema(example = 3200, minimum = 0)]
    pub alive_count: u64,

    /// Average total RTT for proxies in this ASN (ms)
    #[schema(example = 85, minimum = 0)]
    pub avg_rtt_ms: u32,
}

/// Pool-wide quality, latency, and capability metrics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "total_checks": 85000,
    "total_checks_success": 81500,
    "uptime_pct": 95.88,
    "avg_rtt_ms": 115,
    "avg_rtt_tcp_ms": 45,
    "avg_rtt_handshake_ms": 70,
    "supports_https_count": 7800,
    "with_auth_count": 2100,
    "no_auth_count": 6300,
    "total_sources": 12
}))]
pub struct PoolQualityDto {
    /// Total checks executed across all proxies in pool
    #[schema(example = 85000, minimum = 0)]
    pub total_checks: u64,

    /// Number of successful checks across all proxies in pool
    #[schema(example = 81500, minimum = 0)]
    pub total_checks_success: u64,

    /// Overall uptime availability percentage across pool
    #[schema(example = 95.88, minimum = 0.0, maximum = 100.0)]
    pub uptime_pct: f32,

    /// Average total latency (RTT) across all alive proxies (ms)
    #[schema(example = 115, minimum = 0)]
    pub avg_rtt_ms: Option<u32>,

    /// Average TCP SYN/SYN-ACK latency across all alive proxies (ms)
    #[schema(example = 45, minimum = 0)]
    pub avg_rtt_tcp_ms: Option<u32>,

    /// Average protocol handshake latency across all alive proxies (ms)
    #[schema(example = 70, minimum = 0)]
    pub avg_rtt_handshake_ms: Option<u32>,

    /// Number of alive proxies supporting CONNECT for HTTPS
    #[schema(example = 7800, minimum = 0)]
    pub supports_https_count: u64,

    /// Number of alive private proxies requiring authentication
    #[schema(example = 2100, minimum = 0)]
    pub with_auth_count: u64,

    /// Number of alive public proxies without authentication
    #[schema(example = 6300, minimum = 0)]
    pub no_auth_count: u64,

    /// Total registered proxy sources in system
    #[schema(example = 12, minimum = 0)]
    pub total_sources: u64,
}

/// Global system telemetry and pool statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "engine": {
        "active_workers": 128,
        "checks_per_sec": 45.2,
        "checks_completed": 15420,
        "batch_buffer_size": 15,
        "judge_healthy": true
    },
    "pool": {
        "total": 12500,
        "alive": 8400,
        "cold_queue": 1500,
        "cooldown": 1800,
        "dead_permanent": 800
    },
    "quality": {
        "total_checks": 85000,
        "total_checks_success": 81500,
        "uptime_pct": 95.88,
        "avg_rtt_ms": 115,
        "avg_rtt_tcp_ms": 45,
        "avg_rtt_handshake_ms": 70,
        "supports_https_count": 7800,
        "with_auth_count": 2100,
        "no_auth_count": 6300,
        "total_sources": 12
    },
    "by_protocol": {
        "socks5": 5200,
        "http": 3200
    },
    "by_anonymity": {
        "elite": 6800,
        "anonymous": 1400,
        "transparent": 200
    },
    "by_error": {
        "TIMEOUT_TCP": 850,
        "CONN_REFUSED": 430,
        "HANDSHAKE_TIMEOUT": 210
    },
    "top_countries": [
        {"country": "DE", "alive_count": 3200, "avg_rtt_ms": 85},
        {"country": "US", "alive_count": 2500, "avg_rtt_ms": 130},
        {"country": "NL", "alive_count": 1400, "avg_rtt_ms": 75}
    ],
    "top_asns": [
        {"asn": 24940, "asn_org": "Hetzner Online GmbH", "alive_count": 3200, "avg_rtt_ms": 85},
        {"asn": 14061, "asn_org": "DigitalOcean, LLC", "alive_count": 1500, "avg_rtt_ms": 95}
    ]
}))]
pub struct GlobalStatsResponse {
    /// Engine state and runtime metrics
    pub engine: EngineStatsDto,

    /// Distribution of proxy pool across states
    pub pool: PoolCountsDto,

    /// Pool quality, latency, and capability metrics
    pub quality: PoolQualityDto,

    /// Distribution of alive proxies by protocol (socks5, http, socks4)
    #[schema(example = json!({"socks5": 5200, "http": 3200}))]
    pub by_protocol: HashMap<String, u64>,

    /// Distribution of alive proxies by anonymity level
    #[schema(example = json!({"elite": 6800, "anonymous": 1400, "transparent": 200}))]
    pub by_anonymity: HashMap<String, u64>,

    /// Distribution of recorded check errors and failure reasons
    #[schema(example = json!({"TIMEOUT_TCP": 850, "CONN_REFUSED": 430, "HANDSHAKE_TIMEOUT": 210}))]
    pub by_error: HashMap<String, u64>,

    /// Top countries by available proxy count
    pub top_countries: Vec<CountryStatsDto>,

    /// Top ISPs / ASNs by available proxy count
    pub top_asns: Vec<AsnStatsDto>,
}

/// Performance metrics for async checker engine
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "active_workers": 128,
    "checks_per_sec": 45.2,
    "checks_completed": 15420,
    "batch_buffer_size": 15,
    "judge_healthy": true
}))]
pub struct EngineStatsDto {
    /// Number of concurrent verification workers
    #[schema(example = 128, minimum = 0)]
    pub active_workers: u32,

    /// Current verification throughput (checks per second)
    #[schema(example = 45.2, minimum = 0.0)]
    pub checks_per_sec: f32,

    /// Total checks executed by engine since service startup
    #[schema(example = 15420, minimum = 0)]
    pub checks_completed: u64,

    /// Current size of result buffer awaiting batch write to DB
    #[schema(example = 15, minimum = 0)]
    pub batch_buffer_size: usize,

    /// Availability status of default test judge server
    #[schema(example = true)]
    pub judge_healthy: bool,
}

/// Pool count breakdown by lifecycle state
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "total": 12500,
    "alive": 8400,
    "cold_queue": 1500,
    "cooldown": 1800,
    "dead_permanent": 800
}))]
pub struct PoolCountsDto {
    /// Total count of proxies across all states in database
    #[schema(example = 12500, minimum = 0)]
    pub total: u64,

    /// Count of verified working proxies ready for use
    #[schema(example = 8400, minimum = 0)]
    pub alive: u64,

    /// Count of fresh proxies pending initial verification in queue
    #[schema(example = 1500, minimum = 0)]
    pub cold_queue: u64,

    /// Count of quarantined proxies undergoing cooldown rechecks
    #[schema(example = 1800, minimum = 0)]
    pub cooldown: u64,

    /// Count of permanently dead proxies excluded from active checks
    #[schema(example = 800, minimum = 0)]
    pub dead_permanent: u64,
}

/// Proxy availability statistics by country
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "country": "DE",
    "alive_count": 3200,
    "avg_rtt_ms": 85
}))]
pub struct CountryStatsDto {
    /// Two-letter ISO country code
    #[schema(example = "DE", min_length = 2, max_length = 2)]
    pub country: String,

    /// Number of available (alive) proxies in this country
    #[schema(example = 3200, minimum = 0)]
    pub alive_count: u64,

    /// Average total RTT for proxies in this country (ms)
    #[schema(example = 85, minimum = 0)]
    pub avg_rtt_ms: u32,
}

/// Judge server status and health details
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "azenv_net",
    "name": "AZenv.net",
    "http_url": "http://azenv.net/",
    "https_url": "https://azenv.net/",
    "is_builtin": false,
    "priority": 1,
    "supports_anonymity": true,
    "enabled": true,
    "status": "healthy",
    "latency_ms": 420,
    "consecutive_failures": 0,
    "consecutive_successes": 12,
    "last_checked_at": 1794400500,
    "last_error": null
}))]
pub struct JudgeReportDto {
    /// Unique judge server identifier
    #[schema(example = "azenv_net")]
    pub id: String,

    /// Human-readable judge name
    #[schema(example = "AZenv.net")]
    pub name: String,

    /// HTTP judge endpoint
    #[schema(example = "http://azenv.net/")]
    pub http_url: String,

    /// HTTPS judge endpoint
    #[schema(example = "https://azenv.net/")]
    pub https_url: String,

    /// Whether judge is embedded locally in API instance
    #[schema(example = false)]
    pub is_builtin: bool,

    /// Selection priority (0 = primary, 1+ = fallbacks)
    #[schema(example = 1)]
    pub priority: u32,

    /// Supports header-based anonymity level detection
    #[schema(example = true)]
    pub supports_anonymity: bool,

    /// Active status in pool
    #[schema(example = true)]
    pub enabled: bool,

    /// Current health status: healthy, degraded, unhealthy, unknown
    #[schema(example = "healthy")]
    pub status: String,

    /// Response latency during latest health check (ms)
    #[schema(example = 420)]
    pub latency_ms: Option<u64>,

    /// Observed outbound checker IP address from this judge
    #[schema(example = "203.0.113.1")]
    pub observed_ip: Option<String>,

    /// Consecutive failure count
    #[schema(example = 0)]
    pub consecutive_failures: u32,

    /// Consecutive success count
    #[schema(example = 12)]
    pub consecutive_successes: u32,

    /// Last health probe Unix timestamp
    #[schema(example = 1794400500)]
    pub last_checked_at: Option<u64>,

    /// Last recorded health probe error
    pub last_error: Option<String>,
}

/// Result of judge pool health check probe
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JudgeHealthCheckResponse {
    /// Total checked judge servers count
    #[schema(example = 6)]
    pub total_judges: usize,

    /// Healthy and available judge servers count
    #[schema(example = 5)]
    pub healthy_judges: usize,

    /// Active judge ID selected by current strategy
    #[schema(example = "builtin")]
    pub active_judge: Option<String>,

    /// Detailed status list for all judge servers
    pub judges: Vec<JudgeReportDto>,
}
