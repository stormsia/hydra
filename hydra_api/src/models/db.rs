use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Lifecycle state of a proxy in the pool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    /// Fresh proxy waiting for its initial check in the queue
    #[schema(rename = "cold_queue")]
    ColdQueue = 0,
    /// Verified working proxy in the active pool
    #[schema(rename = "alive")]
    Alive = 1,
    /// Temporary check failure, quarantined awaiting recheck
    #[schema(rename = "cooldown")]
    Cooldown = 2,
    /// Consecutive error threshold exceeded, permanently decommissioned
    #[schema(rename = "dead_permanent")]
    DeadPermanent = 3,
}

impl ProxyState {
    pub fn from_i64(val: i64) -> Self {
        match val {
            1 => ProxyState::Alive,
            2 => ProxyState::Cooldown,
            3 => ProxyState::DeadPermanent,
            _ => ProxyState::ColdQueue,
        }
    }

    pub fn to_i64(self) -> i64 {
        self as i64
    }
}

/// Full row representation from the `proxies` table
#[derive(Debug, Clone)]
pub struct ProxyRow {
    pub id: String, // "ip:port"
    pub ip: String,
    pub port: u16,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub state: ProxyState,
    pub protocol: Option<String>,
    pub supports_https: bool,
    pub out_ip: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub anon: Option<String>,
    pub rtt_tcp_ms: Option<u32>,
    pub rtt_handshake_ms: Option<u32>,
    pub rtt_total_ms: Option<u32>,
    pub connect_timeout_ms: u32,
    pub handshake_timeout_ms: u32,
    pub rw_timeout_ms: u32,
    pub recheck_alive_sec: u32,
    pub recheck_dead_sec: u32,
    pub max_dead_strikes: u32,
    pub stability_window_min: u32,
    pub dead_backoff_mult: f32,
    pub checks_total: u64,
    pub checks_success: u64,
    pub dead_strikes: u32,
    pub last_error: Option<String>,
    pub stability_pct: f32,
    pub recent_checks: Option<String>,
    pub remark: Option<String>,
    pub first_seen_at: i64,
    pub last_checked_at: Option<i64>,
    pub next_check_at: i64,
}

/// Row representation from the `sources` table
#[derive(Debug, Clone)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub url: Option<String>,
    pub remark: Option<String>,
    pub created_at: i64,
}

/// Lightweight proxy item fetched specifically for the scheduler check pipeline.
/// Excludes non-essential metrics and heavy metadata (country, asn_org, logs, etc.)
/// to avoid tens of thousands of redundant heap allocations per second.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyCheckItem {
    pub id: String, // "ip:port"
    pub ip: String,
    pub port: u16,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub state: ProxyState,
    pub protocol: Option<String>,
    pub connect_timeout_ms: u32,
    pub handshake_timeout_ms: u32,
    pub rw_timeout_ms: u32,
    pub recheck_alive_sec: u32,
    pub recheck_dead_sec: u32,
    pub max_dead_strikes: u32,
    pub dead_strikes: u32,
    pub stability_window_min: u32,
    pub dead_backoff_mult: f32,
    pub recent_checks: Option<String>,
    pub next_check_at: i64,
}

impl From<&ProxyRow> for ProxyCheckItem {
    fn from(row: &ProxyRow) -> Self {
        ProxyCheckItem {
            id: row.id.clone(),
            ip: row.ip.clone(),
            port: row.port,
            auth_user: row.auth_user.clone(),
            auth_pass: row.auth_pass.clone(),
            state: row.state,
            protocol: row.protocol.clone(),
            connect_timeout_ms: row.connect_timeout_ms,
            handshake_timeout_ms: row.handshake_timeout_ms,
            rw_timeout_ms: row.rw_timeout_ms,
            recheck_alive_sec: row.recheck_alive_sec,
            recheck_dead_sec: row.recheck_dead_sec,
            max_dead_strikes: row.max_dead_strikes,
            dead_strikes: row.dead_strikes,
            stability_window_min: row.stability_window_min,
            dead_backoff_mult: row.dead_backoff_mult,
            recent_checks: row.recent_checks.clone(),
            next_check_at: row.next_check_at,
        }
    }
}

