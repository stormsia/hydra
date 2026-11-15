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
