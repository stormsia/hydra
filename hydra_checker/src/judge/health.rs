use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

/// Availability health status of a Judge server
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum JudgeHealthStatus {
    /// Responding quickly and returning valid payload
    Healthy,
    /// Intermittent errors or elevated latency
    Degraded,
    /// Consecutively failing probes or unreachable
    Unhealthy,
    /// Not yet probed
    #[default]
    Unknown,
}

/// Dynamic health state for a Judge endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeHealth {
    pub status: JudgeHealthStatus,
    pub last_checked_at: Option<u64>,
    pub latency_ms: Option<u64>,
    pub observed_ip: Option<IpAddr>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_error: Option<CompactString>,
}

impl JudgeHealth {
    /// Record a successful check/probe, updating latency and optional observed IP
    pub fn record_success(&mut self, latency_ms: u64, observed_ip: Option<IpAddr>) {
        self.status = JudgeHealthStatus::Healthy;
        self.consecutive_successes += 1;
        self.consecutive_failures = 0;
        self.latency_ms = Some(latency_ms);
        if observed_ip.is_some() {
            self.observed_ip = observed_ip;
        }
    }
}

impl Default for JudgeHealth {
    fn default() -> Self {
        Self {
            status: JudgeHealthStatus::Unknown,
            last_checked_at: None,
            latency_ms: None,
            observed_ip: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_error: None,
        }
    }
}

/// Comprehensive snapshot report of a judge endpoint and its health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeHealthReport {
    pub id: CompactString,
    pub name: CompactString,
    pub http_url: Url,
    pub https_url: Url,
    pub is_builtin: bool,
    pub priority: u32,
    pub supports_anonymity: bool,
    pub enabled: bool,
    pub status: JudgeHealthStatus,
    pub latency_ms: Option<u64>,
    pub observed_ip: Option<IpAddr>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_checked_at: Option<u64>,
    pub last_error: Option<CompactString>,
}
