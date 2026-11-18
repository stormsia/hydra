use compact_str::CompactString;
use serde::{Deserialize, Serialize};
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
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_error: Option<CompactString>,
}

impl Default for JudgeHealth {
    fn default() -> Self {
        Self {
            status: JudgeHealthStatus::Unknown,
            last_checked_at: None,
            latency_ms: None,
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
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_checked_at: Option<u64>,
    pub last_error: Option<CompactString>,
}
