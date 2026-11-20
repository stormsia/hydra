use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use super::endpoint::JudgeEndpoint;
use super::health::{JudgeHealth, JudgeHealthReport, JudgeHealthStatus};
use super::host_identity::HostIdentity;
use super::probe::probe_judge_endpoint_with_bind;

fn current_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Strategy for distributing checks among available healthy judges
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JudgeSelectionStrategy {
    /// Pick the healthy judge with the lowest measured latency (RTT) from probes
    #[default]
    LowestLatency,
    /// Always pick the highest priority healthy judge; fallback only on failure/downtime
    Priority,
    /// Distribute requests round-robin across all currently healthy judges
    RoundRobin,
}

#[derive(Debug)]
pub struct JudgeEntry {
    pub endpoint: JudgeEndpoint,
    pub health: RwLock<JudgeHealth>,
}

impl JudgeEntry {
    pub fn new(endpoint: JudgeEndpoint) -> Self {
        Self {
            endpoint,
            health: RwLock::new(JudgeHealth::default()),
        }
    }
}

/// Dynamic pool of Judge endpoints with live health tracking, priority fallback, and failover
#[derive(Debug)]
pub struct JudgePool {
    entries: RwLock<Vec<Arc<JudgeEntry>>>,
    strategy: JudgeSelectionStrategy,
    round_robin_counter: AtomicUsize,
    strike_limit: u32,
    discovered_identity: Arc<arc_swap::ArcSwap<HostIdentity>>,
    discovered_ip: Arc<arc_swap::ArcSwapOption<IpAddr>>,
    local_bind_ip: RwLock<Option<IpAddr>>,
}

impl JudgePool {
    /// Create a new pool with a builtin judge and optional third-party fallback judges
    pub fn new(
        builtin: JudgeEndpoint,
        third_party: Vec<JudgeEndpoint>,
        strategy: JudgeSelectionStrategy,
    ) -> Self {
        let mut list = Vec::with_capacity(1 + third_party.len());
        list.push(Arc::new(JudgeEntry::new(builtin)));
        for ep in third_party {
            list.push(Arc::new(JudgeEntry::new(ep)));
        }

        let initial_identity = HostIdentity::from_local_interfaces();
        let initial_ip = initial_identity.primary_ip();

        Self {
            entries: RwLock::new(list),
            strategy,
            round_robin_counter: AtomicUsize::new(0),
            strike_limit: 2,
            discovered_identity: Arc::new(arc_swap::ArcSwap::from_pointee(initial_identity)),
            discovered_ip: Arc::new(arc_swap::ArcSwapOption::new(initial_ip.map(Arc::new))),
            local_bind_ip: RwLock::new(None),
        }
    }

    /// Create from arbitrary list of endpoints
    pub fn from_endpoints(endpoints: Vec<JudgeEndpoint>, strategy: JudgeSelectionStrategy) -> Self {
        let entries = endpoints
            .into_iter()
            .map(|ep| Arc::new(JudgeEntry::new(ep)))
            .collect();

        let initial_identity = HostIdentity::from_local_interfaces();
        let initial_ip = initial_identity.primary_ip();

        Self {
            entries: RwLock::new(entries),
            strategy,
            round_robin_counter: AtomicUsize::new(0),
            strike_limit: 2,
            discovered_identity: Arc::new(arc_swap::ArcSwap::from_pointee(initial_identity)),
            discovered_ip: Arc::new(arc_swap::ArcSwapOption::new(initial_ip.map(Arc::new))),
            local_bind_ip: RwLock::new(None),
        }
    }

    /// Configure local socket bind interface for judge availability probes
    pub fn set_local_bind_ip(&self, bind_ip: Option<IpAddr>) {
        let mut guard = self.local_bind_ip.write().unwrap();
        *guard = bind_ip;
    }

    /// Add a new judge to the pool
    pub fn add_judge(&self, endpoint: JudgeEndpoint) {
        let mut guard = self.entries.write().unwrap();
        // Replace if already exists with same ID
        if let Some(pos) = guard.iter().position(|e| e.endpoint.id == endpoint.id) {
            guard[pos] = Arc::new(JudgeEntry::new(endpoint));
        } else {
            guard.push(Arc::new(JudgeEntry::new(endpoint)));
        }
    }

    /// Select the primary judge for a check based on the active strategy
    pub fn select_judge(&self) -> Option<JudgeEndpoint> {
        let entries = self.entries.read().unwrap();
        let enabled: Vec<&Arc<JudgeEntry>> =
            entries.iter().filter(|e| e.endpoint.enabled).collect();
        if enabled.is_empty() {
            return None;
        }

        match self.strategy {
            JudgeSelectionStrategy::LowestLatency => {
                let mut healthy: Vec<(&Arc<JudgeEntry>, u64)> = Vec::new();
                let mut non_unhealthy: Vec<(&Arc<JudgeEntry>, u64)> = Vec::new();

                for entry in &enabled {
                    let health = entry.health.read().unwrap();
                    let lat = health.latency_ms.unwrap_or(u64::MAX);
                    if health.status == JudgeHealthStatus::Healthy {
                        healthy.push((entry, lat));
                    } else if health.status != JudgeHealthStatus::Unhealthy {
                        non_unhealthy.push((entry, lat));
                    }
                }

                if !healthy.is_empty() {
                    healthy.sort_by(|a, b| {
                        a.1.cmp(&b.1)
                            .then_with(|| a.0.endpoint.priority.cmp(&b.0.endpoint.priority))
                    });
                    return Some(healthy[0].0.endpoint.clone());
                }

                if !non_unhealthy.is_empty() {
                    non_unhealthy.sort_by(|a, b| {
                        a.1.cmp(&b.1)
                            .then_with(|| a.0.endpoint.priority.cmp(&b.0.endpoint.priority))
                    });
                    return Some(non_unhealthy[0].0.endpoint.clone());
                }

                // Fallback to lowest priority number if all are unhealthy
                let mut sorted = enabled.clone();
                sorted.sort_by_key(|e| e.endpoint.priority);
                sorted.first().map(|e| e.endpoint.clone())
            }
            JudgeSelectionStrategy::Priority => {
                let mut sorted = enabled.clone();
                sorted.sort_by_key(|e| e.endpoint.priority);

                // 1. Prefer Healthy judges in priority order
                for entry in &sorted {
                    let status = entry.health.read().unwrap().status;
                    if status == JudgeHealthStatus::Healthy {
                        return Some(entry.endpoint.clone());
                    }
                }

                // 2. Fall back to any non-unhealthy judges (Unknown / Degraded) in priority order
                for entry in &sorted {
                    let status = entry.health.read().unwrap().status;
                    if status != JudgeHealthStatus::Unhealthy {
                        return Some(entry.endpoint.clone());
                    }
                }

                // 3. If all are marked Unhealthy, fallback to the lowest priority number anyway
                sorted.first().map(|e| e.endpoint.clone())
            }
            JudgeSelectionStrategy::RoundRobin => {
                let healthy: Vec<&Arc<JudgeEntry>> = enabled
                    .iter()
                    .copied()
                    .filter(|e| e.health.read().unwrap().status != JudgeHealthStatus::Unhealthy)
                    .collect();

                let pool = if !healthy.is_empty() {
                    healthy
                } else {
                    enabled
                };
                let idx = self.round_robin_counter.fetch_add(1, Ordering::Relaxed) % pool.len();
                Some(pool[idx].endpoint.clone())
            }
        }
    }

    /// Return all other available judges sorted by priority, excluding `exclude_id`
    pub fn fallback_judges(&self, exclude_id: &str) -> Vec<JudgeEndpoint> {
        let entries = self.entries.read().unwrap();
        let mut candidates: Vec<&Arc<JudgeEntry>> = entries
            .iter()
            .filter(|e| e.endpoint.enabled && e.endpoint.id != exclude_id)
            .collect();

        if self.strategy == JudgeSelectionStrategy::LowestLatency {
            let mut healthy_with_lat: Vec<(JudgeEndpoint, u64)> = Vec::new();
            let mut degraded_or_unhealthy: Vec<JudgeEndpoint> = Vec::new();

            for entry in &candidates {
                let health = entry.health.read().unwrap();
                let lat = health.latency_ms.unwrap_or(u64::MAX);
                if health.status == JudgeHealthStatus::Healthy {
                    healthy_with_lat.push((entry.endpoint.clone(), lat));
                } else {
                    degraded_or_unhealthy.push(entry.endpoint.clone());
                }
            }

            healthy_with_lat
                .sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.priority.cmp(&b.0.priority)));
            let mut result: Vec<JudgeEndpoint> =
                healthy_with_lat.into_iter().map(|(ep, _)| ep).collect();
            result.extend(degraded_or_unhealthy);
            return result;
        }

        candidates.sort_by_key(|e| e.endpoint.priority);

        // Separate healthy from unhealthy
        let mut healthy = Vec::new();
        let mut degraded_or_unhealthy = Vec::new();

        for entry in &candidates {
            let status = entry.health.read().unwrap().status;
            if status != JudgeHealthStatus::Unhealthy {
                healthy.push(entry.endpoint.clone());
            } else {
                degraded_or_unhealthy.push(entry.endpoint.clone());
            }
        }

        // Return healthy candidates first, then degraded
        healthy.extend(degraded_or_unhealthy);
        healthy
    }

    /// Record a successful check for a judge
    pub fn record_success(&self, id: &str, latency_ms: u64, observed_ip: Option<IpAddr>) {
        let entries = self.entries.read().unwrap();
        if let Some(entry) = entries.iter().find(|e| e.endpoint.id == id) {
            let mut health = entry.health.write().unwrap();
            health.record_success(latency_ms, observed_ip);
            health.last_checked_at = Some(current_unix_sec());
        }
    }

    /// Record a failed check for a judge
    pub fn record_failure(&self, id: &str, error: &str) {
        let entries = self.entries.read().unwrap();
        if let Some(entry) = entries.iter().find(|e| e.endpoint.id == id) {
            let mut health = entry.health.write().unwrap();
            health.consecutive_failures += 1;
            health.consecutive_successes = 0;
            if health.consecutive_failures >= self.strike_limit {
                health.status = JudgeHealthStatus::Unhealthy;
            } else {
                health.status = JudgeHealthStatus::Degraded;
            }
            health.last_error = Some(CompactString::new(error));
            health.last_checked_at = Some(current_unix_sec());
        }
    }

    /// Probe availability of all registered judges concurrently and update their status
    pub async fn check_availability_all(
        &self,
        timeout: Duration,
        tls_connector: &TlsConnector,
    ) -> Vec<JudgeHealthReport> {
        let entries_snapshot: Vec<Arc<JudgeEntry>> = {
            let guard = self.entries.read().unwrap();
            guard.clone()
        };

        let bind_ip = *self.local_bind_ip.read().unwrap();
        let mut probe_futures = Vec::with_capacity(entries_snapshot.len());

        for entry in &entries_snapshot {
            if !entry.endpoint.enabled {
                continue;
            }
            let ep = entry.endpoint.clone();
            let tls = tls_connector.clone();
            probe_futures.push(async move {
                let res = probe_judge_endpoint_with_bind(&ep, timeout, &tls, bind_ip).await;
                (ep.id, res)
            });
        }

        let results = futures::future::join_all(probe_futures).await;

        for (id, res) in results {
            match res {
                Ok(output) => self.record_success(&id, output.latency_ms, output.observed_ip),
                Err(err) => self.record_failure(&id, &err),
            }
        }

        let reports = self.get_health_reports();

        // 1. Harvest discovered public IPs and subnets from all healthy judges
        let harvested = harvest_discovered_identity(&reports);

        // 2. Merge harvested IPs with our current identity (which includes local interfaces)
        let current_id = self.discovered_identity.load();
        let mut updated_identity = (**current_id).clone();
        updated_identity.merge(&harvested);

        // 3. For backward compatibility with tests and scalar real_ip:
        if let Some(consensus_ip) = resolve_consensus_ip(&reports) {
            updated_identity.add_ip(consensus_ip);
            self.discovered_ip.store(Some(Arc::new(consensus_ip)));
        } else if let Some(primary) = updated_identity.primary_ip() {
            self.discovered_ip.store(Some(Arc::new(primary)));
        }

        self.discovered_identity.store(Arc::new(updated_identity));
        reports
    }

    /// Export current snapshot of all judges and their live health telemetry
    pub fn get_health_reports(&self) -> Vec<JudgeHealthReport> {
        let entries = self.entries.read().unwrap();
        let mut reports = Vec::with_capacity(entries.len());

        for entry in entries.iter() {
            let h = entry.health.read().unwrap();
            reports.push(JudgeHealthReport {
                id: entry.endpoint.id.clone(),
                name: entry.endpoint.name.clone(),
                http_url: entry.endpoint.http_url.clone(),
                https_url: entry.endpoint.https_url.clone(),
                is_builtin: entry.endpoint.is_builtin,
                priority: entry.endpoint.priority,
                supports_anonymity: entry.endpoint.supports_anonymity,
                enabled: entry.endpoint.enabled,
                status: h.status,
                latency_ms: h.latency_ms,
                observed_ip: h.observed_ip,
                consecutive_failures: h.consecutive_failures,
                consecutive_successes: h.consecutive_successes,
                last_checked_at: h.last_checked_at,
                last_error: h.last_error.clone(),
            });
        }

        reports.sort_by_key(|r| r.priority);
        reports
    }

    /// Returns the currently discovered host identity (interfaces + judge probes)
    pub fn discovered_identity(&self) -> Arc<HostIdentity> {
        self.discovered_identity.load_full()
    }

    /// Provides shared handle to the atomic ArcSwap holding the dynamic HostIdentity
    pub fn discovered_identity_handle(&self) -> Arc<arc_swap::ArcSwap<HostIdentity>> {
        self.discovered_identity.clone()
    }

    /// Returns the currently discovered public IP resolved by judge consensus (legacy fallback)
    pub fn discovered_ip(&self) -> Option<IpAddr> {
        self.discovered_ip
            .load()
            .as_ref()
            .map(|arc| **arc)
            .or_else(|| self.discovered_identity.load().primary_ip())
    }

    /// Provides shared handle to the atomic ArcSwapOption holding the dynamic IP
    pub fn discovered_ip_handle(&self) -> Arc<arc_swap::ArcSwapOption<IpAddr>> {
        self.discovered_ip.clone()
    }

    /// Check if there is at least one healthy and enabled judge in the pool
    pub fn has_healthy_judges(&self) -> bool {
        let entries = self.entries.read().unwrap();
        entries.iter().any(|e| {
            e.endpoint.enabled && e.health.read().unwrap().status == JudgeHealthStatus::Healthy
        })
    }

    /// Check if there is at least one enabled judge in the pool
    pub fn has_enabled_judges(&self) -> bool {
        let entries = self.entries.read().unwrap();
        entries.iter().any(|e| e.endpoint.enabled)
    }

    /// Background loop that periodically probes all judges and updates their availability
    pub async fn start_health_check_loop(
        self: Arc<Self>,
        interval: Duration,
        tls_connector: Arc<TlsConnector>,
        cancel: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval(interval);
        // Skip first immediate tick since startup probe typically precedes the loop
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let _ = self.check_availability_all(Duration::from_secs(5), &tls_connector).await;
                }
                _ = cancel.cancelled() => {
                    break;
                }
            }
        }
    }
}

/// Consensually resolves the caller's outbound public IP from judge health check reports.
///
/// Discards bogon, private LAN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback
/// (127.0.0.1 from local JudgeServer), and reserved IP addresses.
///
/// Counts frequency across the remaining valid public IPs (majority vote) and returns
/// the most frequently observed IP. In case of a tie in frequency, selects the IP
/// reported by the judge with the highest priority (lowest priority numeric value).
pub fn resolve_consensus_ip(reports: &[JudgeHealthReport]) -> Option<IpAddr> {
    let mut ip_stats: HashMap<IpAddr, (usize, u32)> = HashMap::new();

    for r in reports {
        if let Some(ip) = r.observed_ip {
            let is_bogon = match ip {
                IpAddr::V4(v4) => crate::net_filter::is_bogon_or_reserved_v4(v4),
                IpAddr::V6(v6) => crate::net_filter::is_bogon_or_reserved_v6(v6),
            };
            if !is_bogon {
                let entry = ip_stats.entry(ip).or_insert((0, r.priority));
                entry.0 += 1;
                if r.priority < entry.1 {
                    entry.1 = r.priority;
                }
            }
        }
    }

    ip_stats
        .into_iter()
        .max_by(|(ip_a, (count_a, prio_a)), (ip_b, (count_b, prio_b))| {
            count_a
                .cmp(count_b)
                // When counts are equal, smaller priority number is better
                .then_with(|| prio_b.cmp(prio_a))
                // Deterministic tie-breaker
                .then_with(|| ip_a.cmp(ip_b))
        })
        .map(|(ip, _)| ip)
}

/// Harvests all distinct public IPv4 and IPv6 addresses observed from judges,
/// along with /64 IPv6 subnets, discarding bogons and private LAN addresses.
pub fn harvest_discovered_identity(reports: &[JudgeHealthReport]) -> HostIdentity {
    let mut id = HostIdentity::new();
    for r in reports {
        if let Some(ip) = r.observed_ip {
            let is_bogon = match ip {
                IpAddr::V4(v4) => crate::net_filter::is_bogon_or_reserved_v4(v4),
                IpAddr::V6(v6) => crate::net_filter::is_bogon_or_reserved_v6(v6),
            };
            if !is_bogon {
                id.add_ip(ip);
            }
        }
    }
    id
}
