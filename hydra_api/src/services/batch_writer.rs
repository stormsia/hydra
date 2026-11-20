use chrono::Utc;
use libsql::{Connection, Database, Statement};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::app_state::SchedulerStats;
use crate::services::geoip::GeoIpResult;
use hydra_checker::CheckResult;

pub struct CheckResultWithMeta {
    pub proxy_id: String,
    pub result: CheckResult,
    pub geoip: GeoIpResult,
    pub recheck_alive_sec: u32,
    pub recheck_dead_sec: u32,
    pub max_dead_strikes: u32,
    pub current_strikes: u32,
    pub stability_window_min: u32,
    pub dead_backoff_mult: f32,
    pub recent_checks: Option<String>,
}

pub const UPDATE_ALIVE_SQL: &str = "UPDATE proxies SET
    state = 1,
    protocol = ?2,
    supports_https = ?3,
    out_ip = ?4,
    country = ?5,
    asn = ?6,
    asn_org = ?7,
    anon = ?8,
    rtt_tcp_ms = ?9,
    rtt_handshake_ms = ?10,
    rtt_total_ms = ?11,
    checks_total = checks_total + 1,
    checks_success = checks_success + 1,
    dead_strikes = 0,
    last_error = NULL,
    stability_pct = ?12,
    recent_checks = ?13,
    last_checked_at = ?14,
    next_check_at = ?15
WHERE id = ?1;";

pub const UPDATE_DEAD_SQL: &str = "UPDATE proxies SET
    state = ?2,
    rtt_tcp_ms = ?3,
    rtt_handshake_ms = ?4,
    rtt_total_ms = ?5,
    checks_total = checks_total + 1,
    dead_strikes = ?6,
    last_error = ?7,
    stability_pct = ?8,
    recent_checks = ?9,
    last_checked_at = ?10,
    next_check_at = ?11
WHERE id = ?1;";

pub async fn prepare_batch_statements(
    conn: &Connection,
) -> Result<(Statement, Statement), libsql::Error> {
    let stmt_alive = conn.prepare(UPDATE_ALIVE_SQL).await?;
    let stmt_dead = conn.prepare(UPDATE_DEAD_SQL).await?;
    Ok((stmt_alive, stmt_dead))
}

/// Calculates the next check Unix timestamp for a failed proxy using exponential backoff.
///
/// For the first failure (new_strikes = 1), the delay equals the base `recheck_dead_sec`.
/// For each consecutive failure, delay is multiplied by `dead_backoff_mult` (e.g., 1.5 or 2.0).
/// If `dead_backoff_mult <= 1.0`, the delay remains constant.
pub fn calculate_dead_next_check(
    now: i64,
    recheck_dead_sec: u32,
    dead_backoff_mult: f32,
    new_strikes: u32,
) -> i64 {
    if recheck_dead_sec == 0 {
        return now + 365 * 86400;
    }
    let mult = (dead_backoff_mult as f64).max(1.0);
    let exponent = new_strikes.saturating_sub(1) as i32;
    let delay_sec = ((recheck_dead_sec as f64) * mult.powi(exponent)).round() as i64;
    let capped_delay = delay_sec.clamp(1, 30 * 86400);
    now + capped_delay
}

/// Computes updated check history and stability percentage within a rolling window of N minutes.
///
/// Records are compactly encoded: "ts:status,ts:status" (where 1 = success, 0 = failure).
/// Records older than `(now - window_min * 60)` are automatically pruned as the window shifts.
pub fn update_recent_checks(
    raw: Option<&str>,
    is_alive: bool,
    now: i64,
    window_min: u32,
) -> (String, f32) {
    let window_sec = (window_min.max(1) as i64) * 60;
    let cutoff = now - window_sec;

    let mut checks: Vec<(i64, bool)> = Vec::new();
    if let Some(s) = raw {
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((ts_str, ok_str)) = part.split_once(':')
                && let (Ok(ts), Ok(ok_num)) = (ts_str.parse::<i64>(), ok_str.parse::<u8>())
                && ts >= cutoff
            {
                checks.push((ts, ok_num == 1));
            }
        }
    }

    checks.push((now, is_alive));

    let total = checks.len();
    let success = checks.iter().filter(|(_, ok)| *ok).count();
    let pct = if total > 0 {
        (success as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    let serialized = checks
        .iter()
        .map(|(ts, ok)| format!("{}:{}", ts, if *ok { 1 } else { 0 }))
        .collect::<Vec<_>>()
        .join(",");

    (serialized, pct)
}

pub async fn batch_writer_loop(
    mut rx: mpsc::UnboundedReceiver<CheckResultWithMeta>,
    db: Arc<Database>,
    flush_interval_ms: u64,
    stats: Arc<SchedulerStats>,
) {
    let conn = match db.connect() {
        Ok(c) => {
            if let Err(e) = crate::db::configure_conn(&c).await {
                tracing::error!("Failed to configure connection in batch writer: {e}");
                return;
            }
            c
        }
        Err(e) => {
            tracing::error!("Failed to connect to database in batch writer: {e}");
            return;
        }
    };

    let (mut stmt_alive, mut stmt_dead) = match prepare_batch_statements(&conn).await {
        Ok(stmts) => stmts,
        Err(e) => {
            tracing::error!("Failed to prepare statements in batch writer: {e}");
            return;
        }
    };

    let mut buffer: Vec<CheckResultWithMeta> = Vec::with_capacity(2000);
    let mut interval = tokio::time::interval(Duration::from_millis(flush_interval_ms));

    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some(result) => {
                        buffer.push(result);
                        stats.batch_buffer_size.store(buffer.len(), Ordering::Relaxed);
                        if buffer.len() >= 2000 {
                            flush_batch(&mut buffer, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;
                        }
                    }
                    None => {
                        // Channel closed, flush remaining
                        if !buffer.is_empty() {
                            flush_batch(&mut buffer, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;
                        }
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&mut buffer, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;
                }
            }
        }
    }
}

pub async fn flush_batch(
    buffer: &mut Vec<CheckResultWithMeta>,
    conn: &Connection,
    stmt_alive: &mut Statement,
    stmt_dead: &mut Statement,
    stats: &Arc<SchedulerStats>,
) {
    if buffer.is_empty() {
        return;
    }

    let count = buffer.len();
    let now = Utc::now().timestamp();

    if let Err(e) = conn.execute("BEGIN IMMEDIATE;", ()).await {
        tracing::error!("Failed to begin transaction in batch writer: {e}");
        return;
    }

    let mut write_err = false;

    for item in buffer.iter() {
        let cr = &item.result;
        let (new_recent_checks, stability_pct) = update_recent_checks(
            item.recent_checks.as_deref(),
            cr.is_alive,
            now,
            item.stability_window_min,
        );

        if cr.is_alive {
            let next_check = now + (item.recheck_alive_sec as i64).max(1);
            let proto = cr.detected_protocol.map(|p| p.as_str()).unwrap_or("http");
            let anon = cr.anonymity_level.map(|a| a.as_str());
            let out_ip = cr.external_ip.map(|ip| ip.to_string());
            let supports_https = if cr.supports_https { 1i64 } else { 0i64 };
            let rtt_tcp = cr.metrics.tcp_connect_rtt_ms as i64;
            let rtt_hs = cr.metrics.handshake_rtt_ms as i64;
            let rtt_total = cr.metrics.total_rtt_ms as i64;
            let asn = item.geoip.asn.map(|v| v as i64);

            stmt_alive.reset();
            let res = stmt_alive
                .execute(libsql::params![
                    item.proxy_id.as_str(),
                    proto,
                    supports_https,
                    out_ip,
                    item.geoip.country.as_deref(),
                    asn,
                    item.geoip.asn_org.as_deref(),
                    anon,
                    rtt_tcp,
                    rtt_hs,
                    rtt_total,
                    stability_pct as f64,
                    new_recent_checks.as_str(),
                    now,
                    next_check,
                ])
                .await;
            stmt_alive.reset();

            if let Err(e) = res {
                tracing::error!("Error updating alive proxy {}: {e}", item.proxy_id);
                write_err = true;
                break;
            }
        } else {
            let new_strikes = item.current_strikes + 1;
            let is_permanent = new_strikes >= item.max_dead_strikes || item.recheck_dead_sec == 0;
            let new_state = if is_permanent { 3i64 } else { 2i64 };
            let next_check = if is_permanent {
                now + 365 * 86400
            } else {
                calculate_dead_next_check(
                    now,
                    item.recheck_dead_sec,
                    item.dead_backoff_mult,
                    new_strikes,
                )
            };

            let err_str = cr.error_reason.map(|r| r.as_str());
            let rtt_tcp = cr.metrics.tcp_connect_rtt_ms as i64;
            let rtt_hs = cr.metrics.handshake_rtt_ms as i64;
            let rtt_total = cr.metrics.total_rtt_ms as i64;

            stmt_dead.reset();
            let res = stmt_dead
                .execute(libsql::params![
                    item.proxy_id.as_str(),
                    new_state,
                    rtt_tcp,
                    rtt_hs,
                    rtt_total,
                    new_strikes as i64,
                    err_str,
                    stability_pct as f64,
                    new_recent_checks.as_str(),
                    now,
                    next_check,
                ])
                .await;
            stmt_dead.reset();

            if let Err(e) = res {
                tracing::error!("Error updating dead proxy {}: {e}", item.proxy_id);
                write_err = true;
                break;
            }
        }
    }

    if write_err {
        let _ = conn.execute("ROLLBACK;", ()).await;
        tracing::warn!(
            "Batch writer rolled back transaction due to errors; retaining {} items in buffer",
            buffer.len()
        );
    } else if let Err(e) = conn.execute("COMMIT;", ()).await {
        let _ = conn.execute("ROLLBACK;", ()).await;
        tracing::error!(
            "Failed to commit batch writer transaction: {e}; retaining {} items in buffer",
            buffer.len()
        );
    } else {
        stats
            .checks_completed
            .fetch_add(count as u64, Ordering::Relaxed);
        buffer.clear();
    }

    stats
        .batch_buffer_size
        .store(buffer.len(), Ordering::Relaxed);
}
