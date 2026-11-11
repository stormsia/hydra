use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use libsql::Database;
use tokio::sync::mpsc;

use hydra_checker::CheckResult;
use crate::app_state::SchedulerStats;
use crate::services::geoip::GeoIpResult;

pub struct CheckResultWithMeta {
    pub proxy_id: String,
    pub result: CheckResult,
    pub geoip: GeoIpResult,
    pub recheck_alive_sec: u32,
    pub recheck_dead_sec: u32,
    pub max_dead_strikes: u32,
    pub current_strikes: u32,
}

pub async fn batch_writer_loop(
    mut rx: mpsc::UnboundedReceiver<CheckResultWithMeta>,
    db: Arc<Database>,
    flush_interval_ms: u64,
    stats: Arc<SchedulerStats>,
) {
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
                            flush_batch(&mut buffer, &db, &stats).await;
                        }
                    }
                    None => {
                        // Channel closed, flush remaining
                        if !buffer.is_empty() {
                            flush_batch(&mut buffer, &db, &stats).await;
                        }
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&mut buffer, &db, &stats).await;
                }
            }
        }
    }
}

pub async fn flush_batch(
    buffer: &mut Vec<CheckResultWithMeta>,
    db: &Database,
    stats: &Arc<SchedulerStats>,
) {
    if buffer.is_empty() {
        return;
    }

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

    let count = buffer.len();
    let now = Utc::now().timestamp();

    let stmt_alive = match conn
        .prepare(
            "UPDATE proxies SET
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
                last_checked_at = ?12,
                next_check_at = ?13
            WHERE id = ?1;",
        )
        .await
    {
        Ok(stmt) => stmt,
        Err(e) => {
            tracing::error!("Failed to prepare alive UPDATE statement in batch writer: {e}");
            return;
        }
    };

    let stmt_dead = match conn
        .prepare(
            "UPDATE proxies SET
                state = ?2,
                rtt_tcp_ms = ?3,
                rtt_handshake_ms = ?4,
                rtt_total_ms = ?5,
                checks_total = checks_total + 1,
                dead_strikes = ?6,
                last_error = ?7,
                last_checked_at = ?8,
                next_check_at = ?9
            WHERE id = ?1;",
        )
        .await
    {
        Ok(stmt) => stmt,
        Err(e) => {
            tracing::error!("Failed to prepare dead UPDATE statement in batch writer: {e}");
            return;
        }
    };

    if let Err(e) = conn.execute("BEGIN IMMEDIATE;", ()).await {
        tracing::error!("Failed to begin transaction in batch writer: {e}");
        return;
    }

    let mut write_err = false;

    for item in buffer.iter() {
        let cr = &item.result;
        if cr.is_alive {
            let next_check = now + item.recheck_alive_sec as i64;
            let proto = cr.detected_protocol.map(|p| p.as_str());
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
                now + item.recheck_dead_sec as i64
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
        tracing::warn!("Batch writer rolled back transaction due to errors; retaining {} items in buffer", buffer.len());
    } else if let Err(e) = conn.execute("COMMIT;", ()).await {
        let _ = conn.execute("ROLLBACK;", ()).await;
        tracing::error!("Failed to commit batch writer transaction: {e}; retaining {} items in buffer", buffer.len());
    } else {
        stats.checks_completed.fetch_add(count as u64, Ordering::Relaxed);
        buffer.clear();
    }

    stats.batch_buffer_size.store(buffer.len(), Ordering::Relaxed);
}
