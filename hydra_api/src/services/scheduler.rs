use chrono::Utc;
use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::app_state::AppState;
use crate::db::proxies::fetch_due_proxies;
use crate::models::ProxyRow;
use crate::services::batch_writer::CheckResultWithMeta;
use crate::services::geoip::GeoIpResult;
use hydra_checker::{CheckConfigOverride, CheckTarget, ProxyAuth, ProxyProtocol, TargetHost};

pub fn row_to_target(row: &ProxyRow) -> CheckTarget {
    let host = TargetHost::parse(&row.ip);
    let expected_protocol = row
        .protocol
        .as_deref()
        .and_then(|p| match p.to_lowercase().as_str() {
            "http" => Some(ProxyProtocol::Http),
            "https" => Some(ProxyProtocol::Https),
            "socks4" => Some(ProxyProtocol::Socks4),
            "socks4a" => Some(ProxyProtocol::Socks4a),
            "socks5" => Some(ProxyProtocol::Socks5),
            _ => None,
        });

    let config_override = CheckConfigOverride {
        connect_timeout: Some(Duration::from_millis(row.connect_timeout_ms as u64)),
        handshake_timeout: Some(Duration::from_millis(row.handshake_timeout_ms as u64)),
        read_write_timeout: Some(Duration::from_millis(row.rw_timeout_ms as u64)),
        ..Default::default()
    };

    let mut target = CheckTarget::new(host, row.port).with_override(config_override);
    if let Some(proto) = expected_protocol {
        target = target.with_protocol(proto);
    }
    if let (Some(u), Some(p)) = (&row.auth_user, &row.auth_pass) {
        target.auth = Some(ProxyAuth::new(u, p));
    }

    target
}

pub async fn scheduler_loop(state: AppState, cancel: CancellationToken) {
    let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let concurrency = state.config.checker_concurrency;
    let mut check_tick = tokio::time::interval(Duration::from_secs(1));
    let mut stats_tick = tokio::time::interval(Duration::from_secs(1));

    let mut last_completed_count = state
        .scheduler_stats
        .checks_completed
        .load(Ordering::Relaxed);

    loop {
        tokio::select! {
            _ = check_tick.tick() => {
                let current_in_flight = in_flight.lock().len();
                if current_in_flight >= concurrency {
                    continue;
                }
                let available_capacity = concurrency.saturating_sub(current_in_flight);

                let now = Utc::now().timestamp();
                let conn = match state.connect_db().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Scheduler failed to connect to database: {e}");
                        continue;
                    }
                };

                let batch_size = state.config.scheduler_batch_size;
                let fetch_limit = batch_size.min(available_capacity);
                let rows = match fetch_due_proxies(&conn, now, fetch_limit).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("Scheduler failed to fetch due proxies: {e}");
                        continue;
                    }
                };

                if rows.is_empty() {
                    continue;
                }

                let mut to_check = Vec::with_capacity(rows.len());
                {
                    let mut flight = in_flight.lock();
                    for row in rows {
                        if flight.insert(row.id.clone()) {
                            to_check.push(row);
                        }
                    }
                }

                if to_check.is_empty() {
                    continue;
                }

                let state_clone = state.clone();
                let in_flight_clone = Arc::clone(&in_flight);

                // Run batch checking bounded by concurrency
                tokio::spawn(async move {
                    stream::iter(to_check)
                        .for_each_concurrent(concurrency, |row| {
                            let state = state_clone.clone();
                            let in_flight = Arc::clone(&in_flight_clone);
                            async move {
                                let proxy_id = row.id.clone();
                                let target = row_to_target(&row);

                                state.scheduler_stats.active_workers.fetch_add(1, Ordering::Relaxed);
                                let result = state.engine.check_single(target).await;
                                state.scheduler_stats.active_workers.fetch_sub(1, Ordering::Relaxed);

                                in_flight.lock().remove(&proxy_id);

                                let geoip = if result.is_alive {
                                    if let Some(ext_ip) = result.external_ip {
                                        if let Some(ref g) = state.geoip {
                                            g.lookup(ext_ip)
                                        } else {
                                            GeoIpResult::default()
                                        }
                                    } else {
                                        GeoIpResult::default()
                                    }
                                } else {
                                    GeoIpResult::default()
                                };

                                let meta = CheckResultWithMeta {
                                    proxy_id,
                                    result,
                                    geoip,
                                    recheck_alive_sec: row.recheck_alive_sec,
                                    recheck_dead_sec: row.recheck_dead_sec,
                                    max_dead_strikes: row.max_dead_strikes,
                                    current_strikes: row.dead_strikes,
                                    stability_window_min: row.stability_window_min,
                                    dead_backoff_mult: row.dead_backoff_mult,
                                    recent_checks: row.recent_checks,
                                };

                                let _ = state.result_tx.send(meta);
                            }
                        })
                        .await;
                });
            }

            _ = stats_tick.tick() => {
                let current_completed = state.scheduler_stats.checks_completed.load(Ordering::Relaxed);
                let diff = current_completed.saturating_sub(last_completed_count);
                last_completed_count = current_completed;
                state.scheduler_stats.set_checks_per_sec(diff as f32);
            }

            _ = cancel.cancelled() => {
                tracing::info!("Scheduler received cancellation signal");
                break;
            }
        }
    }
}
