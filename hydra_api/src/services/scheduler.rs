use chrono::Utc;
use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::app_state::{AppState, SchedulerStats};
use crate::db::proxies::fetch_due_proxies;
use crate::models::ProxyCheckItem;
use crate::services::batch_writer::CheckResultWithMeta;
use crate::services::geoip::GeoIpResult;
use hydra_checker::{CheckConfigOverride, CheckTarget, ProxyAuth, ProxyProtocol, TargetHost};

struct WorkerGuard {
    stats: Arc<SchedulerStats>,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.stats.active_workers.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn row_to_target(row: &ProxyCheckItem) -> CheckTarget {
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
    let concurrency = state.config.checker_concurrency.max(1);
    let batch_size = state.config.scheduler_batch_size.max(1);

    // 1. Bounded MPSC channel for continuous task pipeline
    let (task_tx, task_rx) = tokio::sync::mpsc::channel::<ProxyCheckItem>(concurrency);

    // 2. Worker Pool (Consumer)
    let worker_state = state.clone();
    let worker_handle = tokio::spawn(async move {
        ReceiverStream::new(task_rx)
            .for_each_concurrent(concurrency, move |row| {
                let state = worker_state.clone();
                async move {
                    let proxy_id = row.id.clone();
                    state
                        .scheduler_stats
                        .active_workers
                        .fetch_add(1, Ordering::Relaxed);
                    let _guard = WorkerGuard {
                        stats: Arc::clone(&state.scheduler_stats),
                    };

                    let target = row_to_target(&row);
                    let result = state.engine.check_single(target).await;

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
                        max_dead_strikes_zero: row.max_dead_strikes_zero,
                        max_dead_strikes_active: row.max_dead_strikes_active,
                        current_strikes: row.dead_strikes,
                        stability_window_min: row.stability_window_min,
                        dead_backoff_mult_zero: row.dead_backoff_mult_zero,
                        dead_backoff_mult_active: row.dead_backoff_mult_active,
                        checks_success: row.checks_success,
                        recent_checks: row.recent_checks,
                    };

                    let _ = state.result_tx.send(meta);
                }
            })
            .await;
    });

    // 5. Monitoring RPS in stats_tick
    let stats_state = state.clone();
    let stats_cancel = cancel.clone();
    let stats_handle = tokio::spawn(async move {
        let mut stats_tick = tokio::time::interval(Duration::from_secs(1));
        let mut last_completed_count = stats_state
            .scheduler_stats
            .checks_completed
            .load(Ordering::Relaxed);

        loop {
            tokio::select! {
                _ = stats_cancel.cancelled() => break,
                _ = stats_tick.tick() => {
                    let current_completed = stats_state
                        .scheduler_stats
                        .checks_completed
                        .load(Ordering::Relaxed);
                    let diff = current_completed.saturating_sub(last_completed_count);
                    last_completed_count = current_completed;
                    stats_state.scheduler_stats.set_checks_per_sec(diff as f32);
                }
            }
        }
    });

    // 3. Feeder Loop (Producer)
    let mut conn = match state.connect_db().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Scheduler failed to connect to database: {e}");
            drop(task_tx);
            let _ = worker_handle.await;
            let _ = stats_handle.await;
            return;
        }
    };

    'feeder: loop {
        if cancel.is_cancelled() {
            break 'feeder;
        }

        let capacity = task_tx.capacity();
        if capacity == 0 {
            tokio::select! {
                _ = cancel.cancelled() => break 'feeder,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
            continue;
        }

        let now = Utc::now().timestamp();
        let fetch_limit = capacity.min(batch_size);
        let rows = match fetch_due_proxies(&conn, now, fetch_limit).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Scheduler failed to fetch due proxies: {e}");
                if let Ok(new_conn) = state.connect_db().await {
                    conn = new_conn;
                }
                tokio::select! {
                    _ = cancel.cancelled() => break 'feeder,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                continue;
            }
        };

        if rows.is_empty() {
            tokio::select! {
                _ = cancel.cancelled() => break 'feeder,
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
            continue;
        }

        for row in rows {
            tokio::select! {
                _ = cancel.cancelled() => break 'feeder,
                res = task_tx.send(row) => {
                    if res.is_err() {
                        break 'feeder;
                    }
                }
            }
        }
    }

    // 4. Graceful shutdown: close channel and wait for workers to drain
    tracing::info!("Scheduler feeder stopped, closing task channel and draining workers...");
    drop(task_tx);

    let _ = worker_handle.await;
    let _ = stats_handle.await;
    tracing::info!("Scheduler shutdown complete");
}
