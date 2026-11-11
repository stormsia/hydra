use std::sync::Arc;
use std::time::Duration;
use libsql::Database;
use tokio_util::sync::CancellationToken;

use crate::db::run_db_maintenance;

/// Background maintenance task that periodically cleans up aged dead proxies
/// and performs non-blocking SQLite/libSQL WAL maintenance (incremental vacuum, optimize, wal_checkpoint).
pub async fn db_maintenance_loop(
    db: Arc<Database>,
    retention_days: u32,
    interval_secs: u64,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.tick().await; // skip initial immediate tick

    tracing::info!(
        "DB maintenance loop active (interval: {}s, dead proxy retention: {} days)",
        interval_secs,
        retention_days
    );

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                tracing::debug!("Executing scheduled non-blocking DB maintenance...");
                match db.connect() {
                    Ok(conn) => {
                        if let Err(e) = crate::db::configure_conn(&conn).await {
                            tracing::warn!("Failed to configure DB connection for maintenance: {e}");
                            continue;
                        }
                        match run_db_maintenance(&conn, retention_days).await {
                            Ok(stats) => {
                                if stats.purged_dead_proxies > 0 || stats.purged_orphaned_sources > 0 {
                                    tracing::info!(
                                        "DB maintenance completed: purged {} dead proxies, {} orphaned links (WAL optimized)",
                                        stats.purged_dead_proxies,
                                        stats.purged_orphaned_sources
                                    );
                                } else {
                                    tracing::debug!("DB maintenance completed: 0 dead proxies purged, WAL & PRAGMA optimized");
                                }
                            }
                            Err(e) => {
                                tracing::warn!("DB maintenance execution failed: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to acquire DB connection for maintenance: {e}");
                    }
                }
            }
            _ = cancel.cancelled() => {
                tracing::info!("DB maintenance loop received cancellation signal, stopping...");
                break;
            }
        }
    }
}
