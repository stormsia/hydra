use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use libsql::Database;
use tokio::sync::mpsc;
use hydra_checker::CheckerEngine;

use crate::config::ApiConfig;
use crate::services::batch_writer::CheckResultWithMeta;
use crate::services::geoip::GeoIpResolver;

pub struct SchedulerStats {
    pub active_workers: AtomicU32,
    pub checks_completed: AtomicU64,
    pub checks_per_sec_x100: AtomicU32,
    pub batch_buffer_size: AtomicUsize,
    pub judge_healthy: AtomicBool,
}

impl Default for SchedulerStats {
    fn default() -> Self {
        Self {
            active_workers: AtomicU32::new(0),
            checks_completed: AtomicU64::new(0),
            checks_per_sec_x100: AtomicU32::new(0),
            batch_buffer_size: AtomicUsize::new(0),
            judge_healthy: AtomicBool::new(true),
        }
    }
}

impl SchedulerStats {
    pub fn get_checks_per_sec(&self) -> f32 {
        self.checks_per_sec_x100.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_checks_per_sec(&self, cps: f32) {
        self.checks_per_sec_x100.store((cps * 100.0) as u32, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ApiConfig>,
    pub db: Arc<Database>,
    pub engine: Arc<CheckerEngine>,
    pub geoip: Option<Arc<GeoIpResolver>>,
    pub result_tx: mpsc::UnboundedSender<CheckResultWithMeta>,
    pub scheduler_stats: Arc<SchedulerStats>,
}

impl AppState {
    pub async fn connect_db(&self) -> Result<libsql::Connection, crate::error::ApiError> {
        let conn = self.db.connect().map_err(crate::error::ApiError::from)?;
        crate::db::configure_conn(&conn)
            .await
            .map_err(crate::error::ApiError::from)?;
        Ok(conn)
    }
}
