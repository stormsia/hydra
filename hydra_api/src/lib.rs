pub mod app_state;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod router;
pub mod services;

pub use app_state::{AppState, SchedulerStats};
pub use config::ApiConfig;
pub use error::ApiError;
pub use router::{build_router, ApiDoc};

/// Ensures that essential application directories (`data`, `geo`, and any configured database/geoip parent paths) exist.
pub fn ensure_directories(config: &ApiConfig) -> std::io::Result<()> {
    config.ensure_directories()
}
