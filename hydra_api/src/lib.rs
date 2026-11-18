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
pub use router::{ApiDoc, build_router};

/// Installs the ring-based rustls `CryptoProvider` as the process-wide default.
///
/// The workspace uses a single crypto backend (ring) across the checker, judge
/// and HTTP client. `reqwest` is built with the `rustls-no-provider` feature so
/// that it does not pull in a second provider (aws-lc-rs), which would make
/// rustls refuse to auto-select one; in that configuration reqwest requires the
/// provider to be installed explicitly before a TLS connection is made.
///
/// Calling this more than once is safe: subsequent calls are ignored.
pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Ensures that essential application directories (`data`, `geo`, and any configured database/geoip parent paths) exist.
pub fn ensure_directories(config: &ApiConfig) -> std::io::Result<()> {
    config.ensure_directories()
}
