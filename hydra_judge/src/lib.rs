//! # Hydra Judge - Authorized Echo Server
//!
//! An ultra-high-performance, lightweight reference echo server for proxy verification.
//! Designed for high concurrency, zero kernel socket leaks (`SO_LINGER=0`),
//! fast AZenv and JSON header reflection, and instant scanner rejection (Anti-Abuse Token Guard).

pub mod config;
pub mod error;
pub mod formatters;
pub mod metrics;
pub mod server;
pub mod tls;
pub mod token;

pub use config::{JudgeConfig, JudgeConfigBuilder, ResponseFormat, UnauthorizedAction};
pub use error::JudgeError;
pub use metrics::JudgeMetrics;
pub use server::JudgeServer;
pub use token::DailyTokenProvider;
