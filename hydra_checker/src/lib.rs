//! # Hydra Proxy Checker Core
//!
//! An ultra-high-performance, production-grade standalone proxy checking library in Rust.
//! Designed for validating millions of proxies with fail-fast cascade pipelines,
//! zero FD leaks, lock-free TLS, bounded concurrency, and deterministic error codes.

pub mod config;
pub mod engine;
pub mod error;
pub mod judge;
pub mod models;
pub mod net_filter;
pub mod pipeline;
pub mod pool;
pub mod protocols;
pub mod token;
pub mod transport;

// Re-exports for convenient public API
pub use config::{CheckerConfig, CheckerConfigBuilder};
pub use engine::CheckerEngine;
pub use error::{CheckerError, ErrorReason};
pub use judge::{
    JudgeEndpoint, JudgeHealth, JudgeHealthReport, JudgeHealthStatus, JudgePayload, JudgePool,
    JudgeSelectionStrategy, parse_judge_response, probe_judge_endpoint,
};
pub use models::{
    AnonymityLevel, CheckConfigOverride, CheckMetrics, CheckResult, CheckTarget, ProxyAuth,
    ProxyProtocol, TargetHost,
};
pub use token::DailyTokenProvider;
pub use transport::mock::MockDialer;
pub use transport::tcp::TcpDialer;
pub use transport::{Dialer, PrefixedStream};
