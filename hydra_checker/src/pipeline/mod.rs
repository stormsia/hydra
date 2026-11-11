use std::time::Instant;
use tokio_rustls::TlsConnector;

use crate::config::CheckerConfig;
use crate::models::{CheckMetrics, CheckResult, CheckTarget};
use crate::pipeline::handshake::execute_handshake_cascade;
use crate::pipeline::l4_probe::execute_l4_probe;
use crate::transport::Dialer;

pub mod handshake;
pub mod l4_probe;
pub mod l7_judge;

/// Execute the complete 3-stage validation pipeline on a single proxy candidate
pub async fn execute_pipeline<D: Dialer>(
    dialer: &D,
    target: CheckTarget,
    config: &CheckerConfig,
    tls_connector: &TlsConnector,
) -> CheckResult {
    let check_start = Instant::now();
    let mut metrics = CheckMetrics::default();

    let connect_timeout = target
        .config_override
        .as_ref()
        .and_then(|o| o.connect_timeout)
        .unwrap_or(config.connect_timeout);

    // Stage 1: L4 TCP Probe (Fail-Fast)
    let (stream, tcp_rtt) = match execute_l4_probe(
        dialer,
        &target.host,
        target.port,
        connect_timeout,
        config,
    )
    .await
    {
        Ok(res) => res,
        Err(reason) => {
            metrics.total_rtt_ms = check_start.elapsed().as_millis() as u64;
            return CheckResult::failure(target.host, target.port, reason, metrics);
        }
    };

    metrics.tcp_connect_rtt_ms = tcp_rtt;

    // Stage 2 & 3: Protocol Handshake Cascade + L7 Judge Verification
    match execute_handshake_cascade(dialer, stream, &target, config, tls_connector).await {
        Ok(success) => {
            metrics.handshake_rtt_ms = success.handshake_rtt_ms;
            metrics.total_rtt_ms = check_start.elapsed().as_millis() as u64;

            CheckResult {
                target_host: target.host,
                target_port: target.port,
                is_alive: true,
                detected_protocol: Some(success.detected_protocol),
                anonymity_level: success.judge_payload.anonymity,
                external_ip: success.judge_payload.exit_ip,
                metrics,
                supports_https: success.supports_https,
                error_reason: None,
            }
        }
        Err(reason) => {
            metrics.total_rtt_ms = check_start.elapsed().as_millis() as u64;
            CheckResult::failure(target.host, target.port, reason, metrics)
        }
    }
}
