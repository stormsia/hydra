use std::time::{Duration, Instant};

use crate::config::CheckerConfig;
use crate::error::ErrorReason;
use crate::models::TargetHost;
use crate::transport::Dialer;

/// Phase 1: L4 TCP Probe.
///
/// Dials the target proxy and measures raw TCP SYN/SYN-ACK round-trip time.
pub async fn execute_l4_probe<D: Dialer>(
    dialer: &D,
    host: &TargetHost,
    port: u16,
    timeout: Duration,
    config: &CheckerConfig,
) -> Result<(D::Stream, u64), ErrorReason> {
    let start = Instant::now();
    let stream = dialer.connect(host, port, timeout, config).await?;
    let elapsed = start.elapsed();
    if elapsed > timeout {
        return Err(ErrorReason::TimeoutTcp);
    }
    let rtt_ms = elapsed.as_millis() as u64;

    Ok((stream, rtt_ms))
}
