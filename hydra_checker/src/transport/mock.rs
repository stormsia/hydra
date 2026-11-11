use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;

use crate::config::CheckerConfig;
use crate::error::ErrorReason;
use crate::models::TargetHost;
use crate::net_filter::validate_target_ip;
use crate::transport::Dialer;

pub type MockHandler = Box<
    dyn Fn(&TargetHost, u16, usize) -> Result<DuplexStream, ErrorReason> + Send + Sync,
>;

/// In-memory mock dialer for fully deterministic, offline testing of pipelines,
/// protocol handshakes, timeouts, and error handling.
#[derive(Clone)]
pub struct MockDialer {
    attempts: Arc<Mutex<HashMap<(TargetHost, u16), usize>>>,
    handler: Arc<MockHandler>,
}

impl MockDialer {
    /// Create a mock dialer with a custom routing handler
    pub fn new(
        handler: impl Fn(&TargetHost, u16, usize) -> Result<DuplexStream, ErrorReason>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new())),
            handler: Arc::new(Box::new(handler)),
        }
    }

    /// Total connect attempts recorded for a given host and port
    pub fn attempt_count(&self, host: &TargetHost, port: u16) -> usize {
        let attempts = self.attempts.lock().unwrap();
        attempts.get(&(host.clone(), port)).copied().unwrap_or(0)
    }
}

impl Dialer for MockDialer {
    type Stream = DuplexStream;

    async fn connect(
        &self,
        host: &TargetHost,
        port: u16,
        _timeout: Duration,
        config: &CheckerConfig,
    ) -> Result<Self::Stream, ErrorReason> {
        // Run pre-flight check just like real TcpDialer
        if let TargetHost::Ip(ip) = host {
            validate_target_ip(*ip, config)?;
        }

        let attempt_index = {
            let mut attempts = self.attempts.lock().unwrap();
            let count = attempts.entry((host.clone(), port)).or_insert(0);
            let current = *count;
            *count += 1;
            current
        };

        (self.handler)(host, port, attempt_index)
    }
}
