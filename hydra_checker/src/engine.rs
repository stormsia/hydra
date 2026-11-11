use futures::stream::{self, Stream, StreamExt};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::config::CheckerConfig;
use crate::error::CheckerError;
use crate::models::{CheckResult, CheckTarget};
use crate::pipeline::execute_pipeline;
use crate::pool::worker_pool::process_stream;
use crate::transport::tcp::TcpDialer;
use crate::transport::tls::build_tls_connector;
use crate::transport::Dialer;

/// Primary entrypoint for executing high-throughput proxy checks.
#[derive(Clone)]
pub struct CheckerEngine<D: Dialer = TcpDialer> {
    config: Arc<CheckerConfig>,
    dialer: Arc<D>,
    tls_connector: Arc<TlsConnector>,
    semaphore: Arc<Semaphore>,
}

impl CheckerEngine<TcpDialer> {
    /// Initialize engine with production `TcpDialer` and validated `CheckerConfig`
    pub fn new(config: CheckerConfig) -> Result<Self, CheckerError> {
        Self::with_dialer(config, TcpDialer::new())
    }
}

impl<D: Dialer> CheckerEngine<D> {
    /// Initialize engine with a custom dialer (e.g. `MockDialer` for testing)
    pub fn with_dialer(config: CheckerConfig, dialer: D) -> Result<Self, CheckerError> {
        let tls_connector = build_tls_connector(config.judge_ca_cert_der.as_deref())
            .map_err(|e| CheckerError::new(e))?;

        let limit = config.concurrency_limit;

        Ok(Self {
            config: Arc::new(config),
            dialer: Arc::new(dialer),
            tls_connector: Arc::new(tls_connector),
            semaphore: Arc::new(Semaphore::new(limit)),
        })
    }

    /// Access the active engine configuration
    #[inline]
    pub fn config(&self) -> &CheckerConfig {
        &self.config
    }

    /// Access the active TLS connector
    #[inline]
    pub fn tls_connector(&self) -> &Arc<TlsConnector> {
        &self.tls_connector
    }

    /// Access the active Judge pool
    #[inline]
    pub fn judge_pool(&self) -> &Arc<crate::judge::JudgePool> {
        &self.config.judge_pool
    }

    /// Check a single proxy target
    pub async fn check_single(&self, target: CheckTarget) -> CheckResult {
        execute_pipeline(
            self.dialer.as_ref(),
            target,
            self.config.as_ref(),
            self.tls_connector.as_ref(),
        )
        .await
    }

    /// Check a batch of proxy targets, yielding results as each completes
    pub async fn check_batch(&self, targets: Vec<CheckTarget>) -> Vec<CheckResult> {
        self.check_batch_with_cancel(targets, CancellationToken::new())
            .await
    }

    /// Check a batch of targets with external cancellation support
    pub async fn check_batch_with_cancel(
        &self,
        targets: Vec<CheckTarget>,
        cancel_token: CancellationToken,
    ) -> Vec<CheckResult> {
        let target_stream = stream::iter(targets);
        self.check_stream_with_cancel(target_stream, cancel_token)
            .collect()
            .await
    }

    /// Stream check targets, returning results as they complete with backpressure
    pub fn check_stream(
        &self,
        targets: impl Stream<Item = CheckTarget> + Send + 'static,
    ) -> impl Stream<Item = CheckResult> + Send + 'static {
        self.check_stream_with_cancel(targets, CancellationToken::new())
    }

    /// Stream check targets with cancellation support
    pub fn check_stream_with_cancel(
        &self,
        targets: impl Stream<Item = CheckTarget> + Send + 'static,
        cancel_token: CancellationToken,
    ) -> impl Stream<Item = CheckResult> + Send + 'static {
        process_stream(
            Arc::clone(&self.dialer),
            Arc::clone(&self.config),
            Arc::clone(&self.tls_connector),
            Arc::clone(&self.semaphore),
            cancel_token,
            targets,
        )
    }
}
