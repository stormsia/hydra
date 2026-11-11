use futures::stream::{Stream, StreamExt};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::config::CheckerConfig;
use crate::error::ErrorReason;
use crate::models::{CheckMetrics, CheckResult, CheckTarget};
use crate::pipeline::execute_pipeline;
use crate::transport::Dialer;
use tokio_rustls::TlsConnector;

/// Process a stream of targets concurrently with bounded backpressure.
///
/// Returns a stream of results that yields each result as soon as it completes,
/// strictly bounded by `concurrency_limit` and cancellable via `CancellationToken`.
pub fn process_stream<D: Dialer>(
    dialer: Arc<D>,
    config: Arc<CheckerConfig>,
    tls_connector: Arc<TlsConnector>,
    semaphore: Arc<Semaphore>,
    cancel_token: CancellationToken,
    targets: impl Stream<Item = CheckTarget> + Send + 'static,
) -> impl Stream<Item = CheckResult> + Send + 'static {
    let limit = config.concurrency_limit;

    targets
        .map(move |target| {
            let dialer = Arc::clone(&dialer);
            let config = Arc::clone(&config);
            let tls_connector = Arc::clone(&tls_connector);
            let semaphore = Arc::clone(&semaphore);
            let token = cancel_token.clone();

            async move {
                // If cancelled before even starting, return Cancelled immediately
                if token.is_cancelled() {
                    return CheckResult::failure(
                        target.host,
                        target.port,
                        ErrorReason::Cancelled,
                        CheckMetrics::default(),
                    );
                }

                // Acquire semaphore permit to enforce ConcurrencyLimit
                let permit = match semaphore.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        return CheckResult::failure(
                            target.host,
                            target.port,
                            ErrorReason::Cancelled,
                            CheckMetrics::default(),
                        );
                    }
                };

                let target_host = target.host.clone();
                let target_port = target.port;

                // Run pipeline with cancellation awareness
                let check_fut = execute_pipeline(
                    dialer.as_ref(),
                    target,
                    config.as_ref(),
                    tls_connector.as_ref(),
                );

                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        drop(permit);
                        CheckResult::failure(
                            target_host,
                            target_port,
                            ErrorReason::Cancelled,
                            CheckMetrics::default(),
                        )
                    }
                    res = check_fut => {
                        drop(permit);
                        res
                    }
                }
            }
        })
        .buffer_unordered(limit)
}
