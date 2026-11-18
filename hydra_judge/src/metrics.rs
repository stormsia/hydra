use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Real-time lock-free metrics for the Judge instance
#[derive(Debug, Default)]
pub struct JudgeMetrics {
    pub total_connections: AtomicU64,
    pub authorized_requests: AtomicU64,
    pub blocked_scanners: AtomicU64,
    pub active_connections: AtomicI64,
    pub bytes_sent: AtomicU64,
}

impl JudgeMetrics {
    #[inline]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[inline]
    pub fn inc_total(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec_active(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_authorized(&self, bytes: usize) {
        self.authorized_requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_blocked(&self) {
        self.blocked_scanners.fetch_add(1, Ordering::Relaxed);
    }
}
