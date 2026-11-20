use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::CheckerConfig;
use crate::error::ErrorReason;
use crate::models::TargetHost;

pub mod mock;
pub mod tcp;
pub mod tls;

/// Network dialer abstraction using Return Position Impl Trait in Trait (RPITIT / AFIT).
///
/// Compile-time monomorphized, zero dynamic dispatch (`Box<dyn Stream>`),
/// enabling ultra-fast inlining and mockability.
pub trait Dialer: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Establish a connection to the target host and port within the given timeout.
    fn connect(
        &self,
        host: &TargetHost,
        port: u16,
        timeout: Duration,
        config: &CheckerConfig,
    ) -> impl Future<Output = Result<Self::Stream, ErrorReason>> + Send;
}

/// A zero-copy stream adapter that yields bytes from an in-memory prefix buffer
/// before delegating reads and writes to an underlying asynchronous stream.
///
/// Essential for HTTP CONNECT handshakes where `\r\n\r\n` is read iteratively
/// and subsequent TLS or HTTP bytes may have already been buffered in the socket.
#[derive(Debug)]
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    #[inline]
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }

    #[inline]
    pub fn into_inner(self) -> S {
        self.inner
    }

    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let available = &self.prefix[self.offset..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.offset += to_copy;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
