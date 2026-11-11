use std::sync::Arc;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::error::ErrorReason;

/// Build a high-performance, lock-free `TlsConnector`.
///
/// Features:
/// 1. Pre-loaded webpki root certificates.
/// 2. Optional custom DER-encoded Root CA / Server certificate.
/// 3. `Resumption::disabled()` - prevents 10,000+ concurrent workers from contending
///    on an internal session cache Mutex, and forces every proxy to pass an authentic TLS handshake.
pub fn build_tls_connector(custom_ca_der: Option<&[u8]>) -> Result<TlsConnector, ErrorReason> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(der) = custom_ca_der {
        let cert = CertificateDer::from(der.to_vec());
        root_store
            .add(cert)
            .map_err(|_| ErrorReason::TlsHandshakeFailed)?;
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Disable TLS session resumption to eliminate session cache mutex contention
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsConnector::from(Arc::new(config)))
}
