use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::config::JudgeConfig;
use crate::error::JudgeError;

/// Build a high-performance TLS `ServerConfig` from configured paths, DER bytes,
/// or dynamically generate a self-signed certificate if none provided.
pub fn build_server_tls_config(config: &JudgeConfig) -> Result<Arc<ServerConfig>, JudgeError> {
    let (cert_chain, private_key) = if let (Some(cert_der), Some(key_der)) = (
        config.tls_cert_der.as_ref(),
        config.tls_key_der.as_ref(),
    ) {
        // Option 1: In-memory DER
        let certs = vec![CertificateDer::from(cert_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone()));
        (certs, key)
    } else if let (Some(cert_path), Some(key_path)) = (
        config.tls_cert_path.as_ref(),
        config.tls_key_path.as_ref(),
    ) {
        // Option 2: Read PEM files
        let cert_bytes = std::fs::read(cert_path).map_err(|e| {
            JudgeError::Config(format!("Failed to read cert file {}: {e}", cert_path.display()))
        })?;
        let certs = CertificateDer::pem_slice_iter(&cert_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JudgeError::Tls(format!("Failed to parse certificate PEM: {e}")))?;

        let key_file = File::open(key_path).map_err(|e| {
            JudgeError::Config(format!("Failed to open key file {}: {e}", key_path.display()))
        })?;
        let mut key_reader = BufReader::new(key_file);
        let key = PrivateKeyDer::from_pem_reader(&mut key_reader)
            .map_err(|e| JudgeError::Tls(format!("Failed to parse private key PEM: {e}")))?;

        (certs, key)
    } else {
        // Option 3: Auto-generate self-signed cert on the fly
        let san = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert = rcgen::generate_simple_self_signed(san)
            .map_err(|e| JudgeError::Tls(format!("Failed to generate self-signed cert: {e}")))?;

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let certs = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        (certs, key)
    };

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| JudgeError::Tls(format!("Failed to build TLS ServerConfig: {e}")))?;

    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(server_config))
}
