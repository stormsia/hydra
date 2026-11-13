use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use url::Url;

use hydra_checker::{
    CheckTarget, CheckerConfig, CheckerEngine, ErrorReason, MockDialer, ProxyProtocol,
};

#[tokio::test]
async fn test_socks5_tls_tunnel_end_to_end() {
    // 1. Generate in-memory self-signed certificate for test Judge
    let san = vec!["judge.example.com".to_string(), "93.184.216.34".to_string()];
    let cert = rcgen::generate_simple_self_signed(san).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();

    // 2. Build ServerConfig for mock TLS Judge
    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 3. Build CheckerConfig trusting our custom CA cert_der
    let http_url = Url::parse("http://93.184.216.34:80/judge").unwrap();
    let https_url = Url::parse("https://93.184.216.34:443/judge").unwrap();

    let config = CheckerConfig::builder(http_url, https_url, "EXPECTED_TOKEN")
        .judge_ca_cert_der(cert_der)
        .connect_timeout(Duration::from_millis(200))
        .handshake_timeout(Duration::from_millis(200))
        .read_write_timeout(Duration::from_millis(300))
        .real_ip("95.10.10.10".parse().unwrap())
        .build()
        .await
        .unwrap();

    let acceptor_clone = acceptor.clone();
    let dialer = MockDialer::new(move |_host, _port, _attempt| {
        let (client, mut server) = tokio::io::duplex(4096);
        let acceptor = acceptor_clone.clone();

        tokio::spawn(async move {
            // SOCKS5 greeting: read greeting, respond NO_AUTH (0x05, 0x00)
            let mut buf = [0u8; 16];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(&[0x05, 0x00]).await.unwrap();

            // SOCKS5 connect: read request, respond SUCCESS (0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0)
            let mut conn_buf = [0u8; 64];
            let _ = server.read(&mut conn_buf).await.unwrap();
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            server.flush().await.unwrap();

            // Tunnel is now established! Perform TLS accept with client
            let mut tls_server = acceptor.accept(server).await.unwrap();

            // Read HTTP request over TLS
            let mut http_buf = [0u8; 1024];
            let n = tls_server.read(&mut http_buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&http_buf[..n]);
            assert!(req_str.contains("GET /judge?token=EXPECTED_TOKEN HTTP/1.1"));

            // Send valid Judge response
            let resp = "HTTP/1.1 200 OK\r\n\
                        Content-Type: text/plain\r\n\
                        Connection: close\r\n\
                        \r\n\
                        EXPECTED_TOKEN\n\
                        REMOTE_ADDR = 185.220.101.5\n\
                        HTTP_USER_AGENT = Mozilla/5.0\n";
            tls_server.write_all(resp.as_bytes()).await.unwrap();
            tls_server.flush().await.unwrap();
            let _ = tls_server.shutdown().await;
            drop(tls_server);
        });

        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 1080).with_protocol(ProxyProtocol::Socks5);
    let result = engine.check_single(target).await;

    assert!(result.is_alive, "Expected alive result: {:?}", result.error_reason);
    assert_eq!(result.detected_protocol, Some(ProxyProtocol::Socks5));
    assert!(result.supports_https);
    assert_eq!(result.external_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(result.anonymity_level, Some(hydra_checker::AnonymityLevel::Elite));
    assert_eq!(result.error_reason, None);
}

#[tokio::test]
async fn test_socks5_mitm_untrusted_cert_rejected() {
    // 1. Generate an untrusted cert (NOT added to client config)
    let san = vec!["93.184.216.34".to_string()];
    let mitm_cert = rcgen::generate_simple_self_signed(san).unwrap();
    let mitm_cert_der = mitm_cert.cert.der().to_vec();
    let mitm_key_der = mitm_cert.signing_key.serialize_der();

    let cert_chain = vec![CertificateDer::from(mitm_cert_der)];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(mitm_key_der));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 2. Client config without trusting the MITM cert
    let http_url = Url::parse("http://93.184.216.34:80/judge").unwrap();
    let https_url = Url::parse("https://93.184.216.34:443/judge").unwrap();

    let config = CheckerConfig::builder(http_url, https_url, "EXPECTED_TOKEN")
        .connect_timeout(Duration::from_millis(200))
        .handshake_timeout(Duration::from_millis(200))
        .read_write_timeout(Duration::from_millis(200))
        .build()
        .await
        .unwrap();

    let dialer = MockDialer::new(move |_host, _port, _attempt| {
        let (client, mut server) = tokio::io::duplex(4096);
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            // SOCKS5 OK
            let mut buf = [0u8; 16];
            let _ = server.read(&mut buf).await;
            let _ = server.write_all(&[0x05, 0x00]).await;

            let mut conn_buf = [0u8; 64];
            let _ = server.read(&mut conn_buf).await;
            let _ = server.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            let _ = server.flush().await;

            // Attempt TLS accept with untrusted certificate
            let _ = acceptor.accept(server).await;
        });

        Ok(client)
    });

    let engine = CheckerEngine::with_dialer(config, dialer).unwrap();
    let target = CheckTarget::new("8.8.8.8", 1080).with_protocol(ProxyProtocol::Socks5);
    let result = engine.check_single(target).await;

    assert!(!result.is_alive);
    // Verified fail-fast on untrusted MITM TLS cert!
    assert_eq!(result.error_reason, Some(ErrorReason::TlsHandshakeFailed));
}
