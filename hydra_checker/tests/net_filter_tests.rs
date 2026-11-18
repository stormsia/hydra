use std::net::IpAddr;
use url::Url;

use hydra_checker::net_filter::validate_target_ip;
use hydra_checker::{CheckerConfig, ErrorReason};

#[tokio::test]
async fn test_bogon_and_reserved_rejections() {
    let http_url = Url::parse("http://judge.example.com/check").unwrap();
    let https_url = Url::parse("https://judge.example.com/check").unwrap();

    let config = CheckerConfig::builder(http_url, https_url, "TOKEN123")
        .real_ip("198.51.100.55".parse().unwrap())
        .judge_http_addr("93.184.216.34:80".parse().unwrap())
        .build()
        .await
        .unwrap();

    // Loopback
    assert_eq!(
        validate_target_ip("127.0.0.1".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );
    assert_eq!(
        validate_target_ip("::1".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );

    // Private RFC 1918
    assert_eq!(
        validate_target_ip("10.1.2.3".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );
    assert_eq!(
        validate_target_ip("172.16.5.6".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );
    assert_eq!(
        validate_target_ip("192.168.1.100".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );

    // Link-Local / Cloud metadata (AWS/GCP/Azure)
    assert_eq!(
        validate_target_ip("169.254.169.254".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );

    // Shared address space (CGNAT)
    assert_eq!(
        validate_target_ip("100.64.0.1".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );

    // Self IP match (real_ip)
    assert_eq!(
        validate_target_ip("198.51.100.55".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );

    // Judge IP match
    assert_eq!(
        validate_target_ip("93.184.216.34".parse().unwrap(), &config),
        Err(ErrorReason::BogonOrReservedIp)
    );

    // Valid public IP
    let valid_ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(validate_target_ip(valid_ip, &config).is_ok());

    let valid_ip2: IpAddr = "1.1.1.1".parse().unwrap();
    assert!(validate_target_ip(valid_ip2, &config).is_ok());
}
