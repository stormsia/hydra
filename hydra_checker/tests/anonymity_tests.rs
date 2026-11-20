use std::net::IpAddr;

use hydra_checker::{AnonymityLevel, parse_judge_response};

#[test]
fn test_azenv_elite() {
    let body = "\
REMOTE_ADDR = 185.220.101.5
HTTP_HOST = judge.example.com
HTTP_USER_AGENT = Mozilla/5.0 (Windows NT 10.0; Win64; x64)
HTTP_ACCEPT = text/html,application/xhtml+xml
";
    let real_ip: IpAddr = "95.160.20.10".parse().unwrap();
    let res = parse_judge_response(body, Some(real_ip)).unwrap();

    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Elite));
}

#[test]
fn test_azenv_anonymous() {
    let body = "\
REMOTE_ADDR = 185.220.101.5
HTTP_VIA = 1.1 proxy.internal.lan (squid/3.5.20)
HTTP_PROXY_CONNECTION = keep-alive
";
    let real_ip: IpAddr = "95.160.20.10".parse().unwrap();
    let res = parse_judge_response(body, Some(real_ip)).unwrap();

    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Anonymous));
}

#[test]
fn test_azenv_transparent() {
    let real_ip: IpAddr = "95.160.20.10".parse().unwrap();
    let body = format!(
        "\
REMOTE_ADDR = 185.220.101.5
HTTP_VIA = 1.1 proxy.lan
HTTP_X_FORWARDED_FOR = {real_ip}
"
    );
    let res = parse_judge_response(&body, Some(real_ip)).unwrap();

    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Transparent));
}

#[test]
fn test_json_httpbin_format() {
    let real_ip: IpAddr = "95.160.20.10".parse().unwrap();

    // 1. JSON Elite
    let json_elite = r#"{
        "origin": "185.220.101.5",
        "headers": {
            "Host": "httpbin.org",
            "User-Agent": "Mozilla/5.0"
        }
    }"#;
    let res = parse_judge_response(json_elite, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Elite));

    // 2. JSON Anonymous (Via header)
    let json_anon = r#"{
        "origin": "185.220.101.5",
        "headers": {
            "Via": "1.1 varnish",
            "User-Agent": "Mozilla/5.0"
        }
    }"#;
    let res = parse_judge_response(json_anon, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Anonymous));

    // 3. JSON Transparent (X-Forwarded-For in headers)
    let json_trans = format!(
        r#"{{
        "origin": "{real_ip}, 185.220.101.5",
        "headers": {{
            "X-Forwarded-For": "{real_ip}",
            "User-Agent": "Mozilla/5.0"
        }}
    }}"#
    );
    let res = parse_judge_response(&json_trans, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Transparent));

    // 4. JSON Transparent via origin only (httpbin.org behavior where X-Forwarded-For is stripped from headers into origin)
    let json_origin_trans = format!(
        r#"{{
        "origin": "{real_ip}, 185.220.101.5",
        "headers": {{
            "Host": "httpbin.org",
            "User-Agent": "Mozilla/5.0"
        }}
    }}"#
    );
    let res = parse_judge_response(&json_origin_trans, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Transparent));

    // 5. JSON Anonymous via origin only (proxy forwarded an upstream client IP, disclosing proxy usage)
    let json_origin_anon = r#"{
        "origin": "1.2.3.4, 185.220.101.5",
        "headers": {
            "Host": "httpbin.org",
            "User-Agent": "Mozilla/5.0"
        }
    }"#;
    let res = parse_judge_response(json_origin_anon, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Anonymous));
}

#[test]
fn test_json_httpbingo_array_headers_format() {
    let real_ip: IpAddr = "95.160.20.10".parse().unwrap();

    // Httpbingo formats headers as arrays of strings
    let json_bingo_anon = r#"{
        "origin": "185.220.101.5",
        "headers": {
            "Via": ["1.1 fly.io", "1.1 proxy.example"],
            "User-Agent": ["Mozilla/5.0"]
        }
    }"#;
    let res = parse_judge_response(json_bingo_anon, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Anonymous));

    let json_bingo_trans = format!(
        r#"{{
        "origin": "185.220.101.5",
        "headers": {{
            "X-Forwarded-For": ["{real_ip}"],
            "User-Agent": ["Mozilla/5.0"]
        }}
    }}"#
    );
    let res = parse_judge_response(&json_bingo_trans, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    assert_eq!(res.anonymity, Some(AnonymityLevel::Transparent));
}

#[test]
fn test_raw_ip_format() {
    let body = "185.220.101.5\n";
    let real_ip: IpAddr = "95.160.20.10".parse().unwrap();
    let res = parse_judge_response(body, Some(real_ip)).unwrap();
    assert_eq!(res.exit_ip, Some("185.220.101.5".parse().unwrap()));
    // Raw IP provides no headers -> Anonymity cannot be evaluated -> must be None, NOT Elite!
    assert_eq!(res.anonymity, None);
}

#[test]
fn test_multi_ip_and_ipv6_subnet_identity_detection() {
    use hydra_checker::judge::{HostIdentity, parse_judge_response_with_identity};

    // Configure host with multiple IPv4s and routed IPv6 /64 subnet
    let mut identity = HostIdentity::new();
    identity.add_ip("95.160.20.10".parse().unwrap());
    identity.add_ip("198.51.100.42".parse().unwrap());
    identity.add_ip("2001:db8:abcd::1".parse().unwrap()); // Automatically registers /64 prefix 2001:db8:abcd::/64

    // Case 1: Proxy leaks secondary IPv4 in X-Forwarded-For
    let body_v4_secondary = "\
REMOTE_ADDR = 185.220.101.5
HTTP_VIA = 1.1 squid.proxy
HTTP_X_FORWARDED_FOR = 198.51.100.42
";
    let res1 = parse_judge_response_with_identity(body_v4_secondary, &identity).unwrap();
    assert_eq!(res1.anonymity, Some(AnonymityLevel::Transparent));

    // Case 2: Proxy leaks ephemeral/temporary SLAAC IPv6 from the /64 subnet
    let body_v6_slaac = "\
REMOTE_ADDR = 185.220.101.5
HTTP_VIA = 1.1 squid.proxy
HTTP_X_FORWARDED_FOR = 2001:db8:abcd:0:dead:beef:1234:5678
";
    let res2 = parse_judge_response_with_identity(body_v6_slaac, &identity).unwrap();
    assert_eq!(res2.anonymity, Some(AnonymityLevel::Transparent));

    // Case 3: Proxy leaks bracketed IPv6 with port
    let body_v6_port = "\
REMOTE_ADDR = 185.220.101.5
HTTP_X_FORWARDED_FOR = [2001:db8:abcd::dead]:54321
";
    let res3 = parse_judge_response_with_identity(body_v6_port, &identity).unwrap();
    assert_eq!(res3.anonymity, Some(AnonymityLevel::Transparent));

    // Case 4: No leak -> Anonymous (has Via)
    let body_no_leak = "\
REMOTE_ADDR = 185.220.101.5
HTTP_VIA = 1.1 squid.proxy
HTTP_X_FORWARDED_FOR = 203.0.113.99
";
    let res4 = parse_judge_response_with_identity(body_no_leak, &identity).unwrap();
    assert_eq!(res4.anonymity, Some(AnonymityLevel::Anonymous));
}

#[test]
fn test_host_identity_string_parsing() {
    use hydra_checker::judge::HostIdentity;

    let env_str = "95.160.20.10, 198.51.100.42; 2001:db8:cafe::/64 2001:db8:9999::1";
    let identity = HostIdentity::parse_from_str(env_str);

    assert!(identity.contains_ip(&"95.160.20.10".parse().unwrap()));
    assert!(identity.contains_ip(&"198.51.100.42".parse().unwrap()));
    // Check IPv6 subnet match
    assert!(identity.contains_ip(&"2001:db8:cafe:0:1111:2222:3333:4444".parse().unwrap()));
    // Check specific IPv6 match
    assert!(identity.contains_ip(&"2001:db8:9999::1".parse().unwrap()));
    // Unrelated IP should not match
    assert!(!identity.contains_ip(&"192.0.2.1".parse().unwrap()));
    assert!(!identity.contains_ip(&"2001:db8:beef::1".parse().unwrap()));
}

#[test]
fn test_local_interface_harvesting_sanity() {
    use hydra_checker::judge::HostIdentity;

    let local_identity = HostIdentity::from_local_interfaces();
    // Loopback 127.0.0.1 and ::1 must NEVER be in host identity
    assert!(!local_identity.contains_ip(&"127.0.0.1".parse().unwrap()));
    assert!(!local_identity.contains_ip(&"::1".parse().unwrap()));
}
