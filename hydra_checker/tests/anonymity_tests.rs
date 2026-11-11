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
