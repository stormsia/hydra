use std::net::IpAddr;
use std::str::FromStr;
use hydra_checker::net_filter::{is_bogon_or_reserved_v4, is_bogon_or_reserved_v6};
use crate::models::api::ProxyInputItem;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProxy {
    pub id: String, // "185.22.14.9:1080" or "185.22.14.9:1080:user:pass"
    pub ip: String,
    pub port: u16,
    pub protocol_hint: Option<String>,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
}

/// Constructs a full unmasked proxy ID: `ip:port:login:pwd` (or `ip:port` if no auth).
pub fn build_proxy_id(
    ip: &IpAddr,
    port: u16,
    auth_user: Option<&str>,
    auth_pass: Option<&str>,
) -> String {
    let host_port = match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };

    match (auth_user, auth_pass) {
        (Some(u), Some(p)) if !p.is_empty() => format!("{host_port}:{u}:{p}"),
        (Some(u), _) => format!("{host_port}:{u}:"),
        _ => host_port,
    }
}

/// Parses a `ProxyInputItem` (either a formatted string or structured object) into `ParsedProxy`.
pub fn parse_input_item(item: &ProxyInputItem) -> Option<ParsedProxy> {
    parse_input_item_opt(item, false)
}

/// Parse `ProxyInputItem` with option to allow private/loopback IPs (e.g. for testing)
pub fn parse_input_item_opt(item: &ProxyInputItem, allow_private: bool) -> Option<ParsedProxy> {
    match item {
        ProxyInputItem::String(s) => parse_proxy_string_opt(s, allow_private),
        ProxyInputItem::Object(obj) => {
            let host_str = obj.ip.trim();
            if host_str.is_empty() || obj.port == 0 {
                return None;
            }

            let ip: IpAddr = IpAddr::from_str(host_str).ok()?;

            if !allow_private {
                match ip {
                    IpAddr::V4(v4) => {
                        if is_bogon_or_reserved_v4(v4) {
                            return None;
                        }
                    }
                    IpAddr::V6(v6) => {
                        if is_bogon_or_reserved_v6(v6) {
                            return None;
                        }
                    }
                }
            }

            let protocol_hint = if obj.ignore_protocol.unwrap_or(false) {
                None
            } else {
                obj.protocol.clone()
            };

            let id = build_proxy_id(
                &ip,
                obj.port,
                obj.auth_user.as_deref(),
                obj.auth_pass.as_deref(),
            );

            Some(ParsedProxy {
                id,
                ip: ip.to_string(),
                port: obj.port,
                protocol_hint,
                auth_user: obj.auth_user.clone(),
                auth_pass: obj.auth_pass.clone(),
            })
        }
    }
}

/// Parses a single proxy string into a `ParsedProxy`.
/// Validates IP address (must be valid and not bogon/reserved) and port (1..=65535).
pub fn parse_proxy_string(raw: &str) -> Option<ParsedProxy> {
    parse_proxy_string_opt(raw, false)
}

/// Parse with option to allow private/loopback IPs (e.g. for testing / judges)
pub fn parse_proxy_string_opt(raw: &str, allow_private: bool) -> Option<ParsedProxy> {
    let mut s = raw.trim();
    if s.is_empty() {
        return None;
    }

    let mut protocol_hint = None;

    // 1. Detect protocol scheme prefix if present
    if let Some(rest) = s.strip_prefix("http://") {
        protocol_hint = Some("http".to_string());
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        protocol_hint = Some("https".to_string());
        s = rest;
    } else if let Some(rest) = s.strip_prefix("socks5://") {
        protocol_hint = Some("socks5".to_string());
        s = rest;
    } else if let Some(rest) = s.strip_prefix("socks5h://") {
        protocol_hint = Some("socks5".to_string());
        s = rest;
    } else if let Some(rest) = s.strip_prefix("socks4://") {
        protocol_hint = Some("socks4".to_string());
        s = rest;
    } else if let Some(rest) = s.strip_prefix("socks4a://") {
        protocol_hint = Some("socks4a".to_string());
        s = rest;
    }

    let mut auth_user = None;
    let mut auth_pass = None;

    // 2. Check if user:pass@ is present
    if let Some(at_idx) = s.rfind('@') {
        let auth_part = &s[..at_idx];
        s = &s[at_idx + 1..];

        if let Some((user, pass)) = auth_part.split_once(':') {
            auth_user = Some(user.to_string());
            auth_pass = Some(pass.to_string());
        } else {
            auth_user = Some(auth_part.to_string());
        }
    }

    // 3. Now we have either host:port or ip:port:user:pass
    let (host_str, port_str) = if s.starts_with('[') {
        // IPv6 bracketed: e.g. [::1]:1080 or [::1]:1080:user:pass
        let end_bracket = s.find(']')?;
        let host = &s[1..end_bracket];
        let rest = &s[end_bracket + 1..];
        if !rest.starts_with(':') {
            return None;
        }
        let after_colon = &rest[1..];
        // check if user:pass follows port
        let mut parts = after_colon.split(':');
        let port_part = parts.next()?;
        if let (Some(u), Some(p)) = (parts.next(), parts.next())
            && auth_user.is_none() {
                auth_user = Some(u.to_string());
                auth_pass = Some(p.to_string());
            }
        (host, port_part)
    } else {
        // IPv4 or plain host:port or ip:port:user:pass
        let parts: Vec<&str> = s.split(':').collect();
        match parts.len() {
            2 => (parts[0], parts[1]),
            4 => {
                // ip:port:user:pass
                if auth_user.is_none() {
                    auth_user = Some(parts[2].to_string());
                    auth_pass = Some(parts[3].to_string());
                }
                (parts[0], parts[1])
            }
            _ => return None,
        }
    };

    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }

    let ip: IpAddr = IpAddr::from_str(host_str).ok()?;

    if !allow_private {
        match ip {
            IpAddr::V4(v4) => {
                if is_bogon_or_reserved_v4(v4) {
                    return None;
                }
            }
            IpAddr::V6(v6) => {
                if is_bogon_or_reserved_v6(v6) {
                    return None;
                }
            }
        }
    }

    let id = build_proxy_id(&ip, port, auth_user.as_deref(), auth_pass.as_deref());

    Some(ParsedProxy {
        id,
        ip: ip.to_string(),
        port,
        protocol_hint,
        auth_user,
        auth_pass,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_formats() {
        // Plain IPv4
        let p1 = parse_proxy_string("185.22.14.9:1080").unwrap();
        assert_eq!(p1.id, "185.22.14.9:1080");
        assert_eq!(p1.ip, "185.22.14.9");
        assert_eq!(p1.port, 1080);
        assert_eq!(p1.protocol_hint, None);
        assert_eq!(p1.auth_user, None);

        // With protocol
        let p2 = parse_proxy_string("socks5://185.22.14.9:1080").unwrap();
        assert_eq!(p2.protocol_hint, Some("socks5".to_string()));

        // With auth and scheme
        let p3 = parse_proxy_string("http://user:pass@185.22.14.9:8080").unwrap();
        assert_eq!(p3.id, "185.22.14.9:8080:user:pass");
        assert_eq!(p3.protocol_hint, Some("http".to_string()));
        assert_eq!(p3.auth_user, Some("user".to_string()));
        assert_eq!(p3.auth_pass, Some("pass".to_string()));

        // Vendor format ip:port:user:pass
        let p4 = parse_proxy_string("185.22.14.9:8080:myuser:mypass").unwrap();
        assert_eq!(p4.id, "185.22.14.9:8080:myuser:mypass");
        assert_eq!(p4.auth_user, Some("myuser".to_string()));
        assert_eq!(p4.auth_pass, Some("mypass".to_string()));

        // Bogon rejection
        assert!(parse_proxy_string("127.0.0.1:8080").is_none());
        assert!(parse_proxy_string("10.0.0.1:8080").is_none());
        assert!(parse_proxy_string("192.168.1.1:8080").is_none());

        // Bogon allowed when explicit
        assert!(parse_proxy_string_opt("127.0.0.1:8080", true).is_some());
    }
}
