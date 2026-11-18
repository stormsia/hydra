use crate::models::api::ProxyInputItem;
use hydra_checker::net_filter::{is_bogon_or_reserved_v4, is_bogon_or_reserved_v6};
use std::net::IpAddr;
use std::str::FromStr;

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

/// Helper: matches a string case-insensitively against supported proxy protocols.
fn match_protocol(s: &str) -> Option<&'static str> {
    match s.to_ascii_lowercase().as_str() {
        "http" => Some("http"),
        "https" => Some("https"),
        "socks5" | "socks5h" => Some("socks5"),
        "socks4" => Some("socks4"),
        "socks4a" => Some("socks4a"),
        _ => None,
    }
}

/// Helper: attempts to parse `host:port` into `(IpAddr, u16)`.
/// Supports standard `ip:port` and bracketed `[ipv6]:port`.
fn try_parse_host_port(s: &str) -> Option<(IpAddr, u16)> {
    let s = s.trim();
    if s.starts_with('[') {
        let end = s.find(']')?;
        let host_str = &s[1..end];
        let rest = s[end + 1..].strip_prefix(':')?;
        let port: u16 = rest.parse().ok()?;
        if port == 0 {
            return None;
        }
        let ip = IpAddr::from_str(host_str).ok()?;
        Some((ip, port))
    } else {
        let (host_str, port_str) = s.split_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        if port == 0 {
            return None;
        }
        let ip = IpAddr::from_str(host_str).ok()?;
        Some((ip, port))
    }
}

/// Parses a single proxy string into a `ParsedProxy`.
/// Validates IP address (must be valid and not bogon/reserved) and port (1..=65535).
pub fn parse_proxy_string(raw: &str) -> Option<ParsedProxy> {
    parse_proxy_string_opt(raw, false)
}

/// Parse with option to allow private/loopback IPs (e.g. for testing / judges).
///
/// Universal Parser supports:
/// - Standard URL: `[protocol://][user:pass@]host:port`
/// - Inverse URL: `[protocol://]host:port@user:pass`
/// - Vendor format: `host:port:user:pass`
/// - Inverted vendor format: `user:pass:host:port` (log:pass:host:port)
/// - Protocol suffixes: `host:port:socks5`, `host:port:user:pass:socks5`, `user:pass:host:port:socks5`
/// - Protocol prefixes without slashes: `socks5:host:port`, `socks5:user:pass:host:port`
/// - Delimiters: `;`, `|`, whitespace (` ` / `\t`), comma (`,`)
/// - Bracketed IPv6: `[2001:db8::1]:port`, `user:pass@[2001:db8::1]:port`, `[2001:db8::1]:port:user:pass`
pub fn parse_proxy_string_opt(raw: &str, allow_private: bool) -> Option<ParsedProxy> {
    let mut s = raw.trim();
    // Strip optional surrounding quotes ("..." or '...')
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        s = s[1..s.len() - 1].trim();
    }
    if s.is_empty() {
        return None;
    }

    let mut protocol_hint = None;

    // 1. Detect protocol scheme prefix if present (case-insensitive)
    if let Some(idx) = s.find("://") {
        let scheme = &s[..idx];
        if let Some(proto) = match_protocol(scheme) {
            protocol_hint = Some(proto.to_string());
            s = &s[idx + 3..];
        }
    } else if let Some((first, rest)) = s.split_once(':')
        && let Some(proto) = match_protocol(first)
    {
        protocol_hint = Some(proto.to_string());
        s = rest;
    }

    let mut auth_user = None;
    let mut auth_pass = None;
    let mut host_port: Option<(IpAddr, u16)> = None;

    // 2. Handle '@' separator (standard `user:pass@host:port` or inverse `host:port@user:pass`)
    if let Some(at_idx) = s.rfind('@') {
        let left = &s[..at_idx];
        let right = &s[at_idx + 1..];

        // Standard: user:pass@host:port
        if let Some((ip, port)) = try_parse_host_port(right) {
            host_port = Some((ip, port));
            if let Some((u, p)) = left.split_once(':') {
                auth_user = Some(u.to_string());
                auth_pass = Some(p.to_string());
            } else if !left.is_empty() {
                auth_user = Some(left.to_string());
            }
        } else if let Some((ip, port)) = try_parse_host_port(left) {
            // Inverse: host:port@user:pass
            host_port = Some((ip, port));
            if let Some((u, p)) = right.split_once(':') {
                auth_user = Some(u.to_string());
                auth_pass = Some(p.to_string());
            } else if !right.is_empty() {
                auth_user = Some(right.to_string());
            }
        }
    }

    // 3. Alternative compound separators: ';' or '|'
    if host_port.is_none() && (s.contains(';') || s.contains('|')) {
        let chunks: Vec<&str> = s
            .split([';', '|'])
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .collect();
        if chunks.len() == 2 {
            if let Some((ip, port)) = try_parse_host_port(chunks[0]) {
                host_port = Some((ip, port));
                if let Some((u, p)) = chunks[1].split_once(':') {
                    auth_user = Some(u.to_string());
                    auth_pass = Some(p.to_string());
                } else {
                    auth_user = Some(chunks[1].to_string());
                }
            } else if let Some((ip, port)) = try_parse_host_port(chunks[1]) {
                host_port = Some((ip, port));
                if let Some((u, p)) = chunks[0].split_once(':') {
                    auth_user = Some(u.to_string());
                    auth_pass = Some(p.to_string());
                } else {
                    auth_user = Some(chunks[0].to_string());
                }
            }
        }
    }

    // 4. Whitespace, tab or comma separated tokens
    if host_port.is_none() && (s.chars().any(|c| c == ' ' || c == '\t' || c == ',')) {
        let tokens: Vec<&str> = s
            .split([' ', '\t', ','])
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .collect();
        match tokens.len() {
            2 => {
                if let Some((ip, port)) = try_parse_host_port(tokens[0]) {
                    host_port = Some((ip, port));
                    if let Some((u, p)) = tokens[1].split_once(':') {
                        auth_user = Some(u.to_string());
                        auth_pass = Some(p.to_string());
                    } else {
                        auth_user = Some(tokens[1].to_string());
                    }
                } else if let Some((ip, port)) = try_parse_host_port(tokens[1]) {
                    host_port = Some((ip, port));
                    if let Some((u, p)) = tokens[0].split_once(':') {
                        auth_user = Some(u.to_string());
                        auth_pass = Some(p.to_string());
                    } else {
                        auth_user = Some(tokens[0].to_string());
                    }
                }
            }
            3 => {
                if let Some((ip, port)) = try_parse_host_port(tokens[0]) {
                    host_port = Some((ip, port));
                    if let Some(proto) = match_protocol(tokens[1]) {
                        if protocol_hint.is_none() {
                            protocol_hint = Some(proto.to_string());
                        }
                    } else if let Some(proto) = match_protocol(tokens[2]) {
                        if protocol_hint.is_none() {
                            protocol_hint = Some(proto.to_string());
                        }
                        auth_user = Some(tokens[1].to_string());
                    } else {
                        auth_user = Some(tokens[1].to_string());
                        auth_pass = Some(tokens[2].to_string());
                    }
                } else if let Some((ip, port)) = try_parse_host_port(tokens[2]) {
                    host_port = Some((ip, port));
                    auth_user = Some(tokens[0].to_string());
                    auth_pass = Some(tokens[1].to_string());
                } else {
                    let hp = format!("{}:{}", tokens[0], tokens[1]);
                    if let Some((ip, port)) = try_parse_host_port(&hp) {
                        host_port = Some((ip, port));
                        if let Some(proto) = match_protocol(tokens[2])
                            && protocol_hint.is_none()
                        {
                            protocol_hint = Some(proto.to_string());
                        }
                    }
                }
            }
            4 => {
                let hp0 = format!("{}:{}", tokens[0], tokens[1]);
                let hp2 = format!("{}:{}", tokens[2], tokens[3]);
                if let Some((ip, port)) = try_parse_host_port(&hp0) {
                    host_port = Some((ip, port));
                    auth_user = Some(tokens[2].to_string());
                    auth_pass = Some(tokens[3].to_string());
                } else if let Some((ip, port)) = try_parse_host_port(&hp2) {
                    host_port = Some((ip, port));
                    auth_user = Some(tokens[0].to_string());
                    auth_pass = Some(tokens[1].to_string());
                }
            }
            5 => {
                if let Some(proto) = match_protocol(tokens[4]) {
                    if protocol_hint.is_none() {
                        protocol_hint = Some(proto.to_string());
                    }
                    let hp = format!("{}:{}", tokens[0], tokens[1]);
                    if let Some((ip, port)) = try_parse_host_port(&hp) {
                        host_port = Some((ip, port));
                        auth_user = Some(tokens[2].to_string());
                        auth_pass = Some(tokens[3].to_string());
                    }
                } else if let Some(proto) = match_protocol(tokens[0]) {
                    if protocol_hint.is_none() {
                        protocol_hint = Some(proto.to_string());
                    }
                    let hp = format!("{}:{}", tokens[1], tokens[2]);
                    if let Some((ip, port)) = try_parse_host_port(&hp) {
                        host_port = Some((ip, port));
                        auth_user = Some(tokens[3].to_string());
                        auth_pass = Some(tokens[4].to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // 5. Bracketed IPv6 format [2001:db8::1]:port...
    if host_port.is_none() && s.contains('[') && s.contains(']') {
        let start = s.find('[').unwrap();
        let end = s.find(']').unwrap();
        let ip_str = &s[start + 1..end];
        if let Ok(ip) = IpAddr::from_str(ip_str) {
            let prefix = &s[..start];
            let suffix = &s[end + 1..];
            if let Some(after_colon) = suffix.strip_prefix(':') {
                let parts: Vec<&str> = after_colon.split(':').collect();
                if let Ok(port) = parts[0].parse::<u16>()
                    && port > 0
                {
                    host_port = Some((ip, port));
                    if parts.len() >= 3 {
                        auth_user = Some(parts[1].to_string());
                        auth_pass = Some(parts[2..].join(":"));
                    } else if parts.len() == 2 {
                        if let Some(proto) = match_protocol(parts[1]) {
                            if protocol_hint.is_none() {
                                protocol_hint = Some(proto.to_string());
                            }
                        } else {
                            auth_user = Some(parts[1].to_string());
                        }
                    }

                    if auth_user.is_none() && !prefix.is_empty() {
                        let pre = prefix.trim_end_matches(':');
                        if let Some((u, p)) = pre.split_once(':') {
                            auth_user = Some(u.to_string());
                            auth_pass = Some(p.to_string());
                        } else {
                            auth_user = Some(pre.to_string());
                        }
                    }
                }
            }
        }
    }

    // 6. Pure colon-separated formats (:):
    // host:port | host:port:protocol | host:port:user | host:port:user:pass | user:pass:host:port
    if host_port.is_none() {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.len() {
            2 => {
                if let Some((ip, port)) = try_parse_host_port(s) {
                    host_port = Some((ip, port));
                }
            }
            3 => {
                let hp0 = format!("{}:{}", parts[0], parts[1]);
                let hp1 = format!("{}:{}", parts[1], parts[2]);

                if let Some((ip, port)) = try_parse_host_port(&hp0) {
                    host_port = Some((ip, port));
                    if let Some(proto) = match_protocol(parts[2]) {
                        if protocol_hint.is_none() {
                            protocol_hint = Some(proto.to_string());
                        }
                    } else {
                        auth_user = Some(parts[2].to_string());
                    }
                } else if let Some((ip, port)) = try_parse_host_port(&hp1) {
                    host_port = Some((ip, port));
                    if let Some(proto) = match_protocol(parts[0]) {
                        if protocol_hint.is_none() {
                            protocol_hint = Some(proto.to_string());
                        }
                    } else {
                        auth_user = Some(parts[0].to_string());
                    }
                }
            }
            4 => {
                let p0_hp = format!("{}:{}", parts[0], parts[1]);
                let p2_hp = format!("{}:{}", parts[2], parts[3]);

                let is_p0_hp = try_parse_host_port(&p0_hp);
                let is_p2_hp = try_parse_host_port(&p2_hp);

                match (is_p0_hp, is_p2_hp) {
                    (Some((ip, port)), None) => {
                        // host:port:user:pass
                        host_port = Some((ip, port));
                        auth_user = Some(parts[2].to_string());
                        auth_pass = Some(parts[3].to_string());
                    }
                    (None, Some((ip, port))) => {
                        // user:pass:host:port
                        host_port = Some((ip, port));
                        auth_user = Some(parts[0].to_string());
                        auth_pass = Some(parts[1].to_string());
                    }
                    (Some((ip, port)), Some(_)) => {
                        // Priority: host:port:user:pass
                        host_port = Some((ip, port));
                        auth_user = Some(parts[2].to_string());
                        auth_pass = Some(parts[3].to_string());
                    }
                    (None, None) => {}
                }
            }
            n if n >= 5 => {
                // Check if last token is a protocol
                let (working_parts, last_proto) =
                    if let Some(proto) = match_protocol(parts[parts.len() - 1]) {
                        (&parts[..parts.len() - 1], Some(proto))
                    } else {
                        (&parts[..], None)
                    };

                if let Some(proto) = last_proto
                    && protocol_hint.is_none()
                {
                    protocol_hint = Some(proto.to_string());
                }

                // Check if first token is a protocol
                let (working_parts, first_proto) =
                    if let Some(proto) = match_protocol(working_parts[0]) {
                        (&working_parts[1..], Some(proto))
                    } else {
                        (working_parts, None)
                    };

                if let Some(proto) = first_proto
                    && protocol_hint.is_none()
                {
                    protocol_hint = Some(proto.to_string());
                }

                if working_parts.len() >= 4 {
                    let p0_hp = format!("{}:{}", working_parts[0], working_parts[1]);
                    let p_last_hp = format!(
                        "{}:{}",
                        working_parts[working_parts.len() - 2],
                        working_parts[working_parts.len() - 1]
                    );

                    if let Some((ip, port)) = try_parse_host_port(&p0_hp) {
                        host_port = Some((ip, port));
                        auth_user = Some(working_parts[2].to_string());
                        auth_pass = Some(working_parts[3..].join(":"));
                    } else if let Some((ip, port)) = try_parse_host_port(&p_last_hp) {
                        host_port = Some((ip, port));
                        auth_user = Some(working_parts[0].to_string());
                        auth_pass = Some(working_parts[1..working_parts.len() - 2].join(":"));
                    }
                }
            }
            _ => {}
        }
    }

    let (ip, port) = host_port?;

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

        // Inverted vendor format user:pass:ip:port (log:pass:host:port)
        let p5 = parse_proxy_string("myuser:mypass:185.22.14.9:8080").unwrap();
        assert_eq!(p5.id, "185.22.14.9:8080:myuser:mypass");
        assert_eq!(p5.ip, "185.22.14.9");
        assert_eq!(p5.port, 8080);
        assert_eq!(p5.auth_user, Some("myuser".to_string()));
        assert_eq!(p5.auth_pass, Some("mypass".to_string()));

        // Inverse @ format host:port@user:pass
        let p6 = parse_proxy_string("185.22.14.9:8080@myuser:mypass").unwrap();
        assert_eq!(p6.id, "185.22.14.9:8080:myuser:mypass");
        assert_eq!(p6.auth_user, Some("myuser".to_string()));
        assert_eq!(p6.auth_pass, Some("mypass".to_string()));

        // Semicolon separator
        let p7a = parse_proxy_string("185.22.14.9:8080;myuser:mypass").unwrap();
        assert_eq!(p7a.id, "185.22.14.9:8080:myuser:mypass");
        let p7b = parse_proxy_string("myuser:mypass;185.22.14.9:8080").unwrap();
        assert_eq!(p7b.id, "185.22.14.9:8080:myuser:mypass");

        // Pipe separator
        let p8a = parse_proxy_string("185.22.14.9:8080|myuser:mypass").unwrap();
        assert_eq!(p8a.id, "185.22.14.9:8080:myuser:mypass");
        let p8b = parse_proxy_string("myuser:mypass|185.22.14.9:8080").unwrap();
        assert_eq!(p8b.id, "185.22.14.9:8080:myuser:mypass");

        // Whitespace and tab separators
        let p9a = parse_proxy_string("185.22.14.9:8080 myuser mypass").unwrap();
        assert_eq!(p9a.id, "185.22.14.9:8080:myuser:mypass");
        let p9b = parse_proxy_string("185.22.14.9\t8080\tmyuser\tmypass").unwrap();
        assert_eq!(p9b.id, "185.22.14.9:8080:myuser:mypass");
        let p9c = parse_proxy_string("myuser mypass 185.22.14.9 8080").unwrap();
        assert_eq!(p9c.id, "185.22.14.9:8080:myuser:mypass");

        // Protocol suffix
        let p10a = parse_proxy_string("185.22.14.9:8080:socks5").unwrap();
        assert_eq!(p10a.ip, "185.22.14.9");
        assert_eq!(p10a.port, 8080);
        assert_eq!(p10a.protocol_hint, Some("socks5".to_string()));

        let p10b = parse_proxy_string("185.22.14.9:8080:myuser:mypass:socks5").unwrap();
        assert_eq!(p10b.id, "185.22.14.9:8080:myuser:mypass");
        assert_eq!(p10b.protocol_hint, Some("socks5".to_string()));

        let p10c = parse_proxy_string("myuser:mypass:185.22.14.9:8080:socks5").unwrap();
        assert_eq!(p10c.id, "185.22.14.9:8080:myuser:mypass");
        assert_eq!(p10c.protocol_hint, Some("socks5".to_string()));

        // Case-insensitive scheme and quotes
        let p11 = parse_proxy_string("\"SOCKS5://myuser:mypass@185.22.14.9:1080\"").unwrap();
        assert_eq!(p11.id, "185.22.14.9:1080:myuser:mypass");
        assert_eq!(p11.protocol_hint, Some("socks5".to_string()));

        // IPv6 variations
        let p12a = parse_proxy_string_opt("[2001:db8::1]:1080", true).unwrap();
        assert_eq!(p12a.id, "[2001:db8::1]:1080");
        let p12b = parse_proxy_string_opt("user:pass@[2001:db8::1]:1080", true).unwrap();
        assert_eq!(p12b.id, "[2001:db8::1]:1080:user:pass");
        let p12c = parse_proxy_string_opt("user:pass:[2001:db8::1]:1080", true).unwrap();
        assert_eq!(p12c.id, "[2001:db8::1]:1080:user:pass");

        // Bogon rejection
        assert!(parse_proxy_string("127.0.0.1:8080").is_none());
        assert!(parse_proxy_string("10.0.0.1:8080").is_none());
        assert!(parse_proxy_string("192.168.1.1:8080").is_none());

        // Bogon allowed when explicit
        assert!(parse_proxy_string_opt("127.0.0.1:8080", true).is_some());
    }
}
