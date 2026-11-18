use std::net::IpAddr;

use crate::models::AnonymityLevel;

/// Known headers that indicate the presence or involvement of a proxy
const PROXY_HEADER_NAMES: &[&str] = &[
    "via",
    "x-forwarded-for",
    "x-forwarded",
    "forwarded",
    "forwarded-for",
    "x-real-ip",
    "client-ip",
    "x-client-ip",
    "proxy-connection",
    "x-proxy-id",
    "http_via",
    "http_x_forwarded_for",
    "http_forwarded",
    "http_x_real_ip",
    "http_client_ip",
    "http_proxy_connection",
];

/// Classify anonymity level based on extracted headers and our real public IP
pub fn classify_anonymity<'a, I>(headers: I, real_ip: Option<IpAddr>) -> AnonymityLevel
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let real_ip_str = real_ip.map(|ip| ip.to_string());
    let mut has_proxy_header = false;

    for (name, value) in headers {
        // 1. If our real IP is leaked anywhere in headers, it's Transparent
        if let Some(real_str) = &real_ip_str
            && value.contains(real_str.as_str())
        {
            return AnonymityLevel::Transparent;
        }

        // 2. Check if this header matches known proxy signatures (zero heap allocation)
        if PROXY_HEADER_NAMES
            .iter()
            .any(|&known| known.eq_ignore_ascii_case(name))
        {
            has_proxy_header = true;
        }
    }

    if has_proxy_header {
        AnonymityLevel::Anonymous
    } else {
        AnonymityLevel::Elite
    }
}
