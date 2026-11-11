use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use url::Url;

use crate::models::ProxyAuth;

/// Build an absolute-URI HTTP/1.1 GET request for forward Plain HTTP proxies,
/// transmitting the secret token in both the URL and custom request header.
pub fn build_plain_http_request(
    judge_url: &Url,
    auth: Option<&ProxyAuth>,
    token: Option<&str>,
) -> Vec<u8> {
    let host = judge_url.host_str().unwrap_or("localhost");
    let port_str = match judge_url.port() {
        Some(p) if p != 80 => format!(":{p}"),
        _ => String::new(),
    };

    let mut req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}{}\r\n\
         Proxy-Connection: close\r\n\
         Connection: close\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
        judge_url.as_str(),
        host,
        port_str
    );

    // Redundant token transmission: Header + URL
    if let Some(t) = token {
        req.push_str("X-Hydra-Token: ");
        req.push_str(t);
        req.push_str("\r\n");
    }

    if let Some(auth) = auth {
        let credentials = format!("{}:{}", auth.username, auth.password);
        let encoded = BASE64.encode(credentials);
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&encoded);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    req.into_bytes()
}
