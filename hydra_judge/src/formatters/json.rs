use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Serialize)]
struct JsonEchoResponse<'a> {
    origin: String,
    headers: HashMap<&'a str, &'a str>,
    token: &'a str,
}

/// Format JSON httpbin-compatible response
pub fn format_json(
    peer_ip: IpAddr,
    headers: &[(&str, &str)],
    secret_token: &str,
) -> String {
    let mut header_map = HashMap::with_capacity(headers.len());
    for (k, v) in headers {
        header_map.insert(*k, *v);
    }

    let payload = JsonEchoResponse {
        origin: peer_ip.to_string(),
        headers: header_map,
        token: secret_token,
    };

    serde_json::to_string(&payload).unwrap_or_else(|_| {
        format!(
            "{{\"origin\":\"{}\",\"token\":\"{}\"}}",
            peer_ip, secret_token
        )
    })
}
