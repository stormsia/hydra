use std::collections::HashMap;
use std::net::IpAddr;
use serde::Deserialize;

use crate::error::ErrorReason;
use crate::models::AnonymityLevel;

pub mod anonymity;
pub mod endpoint;
pub mod health;
pub mod pool;
pub mod probe;

pub use anonymity::classify_anonymity;
pub use endpoint::JudgeEndpoint;
pub use health::{JudgeHealth, JudgeHealthReport, JudgeHealthStatus};
pub use pool::{JudgeEntry, JudgePool, JudgeSelectionStrategy};
pub use probe::probe_judge_endpoint;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum HeaderValue {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Deserialize)]
struct HttpbinPayload {
    origin: Option<String>,
    headers: Option<HashMap<String, HeaderValue>>,
}

/// Parsed result from a Judge payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgePayload {
    pub exit_ip: Option<IpAddr>,
    pub anonymity: Option<AnonymityLevel>,
}

/// Parse Judge response body (supporting AZenv format, httpbin JSON format, and raw text).
pub fn parse_judge_response(
    body: &str,
    real_ip: Option<IpAddr>,
) -> Result<JudgePayload, ErrorReason> {
    let body = body.trim().strip_prefix('\u{feff}').unwrap_or(body.trim());

    if body.is_empty() {
        return Err(ErrorReason::InvalidResponse);
    }

    // Try parsing as JSON (httpbin, httpbingo, httpbin.dev, and compatible echo endpoints)
    if body.starts_with('{') {
        if let Ok(json) = serde_json::from_str::<HttpbinPayload>(body) {
            let exit_ip = json.origin.as_deref().and_then(|orig| {
                // If comma-separated e.g. "client_ip, proxy_ip", the proxy exit IP is the rightmost
                orig.rsplit(',')
                    .next()
                    .and_then(|s| s.trim().parse::<IpAddr>().ok())
            });

            let mut header_pairs: Vec<(&str, &str)> = Vec::new();
            if let Some(ref hdrs) = json.headers {
                for (name, val) in hdrs {
                    match val {
                        HeaderValue::Single(s) => header_pairs.push((name.as_str(), s.as_str())),
                        HeaderValue::Multiple(vec) => {
                            for s in vec {
                                header_pairs.push((name.as_str(), s.as_str()));
                            }
                        }
                    }
                }
            }

            // Also check `origin`: in standard httpbin.org, `X-Forwarded-For` is extracted into `origin`!
            // e.g. "origin": "client_ip, proxy_ip"
            let mut leaked_ip_in_origin = false;
            let mut proxy_forwarded_origin = false;
            if let Some(orig) = json.origin.as_deref() {
                if let Some((client_parts, _last_ip)) = orig.rsplit_once(',') {
                    proxy_forwarded_origin = true;
                    if let Some(real_ip) = real_ip {
                        let real_str = real_ip.to_string();
                        if client_parts.contains(&real_str) {
                            leaked_ip_in_origin = true;
                        }
                    }
                }
            }

            let mut anonymity = if !header_pairs.is_empty() || json.origin.is_some() {
                Some(classify_anonymity(header_pairs.into_iter(), real_ip))
            } else {
                None
            };

            // If `origin` leaked our real IP, it's definitely Transparent!
            if leaked_ip_in_origin {
                anonymity = Some(AnonymityLevel::Transparent);
            } else if proxy_forwarded_origin && anonymity == Some(AnonymityLevel::Elite) {
                // If `origin` contains forwarded IP chain, proxy revealed upstream client IP
                anonymity = Some(AnonymityLevel::Anonymous);
            }

            return Ok(JudgePayload { exit_ip, anonymity });
        }
    }

    // Try parsing as AZenv format (KEY = VALUE)
    let mut exit_ip = None;
    let mut azenv_headers: Vec<(&str, &str)> = Vec::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, val)) = trimmed.split_once('=') {
            let k = key.trim();
            let v = val.trim().trim_matches('"').trim_matches('\'');

            if k.eq_ignore_ascii_case("REMOTE_ADDR") || k.eq_ignore_ascii_case("ip") {
                exit_ip = v.parse::<IpAddr>().ok();
            }

            azenv_headers.push((k, v));
        }
    }

    if exit_ip.is_some() && !azenv_headers.is_empty() {
        let anonymity = Some(classify_anonymity(azenv_headers.into_iter(), real_ip));
        return Ok(JudgePayload { exit_ip, anonymity });
    }

    // Fallback: Check if the entire body is just an IP address
    if let Ok(ip) = body.trim().parse::<IpAddr>() {
        return Ok(JudgePayload {
            exit_ip: Some(ip),
            anonymity: None, // Raw IP judge cannot determine anonymity; do NOT default to Elite!
        });
    }

    Err(ErrorReason::InvalidResponse)
}
