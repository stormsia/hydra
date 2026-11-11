use std::net::IpAddr;

use crate::config::ResponseFormat;

pub mod azenv;
pub mod json;

pub fn build_echo_response(
    peer_ip: IpAddr,
    headers: &[(&str, &str)],
    secret_token: &str,
    format: ResponseFormat,
) -> (String, &'static str) {
    match format {
        ResponseFormat::Azenv => (
            azenv::format_azenv(peer_ip, headers, secret_token),
            "text/plain; charset=utf-8",
        ),
        ResponseFormat::Json => (
            json::format_json(peer_ip, headers, secret_token),
            "application/json; charset=utf-8",
        ),
    }
}
