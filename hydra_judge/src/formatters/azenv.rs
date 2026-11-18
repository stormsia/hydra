use std::fmt::Write;
use std::net::IpAddr;

/// Format AZenv plain-text response (Key-Value) with zero-allocation header transformations
pub fn format_azenv(peer_ip: IpAddr, headers: &[(&str, &str)], secret_token: &str) -> String {
    let mut out = String::with_capacity(1024);

    // 1. Peer IP as seen on TCP layer (in-place display write, no peer_ip.to_string())
    let _ = writeln!(&mut out, "REMOTE_ADDR = {peer_ip}");

    // 2. Reflected headers: zero heap allocations
    for (name, val) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            out.push_str("CONTENT_TYPE");
        } else if name.eq_ignore_ascii_case("content-length") {
            out.push_str("CONTENT_LENGTH");
        } else {
            out.push_str("HTTP_");
            for b in name.bytes() {
                if b == b'-' {
                    out.push('_');
                } else {
                    out.push(b.to_ascii_uppercase() as char);
                }
            }
        }

        out.push_str(" = ");
        out.push_str(val);
        out.push('\n');
    }

    // 3. Mandatory secret token match for checker validation
    out.push_str("HYDRA_TOKEN = ");
    out.push_str(secret_token);
    out.push('\n');

    out
}
