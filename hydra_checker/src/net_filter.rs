use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::CheckerConfig;
use crate::error::ErrorReason;

/// Returns true if the IPv4 address is in a reserved, private, loopback,
/// multicast, link-local, or benchmarking range.
#[inline]
pub fn is_bogon_or_reserved_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 0.0.0.0/8 - Current network
    if octets[0] == 0 {
        return true;
    }

    // 10.0.0.0/8 - Private RFC 1918
    if octets[0] == 10 {
        return true;
    }

    // 100.64.0.0/10 - Shared address space / CGNAT (RFC 6598)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }

    // 127.0.0.0/8 - Loopback (RFC 1122)
    if octets[0] == 127 {
        return true;
    }

    // 169.254.0.0/16 - Link-local / Cloud metadata (RFC 3927)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // 172.16.0.0/12 - Private RFC 1918
    if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
        return true;
    }

    // 192.0.0.0/24 - IETF Protocol Assignments (RFC 6890)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }

    // 192.0.2.0/24 - TEST-NET-1 (RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }

    // 192.88.99.0/24 - 6to4 Relay Anycast (RFC 3068)
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return true;
    }

    // 192.168.0.0/16 - Private RFC 1918
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // 198.18.0.0/15 - Network Interconnect Device Benchmark (RFC 2544)
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return true;
    }

    // 198.51.100.0/24 - TEST-NET-2 (RFC 5737)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }

    // 203.0.113.0/24 - TEST-NET-3 (RFC 5737)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }

    // 224.0.0.0/4 - Multicast (RFC 5771)
    if (octets[0] & 0xF0) == 224 {
        return true;
    }

    // 240.0.0.0/4 - Reserved for future use (RFC 1112)
    // and 255.255.255.255 Limited Broadcast
    if (octets[0] & 0xF0) >= 240 {
        return true;
    }

    false
}

/// Returns true if the IPv6 address is in a reserved, private, loopback,
/// link-local, multicast, or documentation range.
#[inline]
pub fn is_bogon_or_reserved_v6(ip: Ipv6Addr) -> bool {
    // Unspecified ::
    if ip.is_unspecified() {
        return true;
    }

    // Loopback ::1
    if ip.is_loopback() {
        return true;
    }

    // IPv4-mapped IPv6 ::ffff:0:0/96
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_bogon_or_reserved_v4(v4);
    }

    let segments = ip.segments();

    // Unique Local fc00::/7 (RFC 4193)
    if (segments[0] & 0xFE00) == 0xFC00 {
        return true;
    }

    // Link-Local Unicast fe80::/10 (RFC 4291)
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return true;
    }

    // Multicast ff00::/8 (RFC 4291)
    if (segments[0] & 0xFF00) == 0xFF00 {
        return true;
    }

    // Documentation 2001:db8::/32 (RFC 3849)
    if segments[0] == 0x2001 && segments[1] == 0x0DB8 {
        return true;
    }

    // Discard prefix 100::/64 (RFC 6666)
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return true;
    }

    false
}

/// Fast pre-flight validator for target IP addresses.
///
/// Rejects bogons, loopbacks, private subnets, self-scans (matching real_ip / local_bind_ip),
/// and Judge server IPs with 0 network operations.
#[inline]
pub fn validate_target_ip(ip: IpAddr, config: &CheckerConfig) -> Result<(), ErrorReason> {
    // 1. Check bogon/reserved ranges
    let is_bogon = match ip {
        IpAddr::V4(v4) => is_bogon_or_reserved_v4(v4),
        IpAddr::V6(v6) => is_bogon_or_reserved_v6(v6),
    };

    if is_bogon {
        return Err(ErrorReason::BogonOrReservedIp);
    }

    // 2. Reject self-scan against caller's real public IP
    if let Some(real_ip) = config.real_ip()
        && ip == real_ip
    {
        return Err(ErrorReason::BogonOrReservedIp);
    }

    // 3. Reject target pointing to our own local bind IP
    if let Some(bind_ip) = config.local_bind_ip
        && ip == bind_ip
    {
        return Err(ErrorReason::BogonOrReservedIp);
    }

    // 4. Reject target pointing directly to Judge server IP
    if let Some(judge_http) = config.judge_http_addr
        && ip == judge_http.ip()
    {
        return Err(ErrorReason::BogonOrReservedIp);
    }

    if let Some(judge_https) = config.judge_https_addr
        && ip == judge_https.ip()
    {
        return Err(ErrorReason::BogonOrReservedIp);
    }

    Ok(())
}
