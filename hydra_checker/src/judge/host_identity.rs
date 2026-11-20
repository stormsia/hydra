use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipnet::{IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};

/// Comprehensive representation of a host's network identity across multiple IPv4
/// interfaces, global IPv6 addresses, and routed IPv6 subnets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HostIdentity {
    /// Discovered or configured public IPv4 addresses
    pub ipv4_addrs: HashSet<Ipv4Addr>,
    /// Discovered or configured specific IPv6 addresses
    pub ipv6_addrs: HashSet<Ipv6Addr>,
    /// Routed IPv6 subnets (typically /64 per provider delegation or SLAAC)
    pub ipv6_subnets: Vec<Ipv6Net>,
}

impl HostIdentity {
    /// Create an empty HostIdentity
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if identity contains no known IP addresses or subnets
    pub fn is_empty(&self) -> bool {
        self.ipv4_addrs.is_empty() && self.ipv6_addrs.is_empty() && self.ipv6_subnets.is_empty()
    }

    /// Add a single IP address.
    ///
    /// For IPv6 addresses, if it is a global unicast address, its default /64 subnet
    /// prefix is also added to allow detecting rotated SLAAC/privacy temporary addresses.
    pub fn add_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                self.ipv4_addrs.insert(v4);
            }
            IpAddr::V6(v6) => {
                self.ipv6_addrs.insert(v6);
                // For IPv6, track parent /64 prefix to catch RFC 4941 privacy temporary addresses
                if let Ok(net) = Ipv6Net::new(v6, 64) {
                    let truncated = net.trunc();
                    if !self.ipv6_subnets.contains(&truncated) {
                        self.ipv6_subnets.push(truncated);
                    }
                }
            }
        }
    }

    /// Add a subnet (e.g. /64, /56, or IPv4 CIDR).
    pub fn add_subnet(&mut self, net: IpNet) {
        match net {
            IpNet::V4(v4_net) => {
                for host in v4_net.hosts() {
                    self.ipv4_addrs.insert(host);
                }
            }
            IpNet::V6(v6_net) => {
                let truncated = v6_net.trunc();
                if !self.ipv6_subnets.contains(&truncated) {
                    self.ipv6_subnets.push(truncated);
                }
            }
        }
    }

    /// Merge another HostIdentity into self
    pub fn merge(&mut self, other: &HostIdentity) {
        self.ipv4_addrs.extend(&other.ipv4_addrs);
        self.ipv6_addrs.extend(&other.ipv6_addrs);
        for net in &other.ipv6_subnets {
            if !self.ipv6_subnets.contains(net) {
                self.ipv6_subnets.push(*net);
            }
        }
    }

    /// Checks if a given IP address belongs to this host identity
    /// (either exact match or enclosed in any of the IPv6 subnets).
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.ipv4_addrs.contains(v4),
            IpAddr::V6(v6) => {
                if self.ipv6_addrs.contains(v6) {
                    return true;
                }
                self.ipv6_subnets.iter().any(|subnet| subnet.contains(v6))
            }
        }
    }

    /// Checks if a header value (e.g. from X-Forwarded-For, Via, or Client-IP)
    /// contains or leaks this host's IP identity.
    pub fn matches_header_value(&self, value: &str) -> bool {
        if self.is_empty() {
            return false;
        }

        // 1. Direct string substring check for known IPv4 addresses
        for v4 in &self.ipv4_addrs {
            let v4_str = v4.to_string();
            if value.contains(&v4_str) {
                return true;
            }
        }

        // 2. Direct string substring check for specific IPv6 addresses
        for v6 in &self.ipv6_addrs {
            let v6_str = v6.to_string();
            if value.contains(&v6_str) {
                return true;
            }
        }

        // 3. Token-based IP parser: split value on comma, space, semicolons, brackets, quotes
        // and test if any parsed IP belongs to this host or any of its IPv6 subnets.
        for token in value.split([',', ' ', ';', '"', '\'', '[', ']']) {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Strip optional port from end if format is ip:port (IPv4) or similar
            let candidate = if let Some((ip_part, _port)) = trimmed.split_once(':') {
                if ip_part.contains('.') {
                    ip_part
                } else {
                    // IPv6 colons: don't split unless bracketed [::1]:port handled above
                    trimmed
                }
            } else {
                trimmed
            };

            if let Ok(parsed_ip) = candidate.parse::<IpAddr>()
                && self.contains_ip(&parsed_ip)
            {
                return true;
            }
        }

        false
    }

    /// Parse HostIdentity from a comma/space/semicolon-separated string of IPs and CIDR blocks.
    /// Example: "198.51.100.1, 198.51.100.2, 2001:db8:cafe::/64, 2001:db8::1"
    pub fn parse_from_str(s: &str) -> Self {
        let mut id = Self::new();
        for token in s.split([',', ' ', ';', '\n']) {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Ok(net) = trimmed.parse::<IpNet>() {
                id.add_subnet(net);
            } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
                id.add_ip(ip);
            }
        }
        id
    }

    /// Inspect local host network adapters and harvest all non-bogon, non-loopback
    /// public IPv4 addresses and global unicast IPv6 addresses (with /64 prefixes).
    pub fn from_local_interfaces() -> Self {
        let mut identity = Self::new();

        let ifaces = match if_addrs::get_if_addrs() {
            Ok(list) => list,
            Err(_) => return identity,
        };

        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }

            match iface.addr {
                if_addrs::IfAddr::V4(v4_if) => {
                    let v4 = v4_if.ip;
                    if !crate::net_filter::is_bogon_or_reserved_v4(v4) {
                        identity.ipv4_addrs.insert(v4);
                    }
                }
                if_addrs::IfAddr::V6(v6_if) => {
                    let v6 = v6_if.ip;
                    if !crate::net_filter::is_bogon_or_reserved_v6(v6) {
                        identity.ipv6_addrs.insert(v6);
                        // Extract subnet from interface netmask if valid (e.g. /64), or default to /64
                        let mask_octets = v6_if.netmask.octets();
                        let mut bits = 0u8;
                        for byte in mask_octets {
                            bits += byte.count_ones() as u8;
                        }
                        let prefix_len = if (48..=64).contains(&bits) { bits } else { 64 };
                        if let Ok(net) = Ipv6Net::new(v6, prefix_len) {
                            let truncated = net.trunc();
                            if !identity.ipv6_subnets.contains(&truncated) {
                                identity.ipv6_subnets.push(truncated);
                            }
                        }
                    }
                }
            }
        }

        identity
    }

    /// Provide a single primary representative IP for legacy compatibility
    /// (prefers lowest public IPv4, then lowest public IPv6).
    pub fn primary_ip(&self) -> Option<IpAddr> {
        if let Some(v4) = self.ipv4_addrs.iter().min() {
            return Some(IpAddr::V4(*v4));
        }
        if let Some(v6) = self.ipv6_addrs.iter().min() {
            return Some(IpAddr::V6(*v6));
        }
        None
    }
}
