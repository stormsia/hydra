[← Back to Hydra README](../README.md)

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

# Hydra Checker

High-throughput, asynchronous proxy validation and classification core engine written in pure Rust (Tokio). Features preemptive L4 connection filtering, cascading protocol auto-detection (SOCKS4/5, HTTP CONNECT, Plain HTTP), end-to-end verification via an active Judge Pool, and strict anonymity classification with zero socket/descriptor leaks.

## File and Directory Structure

```text
hydra_checker/
├── .env.example              # Environment configuration template
├── Cargo.toml                # Package manifest and dependencies
├── Cargo.lock                # Locked dependency tree
├── README.md                 # Technical documentation
├── examples/
│   └── stress_bench.rs       # Throughput stress test and benchmark
├── src/
│   ├── judge/
│   │   ├── anonymity.rs      # Proxy anonymity level classification
│   │   ├── endpoint.rs       # Judge endpoint struct and metadata
│   │   ├── health.rs         # Background judge health checker
│   │   ├── mod.rs            # Judge interaction subsystem exports
│   │   ├── pool.rs           # Judge pool, load balancing, and failover
│   │   └── probe.rs          # L7 judge probe and response validation
│   ├── pipeline/
│   │   ├── handshake.rs      # Protocol handshake and cascading auto-detection
│   │   ├── l4_probe.rs       # Preemptive L4 TCP port reachability probe
│   │   ├── l7_judge.rs       # End-to-end L7 request through proxy tunnel
│   │   └── mod.rs            # Multi-stage check pipeline orchestration
│   ├── pool/
│   │   ├── mod.rs            # Concurrent worker pool module
│   │   └── worker_pool.rs    # Concurrency control via Tokio Semaphore
│   ├── protocols/
│   │   ├── http_connect.rs   # HTTP CONNECT tunneling implementation
│   │   ├── http_plain.rs     # Plain HTTP direct forwarding
│   │   ├── mod.rs            # Proxy protocol traits and structs
│   │   ├── socks4.rs         # SOCKS4 and SOCKS4a protocols
│   │   └── socks5.rs         # SOCKS5 protocol with authentication support
│   ├── transport/
│   │   ├── mock.rs           # Mock dialer for unit tests without network
│   │   ├── mod.rs            # Network transport abstraction (Dialer trait)
│   │   ├── tcp.rs            # Custom TCP dialer with SO_LINGER=0 and TCP_NODELAY
│   │   └── tls.rs            # TLS connector and PrefixedStream buffer
│   ├── config.rs             # Checker configuration and ENV parsing
│   ├── engine.rs             # Main verification execution facade
│   ├── error.rs              # Strongly typed error codes (ErrorReason)
│   ├── lib.rs                # Library root and public API
│   ├── models.rs             # Target, outcome, and telemetry models
│   ├── net_filter.rs         # SSRF protection and Bogon IP filtering
│   └── token.rs              # Daily rotating HMAC-SHA256 token verification
└── tests/
    ├── anonymity_tests.rs    # Anonymity level detection tests
    ├── judge_pool_tests.rs   # Judge pool failover and balancing tests
    ├── mock_pipeline_tests.rs# End-to-end pipeline tests on mock dialers
    ├── net_filter_tests.rs   # Bogon filter and DNS-rebind security tests
    ├── tls_tunnel_tests.rs   # TLS tunnel tests through proxy connections
    └── token_rotation_tests.rs # HMAC token rotation tests
```

## Network Verification Pipeline

1. **L4 (TCP Connect)**: SYN handshake with `SO_LINGER=0`, instantaneous Bogon/SSRF rejection, and microsecond TCP RTT measurement.
2. **Handshake**: Protocol negotiation (SOCKS5, SOCKS4, HTTP CONNECT) or sequential cascading auto-detection.
3. **TLS / Judge**: Establish TLS session through the tunnel, execute L7 HTTP request to judge, and validate authenticity token.
4. **Anonymity**: Inspect forwarded headers and reflect client IP to classify level (Elite, Anonymous, Transparent).

## ENV Configuration

| Variable | Type | Default | Description |
|---|---|---|---|
| `JUDGE_HTTP_URL` | String (URL) | `http://127.0.0.1:8080` | Judge URL for Plain HTTP checks |
| `JUDGE_HTTPS_URL` | String (URL) | `http://127.0.0.1:8080` | Judge URL for HTTPS tunnels |
| `JUDGE_SECRET_TOKEN` | String | `hydra_secret_token` | Static verification response token |
| `JUDGE_SECRET_KEY` | Hex String | — | HMAC key for daily rolling token validation |
| `CHECKER_CONCURRENCY` | usize | `5000` | Maximum concurrent validation tasks |
| `CHECKER_CONNECT_TIMEOUT_MS` | u64 | `3000` | TCP connection establishment timeout |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | u64 | `4000` | Tunnel protocol handshake timeout |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | u64 | `5000` | Judge data transmission timeout |
| `CHECKER_MAX_READ_BYTES` | usize | `8192` | Maximum response body buffer size |
| `CHECKER_LOCAL_BIND_IP` | IpAddr | — | Outbound socket binding IP interface |
| `CHECKER_REAL_IP` | IpAddr | — | Host public IP for anonymity comparison |
| `ENABLE_BUILTIN_JUDGE` | bool | `true` | Enable built-in/primary judge in pool |
| `ENABLE_THIRD_PARTY_JUDGES` | bool | `true` | Enable built-in third-party judge pool |
| `JUDGE_SELECTION_STRATEGY` | String | `lowest_latency` | Judge selection strategy |
| `ADDITIONAL_JUDGES` | String | — | Additional comma-separated judge URLs |
| `RUST_LOG` | String | `info` | Logging verbosity filter directive |

## CLI Commands

### Build
```bash
cargo build -p hydra_checker --release
```

### Testing
```bash
# Run all package tests
cargo test -p hydra_checker

# Run specific integration test suite
cargo test -p hydra_checker --test mock_pipeline_tests
```

### Linting & Formatting
```bash
cargo fmt --check
cargo clippy -p hydra_checker --all-targets -- -D warnings
```

### Benchmarks
```bash
cargo run -p hydra_checker --example stress_bench --release
```
