<div align="center">

<img src="assets/logo.svg" alt="Hydra Logo" width="100%" style="max-width: 100%; height: auto;">

# Hydra — High-Performance Rust Proxy Checker, Validator & Pool Engine

[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-0ea5e9.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-10b981.svg?style=flat-square)](LICENSE)
[![Tokio Runtime](https://img.shields.io/badge/async-tokio%201.43-0ea5e9.svg?style=flat-square&logo=tokio)](https://tokio.rs/)
[![Speed](https://img.shields.io/badge/speed-8%2C300%2B%20checks%2Fsec-10b981.svg?style=flat-square)](docs/BENCHMARK_RESULTS.md)
[![Protocols](https://img.shields.io/badge/protocols-SOCKS5%20%7C%20SOCKS4%20%7C%20HTTP-64748b.svg?style=flat-square)](docs/API.md)
[![Storage: libSQL](https://img.shields.io/badge/storage-libSQL%20WAL-0ea5e9.svg?style=flat-square)](hydra_api/README.md)
[![OpenAPI 3.0](https://img.shields.io/badge/OpenAPI-3.0%20%2F%20Swagger-10b981.svg?style=flat-square&logo=swagger)](docs/API.md)
[![Tested Scale: 10M](https://img.shields.io/badge/tested%20scale-10M%20proxies-0ea5e9.svg?style=flat-square)](docs/BENCHMARK_RESULTS.md)

<p align="center">
  <b>Ultra-fast proxy checker & pool orchestrator in Rust.</b><br>
  Ingests raw proxy lists (14k/s), cascades SOCKS5/SOCKS4/HTTP validation, handles GeoIP & SLA policies. Zero-lock libSQL storage, 8.3k checks/s, OpenAPI/Swagger REST API. Built for high-concurrency data scraping pipelines.
</p>

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

<br>

[⚡ Quick Start](#quick-start) • [✨ Features & Benefits](#features) • [📊 Benchmarks](#benchmarks) • [⚖️ Comparison](#comparison) • [📐 Architecture](#architecture) • [⚙️ Configuration](#configuration) • [📖 REST API](docs/API.md)

</div>

---

> [!NOTE]
> **Who is Hydra built for?** Hydra solves out-of-memory crashes when scanning hundreds of thousands of IPs, completely eliminates `database locked` contention errors, prevents OS socket leaks and port exhaustion (`TIME_WAIT`), and automatically normalizes raw proxy lists from hundreds of heterogeneous providers.

### 🎯 Three Key Advantages:

1. **Zero-Config Ingestion of Any Format (14,000+ proxies/sec)**: Ingest raw, messy proxy lists without prior manual cleaning — automatically parsing `ip:port`, `ip:port:user:pass`, `user:pass@ip:port`, URL schemes, IPv6 (`[::1]:port`), and structured JSON. Hydra discards Bogon/Private IPs on the fly and performs cascading protocol auto-detection (`SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP`).
2. **Granular Lifecycle Policies (Custom SLA per Pool)**: Fine-grained verification control via customizable Check Policies — distinct timeouts (L4 Connect, L7 Handshake, I/O), scheduled recheck intervals for alive nodes, differentiated exponential quarantine backoff (`dead_backoff_mult_zero` / `dead_backoff_mult_active`), and configurable failure thresholds (`max_dead_strikes_zero` / `max_dead_strikes_active`). The background scheduler keeps the pool healthy 24/7.
3. **0.06 ms Lookup Latency & Zero Database Locks**: Clustered tables and 8 specialized B-Tree indexes under SQLite WAL mode deliver sub-millisecond filtering across country, ASN, protocol, and anonymity levels. An MPSC micro-batching architecture (committing every 100 ms) guarantees 100% transactional stability even under a sustained concurrent load of 10,000,000 proxies.

---

## <a id="quick-start"></a>🚀 Quick Start Guide

> [!IMPORTANT]
> **System Requirements:**
> * **Rust compiler >= 1.85** (supporting the `Rust 2024` edition).
> * **Git** command line utility.

### 1. Clone & Configure Environment
```bash
git clone https://github.com/stormsia/hydra.git
cd hydra
cp .env.example .env
```

In `.env`, set your secure API master key:
```env
API_KEY=my_secure_hydra_key_12345
```

### 2. Build Monorepo

#### Standard Release Build:
```bash
cargo build --workspace --release
```

#### Maximum Performance (enabling native AVX2/BMI2 instructions of host CPU):
```bash
# Linux / macOS (Bash):
RUSTFLAGS="-C target-cpu=native" cargo build --workspace --release
```
```powershell
# Windows (PowerShell):
$env:RUSTFLAGS="-C target-cpu=native"; cargo build --workspace --release
```
```cmd
REM Windows (CMD):
set RUSTFLAGS=-C target-cpu=native && cargo build --workspace --release
```

### 3. Running

> [!TIP]
> By default, `EMBED_JUDGE` is set to `false`. For an instant local **All-In-One** deployment (running an embedded anonymity verification Judge inside the API process), set `EMBED_JUDGE=true` in your environment or inside `.env`.

#### 🐧 Linux / macOS:
```bash
# Increase open file socket limits (critical for 5,000+ concurrent workers)
ulimit -n 65535

# Run in All-In-One mode (embedded Judge echo server on port 8080):
EMBED_JUDGE=true ./target/release/hydra_api

# Background production daemon (nohup):
nohup ./target/release/hydra_api > hydra_api.log 2>&1 &
```

#### 🪟 Windows (PowerShell):
```powershell
# Run in All-In-One mode:
$env:EMBED_JUDGE="true"; .\target\release\hydra_api.exe
```

#### Standalone Dedicated L7 Judge (Production):
In distributed setups, judges are deployed as separate standalone instances across different regions:
```bash
# Start standalone high-throughput echo server
./target/release/hydra_judge
```

Once running, the following endpoints are available:
* 📖 **Interactive Swagger UI:** [http://127.0.0.1:3000/swagger-ui](http://127.0.0.1:3000/swagger-ui)
* 📋 **OpenAPI 3.0 Specification (JSON):** [http://127.0.0.1:3000/api-docs/openapi.json](http://127.0.0.1:3000/api-docs/openapi.json)
* ⚡ **Real-time Engine Telemetry:**
  ```bash
  curl -H "X-API-Key: my_secure_hydra_key_12345" http://127.0.0.1:3000/api/v1/stats/engine
  ```

---

## <a id="features"></a>⚡ Features & Architectural Decisions

| Challenge / Bottleneck | How Hydra Solves It | Result / Benefit |
|---|---|---|
| **Messy formats from hundreds of providers** | **Zero-Config parser with auto-detection**: parses `ip:port`, `ip:port:user:pass`, URL notation, IPv6, and JSON | Zero manual list cleaning; ingest throughput up to **14,000+ proxies/sec** |
| **Unknown proxy protocols** | **Cascading protocol auto-detection**: `SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP` | No need to know proxy types in advance: engine infers working protocol automatically |
| **Differing SLA requirements per pool** | **Granular lifecycle policies**: customizable L4/L7 timeouts, recheck intervals, stability window | Each pool/source can be assigned an isolated Check Policy |
| **Database lock contention under heavy writes** | Non-blocking **MPSC Micro-Batching (100 ms)** with **SQLite WAL** mode | Up to **8,340 checks/sec** write throughput and **14,000+ proxies/sec** import with **zero `database locked` errors** |
| **Socket leaks and port exhaustion (`TIME_WAIT`)** | Low-level socket control with **`SO_LINGER=0` (TCP RST drop)** | Zero descriptor accumulation across 5,000+ concurrent workers |
| **Wasted bandwidth on dead IPs** | **4-Phase Fail-Fast Pipeline**: L4 Connect &rarr; Handshake &rarr; TLS/Judge &rarr; Anonymity Verdict | Up to 95% bandwidth and socket savings by discarding dead IPs at the SYN stage |
| **Single point of failure for verification judges** | **Dynamic Failover Judge Pool** (`lowest_latency` / consensus) | Seamless failover across healthy mirrors; automatically resolves checker public IP via majority-vote consensus |
| **Echo server abuse by public port scanners** | **Anti-Abuse Token Guard** + 24h rolling sliding-window **HMAC-SHA256** | Unauthorized bots (Shodan, Censys) are immediately dropped with TCP RST |
| **Outdated geolocation databases** | **Lock-Free GeoIP/ASN via `ArcSwap`** with HTTP ETag auto-updates | MaxMind databases update on the fly without Tokio runtime pauses or restarts |
| **Downstream target site rate limits/bans** | Feedback loop via **`POST /api/v1/proxies/report-fail`** | Failed proxies immediately quarantined into `cooldown` with exponential backoff |

---

## <a id="comparison"></a>⚖️ Comparison with Alternatives

| Feature / Engine | **Hydra** | **[ProxyBroker](https://github.com/bluet/proxybroker2)** | **[proxypool](https://github.com/henson/proxypool)** | **[proxy-checker](https://www.npmjs.com/package/proxy-checker)** |
|---|:---:|:---:|:---:|:---:|
| **Language & Runtime** | **Rust 2024 (Tokio 1.43)** | Python (asyncio) | Go (goroutines) | Node.js (JavaScript) |
| **Check Throughput** | **2,100 – 8,340+ checks/sec** | ~100 – 250 checks/sec | ~400 – 800 checks/sec | ~200 – 500 checks/sec |
| **Tested Pool Capacity** | **10,000,000+ proxies** | < 50,000 (OOM leaks) | < 200,000 (Redis bottlenecks) | < 100,000 (GC pauses) |
| **RAM Footprint under Load** | **~92 MB RAM** | 400 – 900+ MB | 250 – 500 MB | 300 – 700 MB |
| **TIME_WAIT Socket Elimination** | **Yes (`SO_LINGER=0` TCP RST)** | No (OS socket defaults) | Partial | No |
| **Persistence Layer** | **Embedded libSQL/WAL (MPSC)** | SQLite (locks under load) | External Redis | MongoDB / In-memory |
| **Granular SLA Policies per Pool** | **Yes (isolated recheck schedules)** | No (global flags only) | No | No |
| **Anti-Scan Judge Defense (HMAC)** | **Yes (24h sliding window)** | No | No | No |
| **Cascading Protocol Fallback** | **SOCKS5/4 &rarr; CONNECT &rarr; HTTP** | Limited | Limited | Manual selection |

---

## <a id="benchmarks"></a>📊 Performance Benchmarks (10M Proxy Stress-Test & Latency)

Stress-test results under **5,000 concurrent workers** on a dataset of **10,000,000 proxies** (`hydra.db` file size: 3.57 GB).

> [!NOTE]
> REST API latencies were measured **under 100% concurrent network checker load** (5,000 workers continuously validating and batch-writing). Raw internal SQL query overhead using clustered B-Tree indexes is **0.06 ms** (by ID: **0.01 ms**).

| Metric | Measured Value | Conditions & Context |
|---|:---:|---|
| **Proxy Import via REST API** | **14,096 proxies/sec** | JSON deserialization, bogon filtering, deduplication, and batch write |
| **Sustained Continuous Check Speed** | **2,111.5 checks/sec** | **~7.6 million checks/hour** (380,725 checks in 3 minutes) |
| **Peak Check Speed** | **8,340.0 checks/sec** | During massive parallel TCP session termination / handshake drops |
| **RAM Usage (5,000 workers)** | **92.4 MB (avg) / 136.4 MB (peak)** | Zero memory leaks on a 10M record pool |
| **CPU Usage (5,000 workers)** | **25.8% (avg) / 47.6% (peak)** | Evenly distributed across the Tokio thread pool |
| **Database Locks (`database locked`)** | **0 errors** | Guaranteed by transactional MPSC micro-batching buffer (100 ms) |
| **API Latency: Fast Query (`limit=50`)** | **~25.6 ms** | **Under 100% checker load** on 10M DB (end-to-end HTTP RTT) |
| **API Latency: Geo Filter (`country=US`)** | **~67.2 ms** | **Under 100% checker load** with dynamic RTT sorting |
| **Engine Telemetry (`GET /api/v1/stats/engine`)** | **< 1.0 ms** | Pure in-memory atomic counters without disk access |

> 🔬 Full measurement logs and testing methodology: [docs/BENCHMARK_RESULTS.md](docs/BENCHMARK_RESULTS.md).

---

## 📦 Workspace Crates

The repository is architected as a modular Cargo workspace:

```
Hydra Monorepo
├── hydra_api       — REST API (Axum), recheck scheduler, MPSC batcher, libSQL storage, Swagger UI
├── hydra_checker   — Non-blocking network validation core, protocol stack, judge pool & filtering
└── hydra_judge     — High-speed zero-framework L7 echo server with anti-scan & HMAC token protection
```

| Crate | Purpose | Documentation |
|---|---|:---:|
| **`hydra_api`** | Lifecycle orchestration, REST API, Swagger UI, proxy retrieval, background scheduler | [Crate README](hydra_api/README.md) • [API Specification](docs/API.md) |
| **`hydra_checker`** | Network validation core, cascading auto-detect, latency timing, and anonymity scoring | [Crate README](hydra_checker/README.md) |
| **`hydra_judge`** | High-performance echo server for header mirroring and real IP detection with RST defense | [Crate README](hydra_judge/README.md) |

---

## <a id="architecture"></a>📐 Monorepo Architecture

```mermaid
flowchart LR
    classDef client fill:#1e293b,stroke:#0ea5e9,stroke-width:2px,color:#f8fafc;
    classDef api fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef checker fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#f8fafc;
    classDef judge fill:#134e4a,stroke:#14b8a6,stroke-width:2px,color:#f8fafc;
    classDef storage fill:#312e81,stroke:#6366f1,stroke-width:2px,color:#f8fafc;

    subgraph Clients["Clients"]
        Scrapers["Scrapers / Bots"]:::client
        SwaggerUI["Swagger UI / CLI"]:::client
    end

    subgraph API["hydra_api"]
        Auth["X-API-Key Guard"]:::api
        Endpoints["REST API (/api/v1)"]:::api
        Scheduler["Scheduler Daemon (1s)"]:::api
        BatchWriter["MPSC Writer (100ms)"]:::api
        Maintenance["DB Maintenance (1h)"]:::api
    end

    subgraph Checker["hydra_checker"]
        PreFlight["Pre-flight Filter"]:::checker
        L4Probe["Phase 1: L4 TCP Probe"]:::checker
        Cascade["Phase 2: Protocol Cascade"]:::checker
        L7Probe["Phase 3: L7 Validation"]:::checker
        Verdict["Phase 4: Anonymity Verdict"]:::checker
        JudgePool["Judge Failover Pool"]:::checker
    end

    subgraph Judges["Echo Judges"]
        HydraJudge["hydra_judge (HMAC Guard)"]:::judge
        ExternalJudges["External Fallback Judges"]:::judge
    end

    subgraph Storage["Storage Layer"]
        DB[("libSQL / SQLite WAL<br/>WITHOUT ROWID (8 indexes)")]:::storage
    end

    Scrapers --> Auth
    SwaggerUI --> Auth
    Auth --> Endpoints
    Endpoints -->|"Fetch alive (0.06 ms)"| DB

    Scheduler -->|"Query due candidates"| DB
    Scheduler -->|"Dispatch check task"| PreFlight

    PreFlight --> L4Probe --> Cascade --> L7Probe --> Verdict
    L7Probe --> JudgePool
    JudgePool -->|"Tokenized probe"| HydraJudge
    JudgePool -.->|"Auto-failover"| ExternalJudges

    Verdict -->|"Verification verdict"| BatchWriter
    BatchWriter -->|"BEGIN IMMEDIATE batch"| DB
    Maintenance -->|"Cleanup & incremental_vacuum"| DB
```

> [!NOTE]
> **Judge Failover Pool & Dynamic Anonymity Detection**: During Phase 4, proxy anonymity (Elite, Anonymous, Transparent) is classified by checking whether the client's public IP leaks in echoed headers (`REMOTE_ADDR`, `X-Forwarded-For`, `Via`). If `CHECKER_REAL_IPS` / `CHECKER_REAL_IP` is unset, the engine dynamically auto-discovers its outbound network identity (`HostIdentity`) by combining local interface inspection with background health check loops across healthy judges, tracking all public IPv4s and routed `/64` IPv6 subnets (defeating ephemeral SLAAC privacy address rotations and multi-WAN setups). Explicitly setting `CHECKER_REAL_IPS` or `CHECKER_REAL_IP` overrides auto-discovery.

---

## 🔄 Deterministic Proxy Lifecycle

Deterministic state transitions prevent lost working nodes and eliminate infinite checking loops on dead proxies:

```mermaid
stateDiagram-v2
    [*] --> cold_queue: Imported into system (state=0, strikes=0)
    cold_queue --> alive: Initial validation passes (state=1)
    cold_queue --> cooldown: Connection error (state=2, strikes=1)

    alive --> alive: Scheduled recheck passes (recheck_alive_sec)
    alive --> cooldown: Recheck fails OR client POST /report-fail

    cooldown --> alive: Quarantine recheck passes (strikes reset to 0)
    cooldown --> cooldown: Repeated failure (strikes < strike_limit)
    cooldown --> dead_permanent: Strike threshold reached (state=3)

    dead_permanent --> cold_queue: Re-imported with revive_dead=true
    dead_permanent --> [*]: Physically pruned by background daemon (>30 days)
```

> [!NOTE]
> Exponential backoff equations and recheck policy parameters are detailed in [CheckPolicyDto Specification](docs/API.md#13-check-policy-and-recheck-scheduling-checkpolicydto).

---

## 🔍 Quick REST API Usage Examples

### 1. Batch Import Proxies (Strings or Objects with Custom Policies)
```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/import \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  -d '{
    "source": "datacenter_feed_1",
    "revive_dead": true,
    "proxies": [
      "socks5://alice:secret123@185.220.101.5:1080",
      "195.154.255.3:8080"
    ]
  }'
```

### 2. Query Verified Proxies with Multi-Criteria Filters
```bash
curl -X GET "http://127.0.0.1:3000/api/v1/proxies?country=DE&anon=elite&protocol=socks5&limit=10" \
  -H "X-API-Key: my_secure_hydra_key_12345"
```

### 3. Report Downstream Target Failure (Immediate Quarantine)
```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  -d '{
    "ids": ["185.220.101.5:1080:alice:secret123"],
    "reason": "Target rate limited (HTTP 429)"
  }'
```

> 📖 Full reference of all 13 endpoints with request and response schemas: [docs/API.md](docs/API.md).

---

## <a id="configuration"></a>⚙️ Environment Configuration (.env)

### Core Parameters

| Variable | Type | Default | Required | Description |
|---|:---:|:---:|:---:|---|
| `API_KEY` | `String` | *(none)* | **Yes** | Master secret key for `X-API-Key` request header authentication. |
| `LISTEN_ADDR` | `SocketAddr` | `0.0.0.0:3000` | No | Bind socket address for API server and Swagger UI. |
| `DB_PATH` | `String` | `./data/hydra.db` | No | File path to libSQL/SQLite database (WAL mode). |
| `EMBED_JUDGE` | `bool` | `false` | No | Run embedded Judge inside API process (All-In-One mode). |
| `EMBED_JUDGE_PORT` | `u16` | `8080` | No | Port for embedded anonymity evaluation judge. |
| `JUDGE_HTTP_URL` | `Url` | `http://127.0.0.1:8080` | No | HTTP URL for checking plain HTTP proxy forwarding. |
| `JUDGE_HTTPS_URL` | `Url` | `http://127.0.0.1:8080` | No | HTTPS URL for checking CONNECT and SOCKS tunnels. |
| `JUDGE_SECRET_TOKEN` | `String` | `hydra_secret_token` | No | Static validation token for verifying judge echo response. |
| `CHECKER_CONCURRENCY` | `usize` | `5000` | No | Maximum number of concurrent network verification tasks. |
| `CHECKER_REAL_IP` | `IpAddr` | *(auto: interfaces + judges)* | No | Outbound public IP of checker host for Transparent proxy detection. Supports `CHECKER_REAL_IPS` for multiple IPs and CIDR subnets (e.g. `203.0.113.1,2001:db8::/64`); defaults to composite auto-discovery combining host interfaces and judge consensus. |
| `ENABLE_BUILTIN_JUDGE` | `bool` | *(auto)* | No | Enable builtin judge in selection pool (true if embedded or custom URL, else false). |
| `ENABLE_THIRD_PARTY_JUDGES` | `bool` | `true` | No | Enable public fallback judges (Httpbingo, Httpbin) for failover. |
| `JUDGE_SELECTION_STRATEGY` | `String` | `lowest_latency` | No | Judge selection algorithm: `lowest_latency`, `priority`, `round_robin`. |
| `GEOIP_AUTO_UPDATE` | `bool` | `true` | No | Automatically download and refresh MaxMind databases via HTTP ETag. |

<details>
<summary>👉 <b>Expand Advanced Tuning Parameters (Timeouts, GeoIP paths, HMAC rotation, Scheduler)</b></summary>

| Variable | Type | Default | Description |
|---|:---:|:---:|---|
| `GEOIP_COUNTRY_PATH` | `String` | `./geo/GeoLite2-Country.mmdb` | Path to local MaxMind Country MMDB file. |
| `GEOIP_ASN_PATH` | `String` | `./geo/GeoLite2-ASN.mmdb` | Path to local MaxMind ASN MMDB file. |
| `GEOIP_RELOAD_SECS` | `u64` | `3600` | Memory reload period for MMDB files (seconds). |
| `GEOIP_UPDATE_INTERVAL_SECS` | `u64` | `86400` | Upstream check interval for fresh MaxMind databases (seconds). |
| `GEOIP_COUNTRY_URL` | `String` | *(jsdelivr mirror)* | HTTP URL for downloading GeoLite2-Country.mmdb.gz. |
| `GEOIP_ASN_URL` | `String` | *(jsdelivr mirror)* | HTTP URL for downloading GeoLite2-ASN.mmdb.gz. |
| `JUDGE_SECRET_KEY` | `String` | *(none)* | HMAC-SHA256 secret key for 24-hour sliding token rotation. |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS`| `u64` | `30` | Health check and RTT ping interval for judges (seconds). |
| `ADDITIONAL_JUDGES` | `String` | *(none)* | Custom additional judges (`HTTP_URL\|HTTPS_URL,...`). |
| `CHECKER_CONNECT_TIMEOUT_MS` | `u64` | `3000` | L4 TCP SYN connection timeout to proxy socket (ms). |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | `u64` | `4000` | Tunnel handshake timeout (SOCKS, HTTP CONNECT) (ms). |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | `u64` | `5000` | Data exchange I/O timeout with judge through proxy tunnel (ms). |
| `CHECKER_MAX_READ_BYTES` | `usize` | `8192` | Max allowed read response payload (defense against memory tarpits). |
| `CHECKER_LOCAL_BIND_IP` | `IpAddr` | *(none)* | Bind outbound checker sockets to a specific local interface IP. |
| `SCHEDULER_BATCH_SIZE` | `usize` | `10000` | Number of due candidate proxies polled by scheduler per second. |
| `BATCH_FLUSH_INTERVAL_MS` | `u64` | `100` | Transactional flush interval for MPSC result buffer into DB (ms). |
| `DEAD_PROXY_RETENTION_DAYS` | `u32` | `30` | Retention duration in days for dead nodes before physical deletion. |
| `DB_MAINTENANCE_INTERVAL_SECS` | `u64` | `3600` | Interval for background maintenance (`PRAGMA incremental_vacuum`). |
| `RUST_LOG` | `String` | `info` | Logging verbosity and tracing filter (`tracing`). |

</details>

---

## 🛠️ Development & Testing

```bash
# Run full workspace test suite
cargo test --workspace

# Run tests for specific crates
cargo test -p hydra_checker
cargo test -p hydra_judge
cargo test -p hydra_api

# Check formatting and run Clippy static analysis
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 🤝 Contributing

We warmly welcome Pull Requests, bug reports, and performance optimization proposals!
Please review the contribution guidelines:
👉 **[Contributor Guide (CONTRIBUTING.md)](CONTRIBUTING.md)**.

---

## 📄 License

Hydra is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
