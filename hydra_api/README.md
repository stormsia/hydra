[← Back to Hydra README](../README.md)

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

# hydra_api

Orchestration, check scheduling, persistent storage, and REST API module for the Hydra proxy pool engine. Coordinates the checker engine (`hydra_checker`), interacts with validation judges (`hydra_judge`), and manages proxy states in libSQL (SQLite WAL).

## Directory Tree

```
hydra_api/
├── Cargo.toml                              # Cargo package manifest and dependencies
├── .env.example                            # Environment variables template
├── docs/API.md                             # Detailed REST API schemas and DTO specification
├── README.md                               # Module technical documentation
├── migrations/
│   └── 001_initial.sql                     # SQL migration for table schemas and B-Tree indexes
├── src/
│   ├── main.rs                             # Entry point: background services and HTTP server startup
│   ├── lib.rs                              # Library export and crypto provider initialization
│   ├── app_state.rs                        # Shared application state (AppState)
│   ├── config.rs                           # Environment configuration parsing and validation
│   ├── error.rs                            # API error types and HTTP status mappings
│   ├── router.rs                           # Axum routes, auth middleware, and Swagger UI
│   ├── db/
│   │   ├── mod.rs                          # Database access functions re-export
│   │   ├── init.rs                         # libSQL initialization, WAL PRAGMA settings, migrations
│   │   ├── proxies.rs                      # CRUD operations and due proxy queries
│   │   ├── sources.rs                      # Proxy source tracking and yield statistics
│   │   └── proxy_sources.rs                # M2M relations between proxies and sources
│   ├── handlers/
│   │   ├── mod.rs                          # HTTP route handlers re-export
│   │   ├── proxies.rs                      # CRUD, import, and failure report handlers
│   │   ├── sources.rs                      # Source management handlers
│   │   ├── stats.rs                        # Database metrics and in-memory telemetry handlers
│   │   └── judges.rs                       # Judge health and status handlers
│   ├── middleware/
│   │   ├── mod.rs                          # Middleware re-exports
│   │   └── auth.rs                         # X-API-Key authorization header validation
│   ├── models/
│   │   ├── mod.rs                          # Data models re-export
│   │   ├── api.rs                          # API request/response DTOs and utoipa schemas
│   │   └── db.rs                           # Database entity models (ProxyRow, SourceRow)
│   └── services/
│       ├── mod.rs                          # Background services re-export
│       ├── scheduler.rs                    # Periodic scheduler for due proxy re-checks
│       ├── batch_writer.rs                 # Non-blocking MPSC batch transactional database writer
│       ├── geoip.rs                        # Lock-free GeoIP/ASN resolver (MaxMind DB + ArcSwap)
│       ├── geoip_updater.rs                # Background mmdb updater using CDN ETag
│       ├── maintenance.rs                  # Stale record cleanup and WAL/PRAGMA optimization
│       └── parser.rs                       # Raw string proxy parser and Bogon IP filter
└── tests/
    ├── api_integration_tests.rs            # REST API integration tests
    ├── db_tests.rs                         # SQL query and migration integration tests
    ├── models_and_parser_tests.rs          # Proxy parser and model serialization tests
    └── scheduler_and_batch_writer_tests.rs # Scheduler queue and batching logic tests
```

## Core Subsystems

- **Router (Axum 0.8):** Handles incoming HTTP requests, enforces `X-API-Key` authentication, serves OpenAPI/Swagger UI, and dispatches to route handlers.
- **Scheduler:** Scans for due proxies (`next_check_at <= now`) every second and dispatches validation jobs to the checker pool adhering to timeout policies.
- **Batch Writer:** Non-blocking MPSC channel buffer aggregating validation outcomes and flushing them in atomic SQLite transactions every 100 ms.
- **GeoIP Resolver:** Lock-free IP enrichment with country and ASN metadata (MaxMind DB via `ArcSwap`) featuring automated CDN ETag updates.
- **Database (libSQL):** High-throughput local storage operating in WAL mode with `WITHOUT ROWID` clustered tables and 8 B-Tree indexes for sub-millisecond filtering.

## Environment Variables

All settings are read from the environment or `.env` file. All endpoints require the `X-API-Key: <API_KEY>` header.

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `LISTEN_ADDR` | String | `0.0.0.0:3000` | API bind address and port |
| `API_KEY` | String | — *(required)* | Master authorization key for X-API-Key header |
| `DB_PATH` | String | `./data/hydra.db` | libSQL database file path |
| `EMBED_JUDGE` | bool | `false` | Run embedded Judge echo server inside API process |
| `EMBED_JUDGE_PORT` | u16 | `8080` | Port for embedded Judge server |
| `CHECKER_CONCURRENCY` | usize | `5000` | Maximum concurrent checker validation tasks |
| `CHECKER_REAL_IP` | String | *(auto: consensus)* | Outbound public IP for Transparent proxy detection (defaults to dynamic judge consensus via majority vote; explicit value overrides) |
| `JUDGE_HTTP_URL` | String | `http://127.0.0.1:8080` | Judge echo server URL for HTTP checks |
| `JUDGE_HTTPS_URL` | String | `http://127.0.0.1:8080` | Judge echo server URL for HTTPS tunnel checks |
| `JUDGE_SECRET_TOKEN` | String | `hydra_secret_token` | Static verification token for judge response |
| `JUDGE_SECRET_KEY` | String | — | HMAC key for rolling daily secret tokens |
| `ENABLE_BUILTIN_JUDGE` | bool | `auto` | Enable builtin judge in selection pool (auto: true if embedded/custom URL, else false) |
| `ENABLE_THIRD_PARTY_JUDGES` | bool | `true` | Enable built-in third-party judge endpoints |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS` | u64 | `30` | Interval between judge health check sweeps |
| `JUDGE_SELECTION_STRATEGY` | String | `lowest_latency` | Strategy for choosing active judge endpoint |
| `ADDITIONAL_JUDGES` | String | — | Comma-separated extra judge URLs |
| `GEOIP_AUTO_UPDATE` | bool | `true` | Auto-download latest GeoIP MMDB from CDN |
| `GEOIP_COUNTRY_PATH` | String | `./geo/GeoLite2-Country.mmdb` | Local path to MaxMind Country MMDB |
| `GEOIP_ASN_PATH` | String | `./geo/GeoLite2-ASN.mmdb` | Local path to MaxMind ASN MMDB |
| `GEOIP_RELOAD_SECS` | u64 | `3600` | Interval to hot-reload MMDB files from disk |
| `GEOIP_UPDATE_INTERVAL_SECS` | u64 | `86400` | Interval between CDN update checks |
| `GEOIP_COUNTRY_URL` | String | `https://cdn.jsdelivr.net/...` | Remote download URL for Country MMDB |
| `GEOIP_ASN_URL` | String | `https://cdn.jsdelivr.net/...` | Remote download URL for ASN MMDB |
| `SCHEDULER_BATCH_SIZE` | usize | `10000` | Maximum proxies fetched per scheduler tick |
| `BATCH_FLUSH_INTERVAL_MS` | u64 | `100` | Buffer flush interval to database (ms) |
| `DEAD_PROXY_RETENTION_DAYS` | u32 | `30` | Retention window for dead proxies (days) |
| `DB_MAINTENANCE_INTERVAL_SECS` | u64 | `3600` | Database VACUUM / WAL maintenance interval |
| `RUST_LOG` | String | `info,hydra_api=debug` | System logging filter directive |

## API Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/proxies/import` | Batch import raw proxies into `cold_queue` |
| `GET` | `/api/v1/proxies` | Filtered proxy query (country, protocol, anonymity) |
| `GET` | `/api/v1/proxies/{id}` | Retrieve detailed proxy metadata by ID |
| `PATCH` | `/api/v1/proxies/{id}` | Partially update proxy parameters or check policy |
| `DELETE` | `/api/v1/proxies/{id}` | Permanently delete proxy from database |
| `POST` | `/api/v1/proxies/report-fail` | Report client connection failure and trigger cooldown |
| `GET` | `/api/v1/sources` | List proxy sources and yield statistics |
| `GET` | `/api/v1/sources/{name}` | Detailed statistics for a specific source |
| `DELETE` | `/api/v1/sources/{name}` | Delete source and disassociate linked records |
| `GET` | `/api/v1/judges` | Judge pool health status and RTT metrics |
| `POST` | `/api/v1/judges/health-check` | Force immediate health check across all judges |
| `GET` | `/api/v1/stats` | Global proxy pool statistics and DB metrics |
| `GET` | `/api/v1/stats/engine` | In-memory checker performance telemetry |
| `GET` | `/swagger-ui` | Interactive Swagger UI API documentation |
| `GET` | `/api-docs/openapi.json` | OpenAPI 3.0 specification in JSON format |

For detailed request schemas, DTO models, and response examples, refer to [../docs/API.md](../docs/API.md).

## Build & Run

### 1. Configure Environment

Linux / macOS:
```bash
cp .env.example .env
sed -i 's/API_KEY=.*/API_KEY=your_secure_key/' .env
```

Windows (PowerShell):
```powershell
Copy-Item .env.example .env
(Get-Content .env) -replace 'API_KEY=.*', 'API_KEY=your_secure_key' | Set-Content .env
```

### 2. Build and Launch

Linux / Windows:
```bash
# Run in debug/development mode
cargo run -p hydra_api

# Run in optimized release mode
cargo run --release -p hydra_api

# Compile release binary
cargo build --release -p hydra_api
```

### 3. Testing

```bash
cargo test -p hydra_api
```
