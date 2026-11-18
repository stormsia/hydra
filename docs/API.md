[← Back to Hydra README](../README.md) | [English](API.md) • [Русский](API.ru.md) • [简体中文](API.zh.md)

# Hydra REST API

Base URL: `http://127.0.0.1:3000`  
Authentication: HTTP header `X-API-Key: <token>` (configured via `API_KEY` environment variable). The endpoints `/swagger-ui` and `/api-docs/openapi.json` are public.

---

## 1. Reference Schemas & Definitions

### 1.1. Lifecycle States (`ProxyState`)

| State Value (`state`) | Code | Description |
|---|---|---|
| `cold_queue` | `0` | Newly ingested proxy awaiting its initial check in the pre-flight testing queue. |
| `alive` | `1` | Validated, operational proxy in active pool confirmed by an echo judge. Ready for client rotation. |
| `cooldown` | `2` | Quarantined following a verification error or client fail report. Scheduled for exponential backoff recheck. |
| `dead_permanent` | `3` | Consecutive failure threshold exceeded (`max_dead_strikes`). Excluded from scheduling queues. |

### 1.2. Protocols and Anonymity Levels

| Parameter | Allowed Values | Description |
|---|---|---|
| `protocol` | `socks5`, `socks4`, `http` | Network protocol. For `http`, support for HTTPS CONNECT tunneling (`supports_https`) is verified. |
| `anon` | `elite` | High anonymity: proxy headers and client original IP are hidden (no `Via`, `X-Forwarded-For`). |
| | `anonymous` | Medium anonymity: proxy presence is signaled to the target server, but client real IP is obscured. |
| | `transparent` | Transparent: real client IP address is forwarded to the destination in request headers. |

### 1.3. Check Policy and Recheck Scheduling (`CheckPolicyDto`)

Network timeouts, degradation thresholds, and background scheduler settings. Configured during pool ingestion (`POST /api/v1/proxies/import`) or patched individually via `PATCH /api/v1/proxies/{id}`.

| JSON Field | Type | Default | Range | Exact Purpose & Influence on Scheduler / Checker |
|---|---|---|---|---|
| `connect_timeout_ms` | `u32` | `3000` (ms) | `100` – `60000` | Maximum timeout for establishing initial TCP SYN connection to proxy socket. Exceeding triggers a `connect` phase failure. |
| `handshake_timeout_ms` | `u32` | `4000` (ms) | `100` – `60000` | Maximum timeout for protocol handshake (SOCKS auth / SSL/TLS handshake / HTTP CONNECT). Exceeding triggers a `handshake` phase failure. |
| `rw_timeout_ms` | `u32` | `5000` (ms) | `100` – `60000` | Maximum timeout for sending test HTTP request and reading full response from judge (I/O). Exceeding triggers a `rw timeout` phase failure. |
| `recheck_alive_sec` | `u32` | `60` (s) | `10` – `86400` | Interval for routine background re-validation of healthy `alive` proxies. On success, scheduler sets `next_check_at = now + recheck_alive_sec`. |
| `recheck_dead_sec` | `u32` | `1800` (s) | `30` – `604800` | Base recheck interval for quarantined nodes in `cooldown`. Serves as base delay for exponential backoff. When set to `0`, proxy transitions directly to `dead_permanent`. |
| `max_dead_strikes` | `u32` | `3` | `1` – `50` | Maximum allowed consecutive failures (`dead_strikes`). Once reached, proxy is permanently transitioned to `dead_permanent` (code `3`) and excluded from active queues. |
| `stability_window_min` | `u32` | `5` (min) | `1` – `1440` | Sliding time window (minutes) for calculating `stability_pct`. Check history older than `(now - stability_window_min * 60)` is discarded. Aliases: `stability_window`, `window_min`, `window_minutes`. |
| `dead_backoff_mult` | `f32` | `1.5` | `1.0` – `10.0` | Exponential backoff multiplier for calculating penalty recheck delays in `cooldown`. If `1.0`, recheck interval remains constant. Aliases: `backoff_multiplier`, `recheck_dead_multiplier`, `dead_multiplier`, `recheck_dead_mult`, `multiplier`. |

**Exponential Backoff Formula in `cooldown`:**

When a check fails, consecutive strikes increment: `new_strikes = current_strikes + 1`. If `strikes < max_dead_strikes`, proxy is put into or retained in `cooldown`, with delay calculated as:

`interval = recheck_dead_sec * (dead_backoff_mult ^ (strikes - 1))`

> *Note:* Computed `interval` is clamped between 1 second and 30 days: `clamp(1, 2592000)` seconds. Next check is scheduled as `next_check_at = now + interval`. If `strikes >= max_dead_strikes`, proxy moves to terminal state `dead_permanent` (code `3`).

> **Proxy Identifier Format (`id`):** `ip:port` (for public proxies) or `ip:port:user:pass` (for authenticated proxies). Special characters (`:`, `@`, `#`, `/`) in URL paths (`/api/v1/proxies/{id}`) **must** be percent-encoded (e.g. `1.2.3.4%3A8080%3Au%40ser%3Ap%23ass`).

---

## 2. API Routes

### Group 1: Proxies

#### `POST /api/v1/proxies/import`
Batch ingestion of raw proxies into `cold_queue` with validation, deduplication, and source binding.

- **Request Body (JSON):**
  ```json
  {
    "source": "premium_pool_v1",
    "source_url": "https://provider.example.com/feed.txt",
    "remark": "Corporate subnet proxies",
    "revive_dead": true,
    "ignore_protocol": false,
    "policy": {
      "connect_timeout_ms": 3000,
      "handshake_timeout_ms": 4000,
      "rw_timeout_ms": 5000,
      "recheck_alive_sec": 60,
      "recheck_dead_sec": 1800,
      "max_dead_strikes": 3,
      "stability_window_min": 5,
      "dead_backoff_mult": 1.5
    },
    "proxies": [
      "socks5://user:pass@185.220.101.5:1080",
      "195.154.255.3:8080",
      {
        "ip": "185.220.101.6",
        "port": 1080,
        "protocol": "socks5",
        "auth_user": "myuser",
        "auth_pass": "mypassword",
        "ignore_protocol": false
      }
    ]
  }
  ```
  - `revive_dead` *(bool, def: false)*: Reset strike counters and revive existing `dead_permanent` proxies back to `cold_queue`.
  - `ignore_protocol` *(bool, def: false)*: Ignore provided protocol and initiate cascading auto-detect (SOCKS5 → SOCKS4 → HTTP).
  - `policy` *(object, opt)*: Override network timeouts and recheck scheduling for this pool (see [Section 1.3](#13-check-policy-and-recheck-scheduling-checkpolicydto)). Defaults applied if omitted.
  - `proxies` *(array)*: Elements in string format (`proto://user:pass@ip:port`, `ip:port:user:pass`, `ip:port`, `[ipv6]:port`) or JSON objects.

- **Response `200 OK` (JSON):**
  ```json
  {
    "source_id": 1,
    "total_received": 3,
    "inserted_new": 2,
    "updated_existing": 1,
    "revived": 0,
    "invalid_format": 0
  }
  ```
- **Errors:** `400 Bad Request` (missing `source`), `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X POST http://127.0.0.1:3000/api/v1/proxies/import -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"source":"p1","proxies":["socks5://u:p@1.2.3.4:1080","5.6.7.8:8080"]}'
  ```

---

#### `GET /api/v1/proxies`
Filtered and paginated retrieval of proxies based on network health, geography, and performance metrics.

- **Query Parameters:**
  | Parameter | Type | Default | Description |
  |---|---|---|---|
  | `state` | string | `alive` | Status filter: `alive`, `cold_queue`, `cooldown`, `dead_permanent`. |
  | `country` | string | — | ISO 2-letter country code or comma-separated list (`DE` or `DE,NL,FR`). |
  | `exclude_country` | string | — | Excluded country codes comma-separated (`RU,CN`). |
  | `protocol` | string | — | Protocol filter: `socks5`, `http`, `socks4`. |
  | `anon` | string | — | Anonymity level: `elite`, `anonymous`, `transparent`. |
  | `supports_https` | bool | — | HTTPS CONNECT tunneling support (`true`/`false`). |
  | `has_auth` | bool | — | Authentication filter (`true` for private, `false` for public). |
  | `max_rtt` | u32 | — | Maximum acceptable total RTT (ms). |
  | `min_uptime` | f32 | — | Minimum lifetime uptime percentage (0.0 — 100.0 %). |
  | `min_stability` | f32 | — | Minimum stability score within sliding window (0.0 — 100.0 %). |
  | `stability_window_min` | u32 | — | Sliding window size for stability calculation (minutes). |
  | `source` | string | — | Source name filter. |
  | `limit` | u32 | `50` | Result limit. `0` disables limit (exports entire pool). |
  | `offset` | u32 | `0` | Pagination offset. |

- **Response `200 OK` (JSON):**
  ```json
  [
    {
      "id": "185.220.101.5:1080:user:secret123",
      "ip": "185.220.101.5",
      "port": 1080,
      "url": "socks5://user:secret123@185.220.101.5:1080",
      "protocol": "socks5",
      "has_auth": true,
      "auth_user": "user",
      "auth_pass": "secret123",
      "state": "alive",
      "supports_https": true,
      "out_ip": "185.220.101.5",
      "country": "DE",
      "asn": 24940,
      "asn_org": "Hetzner Online GmbH",
      "anon": "elite",
      "rtt_tcp_ms": 42,
      "rtt_handshake_ms": 68,
      "rtt_total_ms": 110,
      "uptime_pct": 98.5,
      "stability_pct": 100.0,
      "stability_window_min": 5,
      "checks_total": 450,
      "checks_success": 445,
      "dead_strikes": 0,
      "last_error": null,
      "remark": "High performance German node",
      "first_seen_at": 1731200000,
      "last_checked_at": 1731256800,
      "next_check_at": 1731256860
    }
  ]
  ```
- **Errors:** `400 Bad Request`, `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/proxies?state=alive&protocol=socks5&country=DE&limit=10" -H "X-API-Key: $KEY"
  ```

---

#### `POST /api/v1/proxies/report-fail`
Client-side notification of proxy failure: downgrades node to `cooldown`, increments `dead_strikes`, and schedules an immediate recheck.

- **Request Body (JSON):**
  ```json
  {
    "ids": [
      "185.220.101.5:1080:myuser:mypassword",
      "195.154.255.3:8080"
    ],
    "reason": "Connection reset by peer during target handshake"
  }
  ```
  *(Supports both single `id: "..."` and array `ids: ["..."]`)*.

- **Response `200 OK` (JSON):**
  ```json
  {
    "status": "reported",
    "affected_count": 2,
    "reported_ids": [
      "185.220.101.5:1080:myuser:mypassword",
      "195.154.255.3:8080"
    ],
    "proxy_id": "185.220.101.5:1080:myuser:mypassword"
  }
  ```
- **Errors:** `400 Bad Request` (missing `id`/`ids` or blank `reason`), `401 Unauthorized`, `404 Not Found` (no matching proxies found in `alive` state), `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"ids":["195.154.255.3:8080"],"reason":"target ban"}'
  ```

---

#### `GET /api/v1/proxies/{id}`
Retrieve complete proxy details with configured check policies (see [Section 1.3](#13-check-policy-and-recheck-scheduling-checkpolicydto)), latency breakdown, and linked sources.

- **Path Parameters:** `id` *(string, URL-encoded)* — proxy identifier (`ip:port` or `ip:port:user:pass`).
- **Response `200 OK` (JSON):**
  ```json
  {
    "id": "185.220.101.5:1080:user:secret123",
    "ip": "185.220.101.5",
    "port": 1080,
    "url": "socks5://user:secret123@185.220.101.5:1080",
    "has_auth": true,
    "auth_user": "user",
    "auth_pass": "secret123",
    "state": "alive",
    "protocol": "socks5",
    "supports_https": true,
    "out_ip": "185.220.101.5",
    "country": "DE",
    "asn": 24940,
    "asn_org": "Hetzner Online GmbH",
    "anon": "elite",
    "metrics": {
      "rtt_tcp_ms": 42,
      "rtt_handshake_ms": 68,
      "rtt_total_ms": 110
    },
    "policy": {
      "connect_timeout_ms": 3000,
      "handshake_timeout_ms": 4000,
      "rw_timeout_ms": 5000,
      "recheck_alive_sec": 60,
      "recheck_dead_sec": 1800,
      "max_dead_strikes": 3,
      "stability_window_min": 5,
      "dead_backoff_mult": 1.5
    },
    "stats": {
      "checks_total": 450,
      "checks_success": 445,
      "uptime_pct": 98.88,
      "stability_pct": 100.0,
      "dead_strikes": 0,
      "last_error": null,
      "first_seen_at": 1731200000,
      "last_checked_at": 1731256800,
      "next_check_at": 1731256860
    },
    "meta": {
      "remark": "High performance German node",
      "sources": ["premium_pool_v1", "backup_tor_feed"],
      "source_details": [
        { "name": "premium_pool_v1", "added_at": 1731200000 },
        { "name": "backup_tor_feed", "added_at": 1731210000 }
      ]
    }
  }
  ```
- **Errors:** `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY"
  ```

---

#### `PATCH /api/v1/proxies/{id}`
Partial update of metadata, credentials, Check Policy timeouts, or triggering an immediate recheck.

- **Path Parameters:** `id` *(string, URL-encoded)*.
- **Request Body (JSON):**
  ```json
  {
    "remark": "Reserved for scraper worker #4",
    "auth_user": "myuser",
    "auth_pass": "mypassword",
    "ignore_protocol": false,
    "force_recheck": true,
    "policy": {
      "connect_timeout_ms": 2000,
      "handshake_timeout_ms": 3000,
      "rw_timeout_ms": 4000,
      "recheck_alive_sec": 30,
      "recheck_dead_sec": 600,
      "max_dead_strikes": 2,
      "stability_window_min": 5,
      "dead_backoff_mult": 2.0
    }
  }
  ```
  - `policy` *(object, opt)*: Partial or full update of timeout and recheck parameters (see [Section 1.3](#13-check-policy-and-recheck-scheduling-checkpolicydto)).
  - `force_recheck` *(bool, opt)*: Force scheduling a re-verification immediately on current second.
  - `ignore_protocol` *(bool, opt)*: Reset cached protocol and trigger cascading re-negotiation (SOCKS5 → SOCKS4 → HTTP).

- **Response:** `200 OK` (empty body).
- **Errors:** `400 Bad Request`, `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X PATCH "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"force_recheck":true,"remark":"updated"}'
  ```

---

#### `DELETE /api/v1/proxies/{id}`
Permanently remove a proxy and its source associations from the database.

- **Path Parameters:** `id` *(string, URL-encoded)*.
- **Response:** `204 No Content`.
- **Errors:** `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -i -X DELETE "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY"
  ```

---

### Group 2: Sources

#### `GET /api/v1/sources`
List all registered proxy sources with aggregated yield rates (yield %), state counts, and average latency.

- **Query Parameters:** None.
- **Response `200 OK` (JSON):**
  ```json
  [
    {
      "id": 1,
      "name": "premium_pool_v1",
      "url": "https://provider.example.com/feed.txt",
      "remark": "Primary corporate subnet proxies",
      "total_proxies": 1000,
      "alive_proxies": 850,
      "cold_queue_proxies": 50,
      "cooldown_proxies": 70,
      "dead_proxies": 30,
      "yield_pct": 85.0,
      "avg_rtt_ms": 145,
      "created_at": 1731200000,
      "last_added_at": 1731250000,
      "last_checked_at": 1731256800
    }
  ]
  ```
- **Errors:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/sources" -H "X-API-Key: $KEY"
  ```

---

#### `GET /api/v1/sources/{name}`
Detailed statistics for a specific source by its unique name.

- **Path Parameters:** `name` *(string)* — source name.
- **Response `200 OK` (JSON):** Single `SourceStatsItem` object (matching structure in `GET /api/v1/sources`).
- **Errors:** `400 Bad Request` (empty name), `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/sources/premium_pool_v1" -H "X-API-Key: $KEY"
  ```

---

#### `DELETE /api/v1/sources/{name}`
Delete a proxy source. Proxies associated solely with this source are cascaded and removed.

- **Path Parameters:** `name` *(string)* — source name.
- **Response:** `204 No Content`.
- **Errors:** `400 Bad Request`, `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -i -X DELETE "http://127.0.0.1:3000/api/v1/sources/premium_pool_v1" -H "X-API-Key: $KEY"
  ```

---

### Group 3: Judges

#### `GET /api/v1/judges`
List of registered judge echo servers (both built-in and external fallbacks) with health metrics and priority tiers.

- **Query Parameters:** None.
- **Response `200 OK` (JSON):**
  ```json
  [
    {
      "id": "builtin",
      "name": "Built-in Hydra Judge",
      "http_url": "http://127.0.0.1:8080",
      "https_url": "https://127.0.0.1:8443",
      "is_builtin": true,
      "priority": 0,
      "supports_anonymity": true,
      "enabled": true,
      "status": "healthy",
      "latency_ms": 12,
      "consecutive_failures": 0,
      "consecutive_successes": 48,
      "last_checked_at": 1731256800,
      "last_error": null
    }
  ]
  ```
  - `status`: `healthy`, `degraded`, `unhealthy`, `unknown`.
  - `priority`: `0` — primary (builtin), `1+` — standby fallback nodes.

- **Errors:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/judges" -H "X-API-Key: $KEY"
  ```

---

#### `POST /api/v1/judges/health-check`
Force an immediate parallel health check across all configured judges and re-elect the active validation node.

- **Request Body:** None.
- **Response `200 OK` (JSON):**
  ```json
  {
    "total_judges": 4,
    "healthy_judges": 4,
    "active_judge": "builtin",
    "judges": [
      {
        "id": "builtin",
        "name": "Built-in Hydra Judge",
        "http_url": "http://127.0.0.1:8080",
        "https_url": "https://127.0.0.1:8443",
        "is_builtin": true,
        "priority": 0,
        "supports_anonymity": true,
        "enabled": true,
        "status": "healthy",
        "latency_ms": 12,
        "consecutive_failures": 0,
        "consecutive_successes": 49,
        "last_checked_at": 1731256900,
        "last_error": null
      }
    ]
  }
  ```
- **Errors:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X POST "http://127.0.0.1:3000/api/v1/judges/health-check" -H "X-API-Key: $KEY"
  ```

---

### Group 4: Stats

#### `GET /api/v1/stats`
Global system summary: runtime engine metrics, pool status, validation quality, and distribution breakdowns by protocol, anonymity, error reason, country, and ASN.

- **Query Parameters:** None.
- **Response `200 OK` (JSON):**
  ```json
  {
    "engine": {
      "active_workers": 128,
      "checks_per_sec": 45.2,
      "checks_completed": 15420,
      "batch_buffer_size": 15,
      "judge_healthy": true
    },
    "pool": {
      "total": 12500,
      "alive": 8400,
      "cold_queue": 1500,
      "cooldown": 1800,
      "dead_permanent": 800
    },
    "quality": {
      "total_checks": 85000,
      "total_checks_success": 81500,
      "uptime_pct": 95.88,
      "avg_rtt_ms": 115,
      "avg_rtt_tcp_ms": 45,
      "avg_rtt_handshake_ms": 70,
      "supports_https_count": 7800,
      "with_auth_count": 2100,
      "no_auth_count": 6300,
      "total_sources": 12
    },
    "by_protocol": {
      "socks5": 5200,
      "http": 3200
    },
    "by_anonymity": {
      "elite": 6800,
      "anonymous": 1400,
      "transparent": 200
    },
    "by_error": {
      "TIMEOUT_TCP": 850,
      "CONN_REFUSED": 430,
      "HANDSHAKE_TIMEOUT": 210
    },
    "top_countries": [
      { "country": "DE", "alive_count": 3200, "avg_rtt_ms": 85 },
      { "country": "US", "alive_count": 2500, "avg_rtt_ms": 130 }
    ],
    "top_asns": [
      { "asn": 24940, "asn_org": "Hetzner Online GmbH", "alive_count": 3200, "avg_rtt_ms": 85 }
    ]
  }
  ```
- **Errors:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/stats" -H "X-API-Key: $KEY"
  ```

---

#### `GET /api/v1/stats/engine`
Instantaneous runtime engine metrics from in-memory atomic counters (zero database queries).

- **Query Parameters:** None.
- **Response `200 OK` (JSON):**
  ```json
  {
    "active_workers": 128,
    "checks_per_sec": 45.2,
    "checks_completed": 15420,
    "batch_buffer_size": 15,
    "judge_healthy": true
  }
  ```
- **Errors:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/stats/engine" -H "X-API-Key: $KEY"
  ```

---

### OpenAPI / Swagger Documentation

- **`GET /swagger-ui`**: Interactive web UI for exploring and testing API endpoints.
- **`GET /api-docs/openapi.json`**: Machine-readable OpenAPI 3.0 specification.

*Both endpoints are publicly accessible without `X-API-Key`.*

---

## 3. Error Handling (`ApiError`)

When a request encounters an issue, the service responds with the appropriate HTTP status code and a unified JSON error payload:

```json
{
  "error": "not_found",
  "message": "Proxy '185.220.101.5:1080' not found"
}
```

| HTTP Status | `error` Code | Description |
|---|---|---|
| `400 Bad Request` | `bad_request` | Query/body validation failed or invalid JSON payload. |
| `401 Unauthorized` | `unauthorized` | Missing or invalid `X-API-Key` header. |
| `404 Not Found` | `not_found` | Requested proxy or source entity does not exist in the database. |
| `409 Conflict` | `conflict` | Entity conflict (e.g. duplicate key or state violation). |
| `500 Internal Server Error` | `internal_error` | SQLite/libsql transaction failure or runtime error. |
