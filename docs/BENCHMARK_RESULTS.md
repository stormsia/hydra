[← Back to Hydra README](../README.md) | [English](BENCHMARK_RESULTS.md) • [Русский](BENCHMARK_RESULTS.ru.md) • [简体中文](BENCHMARK_RESULTS.zh.md)

# Hydra Proxy Checker — Benchmark Results & Performance Metrics

## 1. Throughput & Latency

> **API Latency Measurement Conditions:** All HTTP requests to the REST API were executed **in parallel under 100% checker load** (5,000 active workers continuously verifying a pool of 10 million entries with non-stop background transactional writes). The API responded normally without throttling or degradation.

| Metric | Value | Notes & Context |
|---|:---:|---|
| **Proxy Import via REST API** | **14,096 proxies/sec** | Batch JSON ingestion with bogon IP filtering |
| **Continuous Verification (10M pool, 5,000 workers)** | **2,111.5 checks/sec** | ~7.6M checks/hour (380,725 checks in 3 minutes) |
| **Peak Check Speed** | **8,340.0 checks/sec** | During massive parallel TCP session termination |
| **Fast Query Retrieval (`GET /api/v1/proxies?limit=50`)** | **~25.6 ms** | Under full checker load (top nodes by total RTT) |
| **Geo Filtering (`GET /api/v1/proxies?country=US&limit=50`)** | **~67.2 ms** | Under full checker load (geo filter + RTT sorting) |
| **Proxy Details Lookup (`GET /api/v1/proxies/{id}`)** | **~33.7 ms** | Under full checker load (point lookup by primary key) |
| **Engine Telemetry (`GET /api/v1/stats/engine`)** | **< 1.0 ms** | In-memory atomic counters without disk access |

---

## 2. Resource Consumption (5,000 Concurrent Workers)

| Resource / Indicator | Average | Peak | Stability |
|---|:---:|:---:|---|
| **RAM** | **92.4 MB** | **136.4 MB** | Zero memory leaks observed |
| **CPU** | **25.8 %** | **47.6 %** | Smooth Tokio runtime load distribution |
| **Database Locks (`database locked`)** | **0** | **0** | 100 ms micro-batching write buffer |

---

## 3. Judge Pool

Judge selection follows the `lowest_latency` strategy: RTT is probed every 30 seconds with automatic failover to the healthy leader.

| Judge | URL | RTT | HTTPS | Header Echo (`Via`, `XFF`) | Status |
|---|---|:---:|:---:|:---:|:---:|
| **httpbingo_org** | `https://httpbingo.org/get` | **300 – 340 ms** | Yes | Yes | **Active Leader** |
| **httpbun_com** | `https://httpbun.com/get` | 420 – 510 ms | Yes | Yes | Standby |
| **httpbin_org** | `https://httpbin.org/get` | 510 – 575 ms | Yes | Yes | Standby |
| **httpbin_rs** | `https://httpbin.rs/get` | 595 – 690 ms | Yes | Yes | Standby |
| **httpbin_dev** | `https://httpbin.dev/get` | 660 – 770 ms | Yes | Yes | Standby |

---

## 4. Engineering Takeaways

1. **Production Throughput**: The engine validates over **7.6 million addresses per hour** on a 10-million proxy dataset, sustaining over 2,100 checks/sec on a single host.
2. **Minimal Footprint**: Memory usage stays under **137 MB RAM** even with 5,000 active concurrent connections. The system runs comfortably on budget VMs (1 vCPU, 1 GB RAM).
3. **Network Bound**: Performance is limited by network bandwidth and OS networking stack limits (ephemeral ports, conntrack table size, `nofile`), rather than CPU computation or database I/O.
4. **Concurrency without Contention**: Asynchronous result micro-batching (100 ms) guarantees zero `database locked` errors. Concurrent REST API requests execute in milliseconds even under 100% network validation load on a 10M record database.
5. **Recommended Tuning**: For stable production deployments, configure `CHECKER_CONCURRENCY=5000`, `BATCH_FLUSH_INTERVAL_MS=100`, and set OS open descriptor limits to `nofile >= 65535`.
