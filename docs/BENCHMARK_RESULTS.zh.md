[← 返回 Hydra README](../README.zh.md) | [English](BENCHMARK_RESULTS.md) • [Русский](BENCHMARK_RESULTS.ru.md) • [简体中文](BENCHMARK_RESULTS.zh.md)

# Hydra Proxy Checker — 基准测试结果与性能指标报告

## 1. 吞吐量与接口响应时延 (Throughput & Latency)

> **API 响应时延测试条件：** 所有针对 REST API 的 HTTP 请求均在 **检测引擎 100% 满负荷高压下并行发起**（5,000 个并发 Worker 持续扫描 1000 万代理池并执行后台事务级批量写入）。服务端响应稳定，无任何速率抑制（Rate Throttling）或性能衰减。

| 评估指标 | 测量结果 | 测试环境与说明 |
|---|:---:|---|
| **REST API 代理批量导入** | **14,096 代理/秒** | 包含 JSON 反序列化与 Bogon 私网 IP 过滤 |
| **持续稳定检测速率（10M 池，5000 线程）** | **2,111.5 检测/秒** | 约 760 万次检测/小时（3 分钟内完成 380,725 次验证） |
| **瞬时峰值检测速率** | **8,340.0 检测/秒** | 发生于批量并发 TCP 会话断开与握手阻断阶段 |
| **快速节点检索 (`GET /api/v1/proxies?limit=50`)** | **~25.6 毫秒** | 满载检测环境下实测（按总 RTT 排序返回最优节点） |
| **国家筛选 (`GET /api/v1/proxies?country=US&limit=50`)** | **~67.2 毫秒** | 满载检测环境下实测（地理位置索引过滤 + RTT 排序） |
| **代理详情点查 (`GET /api/v1/proxies/{id}`)** | **~33.7 毫秒** | 满载检测环境下实测（基于主键聚簇索引精确查找） |
| **实时运行时遥测 (`GET /api/v1/stats/engine`)** | **< 1.0 毫秒** | 纯内存原子无锁计数器，零磁盘 I/O 阻塞 |

---

## 2. 硬件资源占用情况（5,000 个并发 Worker）

| 监控指标 / 资源维度 | 平均值 | 峰值 | 稳定性评估 |
|---|:---:|:---:|---|
| **物理内存 (RAM)** | **92.4 MB** | **136.4 MB** | 长周期运行无内存泄漏 |
| **CPU 占用率** | **25.8 %** | **47.6 %** | 在 Tokio 异步运行时各核心均衡分配 |
| **数据库锁冲突 (`database locked`)** | **0 次** | **0 次** | 100 毫秒 MPSC 微批处理事务写入机制保障 |

---

## 3. 裁判回显池 (Judge Pool)

裁判节点基于 `lowest_latency`（最低时延）策略进行动态调度：每隔 30 秒执行一次全量 RTT 探活检测，自动漂移选举主节点（Failover）。

| 裁判节点标识 | 目标地址 URL | 平均时延 (RTT) | HTTPS 支持 | 请求头镜像 (`Via`, `XFF`) | 当前状态 |
|---|---|:---:|:---:|:---:|:---:|
| **httpbingo_org** | `https://httpbingo.org/get` | **300 – 340 毫秒** | 支持 | 支持 | **Active Leader (主节点)** |
| **httpbun_com** | `https://httpbun.com/get` | 420 – 510 毫秒 | 支持 | 支持 | Standby (待命) |
| **httpbin_org** | `https://httpbin.org/get` | 510 – 575 毫秒 | 支持 | 支持 | Standby (待命) |
| **httpbin_rs** | `https://httpbin.rs/get` | 595 – 690 毫秒 | 支持 | 支持 | Standby (待命) |
| **httpbin_dev** | `https://httpbin.dev/get` | 660 – 770 毫秒 | 支持 | 支持 | Standby (待命) |

---

## 4. 关键工程结论 (Key Takeaways)

1. **工业级生产吞吐**：单机节点在维护 1000 万规模代理底库时，能够保持每小时 **760 万次以上** 的持续有效验证，稳定检测速率突破 2,100 checks/sec。
2. **极低资源开销**：在驱动 5,000 个全并发网络连接时，内存占用始终平稳在 **137 MB RAM** 以内。非常适合低成本入门级云服务器（1 vCPU, 1 GB RAM）长期部署。
3. **网络 I/O 成为主瓶颈**：系统的极限瓶颈在于物理网络带宽及宿主操作系统的网络协议栈参数（如临时端口号范围、conntrack 连接追踪表上限、`nofile` 句柄数），而非 CPU 算力或存储层。
4. **高并发读写零竞争**：基于 MPSC 队列的异步微批处理机制（100ms 聚合提交），彻底消除了 SQLite 的 `database locked` 锁竞争问题。在千万级数据库持续高压写入下，前端 REST API 接口仍能在数毫秒内完成查询。
5. **推荐生产调优配置**：为保证极致吞吐与系统健壮性，建议设置 `CHECKER_CONCURRENCY=5000`、`BATCH_FLUSH_INTERVAL_MS=100`，并将操作系统的文件描述符上限调整至 `nofile >= 65535`。
