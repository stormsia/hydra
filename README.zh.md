<div align="center">

<img src="assets/logo.svg" alt="Hydra Logo" width="100%" style="max-width: 100%; height: auto;">

# Hydra — High-Performance Rust Proxy Checker, Validator & Pool Engine

[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-0ea5e9.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-10b981.svg?style=flat-square)](LICENSE)
[![Tokio Runtime](https://img.shields.io/badge/async-tokio%201.43-0ea5e9.svg?style=flat-square&logo=tokio)](https://tokio.rs/)
[![Speed](https://img.shields.io/badge/speed-8%2C300%2B%20checks%2Fsec-10b981.svg?style=flat-square)](docs/BENCHMARK_RESULTS.zh.md)
[![Protocols](https://img.shields.io/badge/protocols-SOCKS5%20%7C%20SOCKS4%20%7C%20HTTP-64748b.svg?style=flat-square)](docs/API.zh.md)
[![Storage: libSQL](https://img.shields.io/badge/storage-libSQL%20WAL-0ea5e9.svg?style=flat-square)](hydra_api/README.md)
[![OpenAPI 3.0](https://img.shields.io/badge/OpenAPI-3.0%20%2F%20Swagger-10b981.svg?style=flat-square&logo=swagger)](docs/API.zh.md)
[![Tested Scale: 10M](https://img.shields.io/badge/tested%20scale-10M%20proxies-0ea5e9.svg?style=flat-square)](docs/BENCHMARK_RESULTS.zh.md)

<p align="center">
  <b>High-throughput, asynchronous proxy validation engine and streaming pool manager written in pure Rust.</b><br>
  纯 Rust 编写的工业级高并发异步代理验证引擎与实时流式代理池管理器，支持数千万级代理的毫秒级验证、健康评分、匿名度分类及智能路由。
</p>

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

<br>

[⚡ 快速上手](#quick-start) • [✨ 核心特性](#features) • [📊 性能基准](#benchmarks) • [⚖️ 横向对比](#comparison) • [📐 系统架构](#architecture) • [⚙️ 环境配置](#configuration) • [📖 REST API](docs/API.zh.md)

</div>

---

> [!NOTE]
> **Hydra 为何而生？** 彻底解决海量 IP 检测场景下的内存溢出崩溃、数据库写锁死 (`database locked`)、操作系统 TCP 描述符耗尽 (`TIME_WAIT` 堆积)，并实现百级数据源异构代理列表的自动解析与零停机协议推断。

### 🎯 三大核心优势：

1. **零配置极速摄取全格式代理（14,000+ 代理/秒）**：支持无格式要求的原始数据流直接导入 — 自动识别 `ip:port`、`ip:port:user:pass`、`user:pass@ip:port`、URL 协议前缀、IPv6 (`[::1]:port`) 及结构化 JSON。系统纳秒级过滤 Bogon/私网地址，并执行协议级联探测（`SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP`）。
2. **细粒度全生命周期策略（为每个代理池定制 SLA）**：通过可插拔的检测策略（Check Policy）精准控制分层超时（L4 连接、L7 握手、I/O 读写）、健康存活轮询间隔、指数退避隔离期（`cooldown`）以及连续失败熔断阈值（`max_dead_strikes`），调度器 7×24 小时全自动保障池内节点时效性。
3. **0.06 毫秒极速查询与零锁死保证**：基于 SQLite WAL 模式、WITHOUT ROWID 聚簇表与 8 个专用 B-Tree 索引，针对国家、ASN、协议与匿名度实现亚毫秒级检索。结合 MPSC 微批处理写入架构（100 毫秒事务刷盘），在 10,000,000 级代理持续高并发冲击下保持 100% 事务稳定性与 0 锁错误。

---

## <a id="quick-start"></a>🚀 快速上手 (Quick Start Guide)

> [!IMPORTANT]
> **系统环境要求：**
> * **Rust 编译器 >= 1.85**（支持 `Rust 2024` edition）。
> * **Git** 命令行工具。

### 1. 克隆仓库与配置环境
```bash
git clone https://github.com/stormsia/hydra.git
cd hydra
cp .env.example .env
```

在 `.env` 文件中配置您的 API 访问主密钥：
```env
API_KEY=my_secure_hydra_key_12345
```

### 2. 编译项目 (Monorepo)

#### 标准 Release 编译：
```bash
cargo build --workspace --release
```

#### 极限性能编译（启用宿主机 CPU 原生 AVX2/BMI2 优化指令集）：
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

### 3. 启动服务

> [!TIP]
> 默认配置中 `EMBED_JUDGE` 为 `false`。若需在本地快速以 **All-In-One 一体化模式** 运行（内置匿名度验证 Judge 节点），请设置环境变量 `EMBED_JUDGE=true` 或在 `.env` 中声明 `EMBED_JUDGE=true`。

#### 🐧 Linux / macOS:
```bash
# 提升系统打开文件句柄上限（5,000+ 并发工作线程必备）
ulimit -n 65535

# 以 All-In-One 模式启动（在 8080 端口集成高性能 Judge 镜像回显服务）：
EMBED_JUDGE=true ./target/release/hydra_api

# 生产环境后台守护进程运行 (nohup):
nohup ./target/release/hydra_api > hydra_api.log 2>&1 &
```

#### 🪟 Windows (PowerShell):
```powershell
# 以 All-In-One 模式启动：
$env:EMBED_JUDGE="true"; .\target\release\hydra_api.exe
```

#### 生产环境独立部署 L7 Judge（推荐）：
在分布式高可用拓扑中，Judge 节点通常独立部署于不同地域以规避网络瓶颈：
```bash
# 启动超轻量、零依赖的高吞吐 Judge 回显服务
./target/release/hydra_judge
```

启动完成后即可访问以下接口与看板：
* 📖 **交互式 Swagger UI：** [http://127.0.0.1:3000/swagger-ui](http://127.0.0.1:3000/swagger-ui)
* 📋 **OpenAPI 3.0 规范文档 (JSON)：** [http://127.0.0.1:3000/api-docs/openapi.json](http://127.0.0.1:3000/api-docs/openapi.json)
* ⚡ **实时引擎遥测指标：**
  ```bash
  curl -H "X-API-Key: my_secure_hydra_key_12345" http://127.0.0.1:3000/api/v1/stats/engine
  ```

---

## <a id="features"></a>⚡ 核心特性与架构设计 (Features & Benefits)

| 场景 / 业务痛点 | Hydra 解决方案 | 达成效果 |
|---|---|---|
| **海量供应商异构格式混乱** | **零配置自适应语法解析**：原生支持 `ip:port`、`ip:port:user:pass`、URL、IPv6 与 JSON | 彻底省去清洗脚本；入库吞吐高达 **14,000+ 代理/秒** |
| **未标注代理类型与协议** | **级联协议自协商检测**：`SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP` | 无需预设类型，引擎按协议栈开销自适应推断可用性 |
| **不同业务对代理 SLA 诉求不同** | **细粒度全生命周期控制策略**：独立配置 L4/L7 超时、复检频率、稳定性时间窗 | 每个数据源/业务池独享个性化检测策略（Check Policy） |
| **高并发写入时 SQLite 数据库锁死** | 基于 **SQLite WAL** 的非阻塞 **MPSC 微批写入（100ms 刷新）** | 写入吞吐达 **8,340 检测/秒**，导入达 **14,000+ 条/秒**，**0 数据库锁错误** |
| **大量 TCP 连接致套接字耗尽 (`TIME_WAIT`)** | 套接字层精细控制 **`SO_LINGER=0` (TCP RST 丢弃)** | 5,000 并发任务下系统套接字零累积，释放瞬时完成 |
| **不可达 IP 浪费网络带宽与算力** | **4 阶段快速失败流水线**：L4 Connect &rarr; 协议握手 &rarr; TLS/Judge &rarr; 匿名度判定 | 节约高达 95% 带宽与文件描述符（在 SYN 阶段快速阻断） |
| **中心检测节点 (Judge) 单点故障** | **动态故障转移裁判池 (Failover Pool)**（支持最小延迟策略 `lowest_latency`） | 首选裁判失活时秒级无缝漂移至备选健康集群 |
| **公网回显服务被网络扫描器滥用** | **防滥用 Token 防护** + 24 小时动态滑动窗口 **HMAC-SHA256** | 自动拦截 Shodan、Censys 等爬虫探测并以 TCP RST 阻断 |
| **IP 归属地库版本落后滞后** | 基于 **`ArcSwap` 实现无锁 GeoIP/ASN 内存更新**（支持 HTTP ETag 增量拉取） | MaxMind 数据库热更新无需重启，零阻塞 Tokio 异步运行时 |
| **爬虫业务端被风控封禁反馈** | 闭环回传接口 **`POST /api/v1/proxies/report-fail`** | 触发故障的代理立即进入 `cooldown` 隔离队列并启用指数退避 |

---

## <a id="comparison"></a>⚖️ 与同类产品对比 (Benchmark Comparison)

| 维度 / 引擎 | **Hydra** | **[ProxyBroker](https://github.com/bluet/proxybroker2)** | **[proxypool](https://github.com/henson/proxypool)** | **[proxy-checker](https://www.npmjs.com/package/proxy-checker)** |
|---|:---:|:---:|:---:|:---:|
| **开发语言与运行时** | **Rust 2024 (Tokio 1.43)** | Python (asyncio) | Go (goroutines) | Node.js (JavaScript) |
| **峰值检测吞吐量** | **2,100 – 8,340+ 检测/秒** | ~100 – 250 检测/秒 | ~400 – 800 检测/秒 | ~200 – 500 检测/秒 |
| **实测容量上限** | **10,000,000+ 代理** | < 50,000 (内存泄漏严重) | < 200,000 (Redis 性能瓶颈) | < 100,000 (V8 GC 停顿) |
| **高负荷内存占用** | **~92 MB RAM** | 400 – 900+ MB | 250 – 500 MB | 300 – 700 MB |
| **TIME_WAIT 套接字消除** | **支持 (`SO_LINGER=0` TCP RST)** | 不支持 (操作系统默认) | 部分支持 | 不支持 |
| **持久化存储方案** | **内嵌 libSQL/WAL (MPSC 微批)** | 原生 SQLite (极易锁死) | 外部 Redis | MongoDB / 纯内存 |
| **多池个性化 SLA 策略** | **支持 (独立超时与复检周期)** | 不支持 (全局统一) | 不支持 | 不支持 |
| **裁判防扫描保护 (HMAC)** | **支持 (24h 滑动窗口授权)** | 不支持 | 不支持 | 不支持 |
| **级联协议自动推断** | **SOCKS5/4 &rarr; CONNECT &rarr; HTTP** | 仅支持有限类型 | 仅支持有限类型 | 需人工指定 |

---

## <a id="benchmarks"></a>📊 性能基准测试 (10M 代理压力测试与延迟)

本基准测试在 **5,000 个并发 Worker** 持续高压下针对 **10,000,000 个代理** 数据集进行测试（`hydra.db` 文件大小为 3.57 GB）。

> [!NOTE]
> REST API 延迟指标是在 **网络检测流水线 100% 满负荷运转** 时测得（5,000 个工作线程同时执行网络探测与异步批量写入）。单条记录基于聚簇 B-Tree 索引的纯 SQL 查询底座开销仅为 **0.06 毫秒**（按主键查找为 **0.01 毫秒**）。

| 性能指标 | 实测数值 | 测试环境与说明 |
|---|:---:|---|
| **REST API 代理导入吞吐** | **14,096 代理/秒** | 包含 JSON 反序列化、Bogon 过滤、去重与分批事务插入 |
| **持续稳定检测速率** | **2,111.5 检测/秒** | **约 760 万次检测/小时**（3 分钟内完成 380,725 次完整测试） |
| **瞬时峰值检测速率** | **8,340.0 检测/秒** | 出现在批量 TCP 超时重置和握手快速失败阶段 |
| **5,000 并发下内存占用** | **92.4 MB (平均) / 136.4 MB (峰值)** | 1000 万数据规模下零内存泄漏 |
| **5,000 并发下 CPU 占用** | **25.8% (平均) / 47.6% (峰值)** | 在 Tokio 多线程任务调度池内均衡分发 |
| **数据库锁死报错 (`database locked`)** | **0 次** | 得益于 100ms 事务型 MPSC 聚合写入缓冲区 |
| **API 延迟：极速节点过滤 (`limit=50`)** | **~25.6 毫秒** | **100% 检测高负荷下** 10M 规模的全链路 HTTP RTT |
| **API 延迟：地理位置筛选 (`country=US`)** | **~67.2 毫秒** | **100% 检测高负荷下** 地理索引过滤与时延动态排序 |
| **运行时遥测接口 (`GET /api/v1/stats/engine`)** | **< 1.0 毫秒** | 纯内存原子计数器，零磁盘 I/O 阻塞 |

> 🔬 详细测试方案与压测复现指南：[docs/BENCHMARK_RESULTS.zh.md](docs/BENCHMARK_RESULTS.zh.md)。

---

## 📦 工作区子包组成 (Workspace Crates)

项目采用高度解耦的 Cargo Monorepo 模块化架构：

```
Hydra Monorepo
├── hydra_api       — REST API (Axum)、生命周期调度器、MPSC 写入缓冲、libSQL 持久化、Swagger UI
├── hydra_checker   — 非阻塞异步网络探测核心、协议级联自协商、裁判健康池管理与过滤管道
└── hydra_judge     — 极速零框架 L7 镜像回显服务，集成 HMAC 动态令牌与反扫描防御
```

| 模块包名 | 核心职责 | 相关文档 |
|---|---|:---:|
| **`hydra_api`** | 全局调度编排、REST API 暴露、Swagger 文档、条件筛选导出与后台持久化 | [模块说明](hydra_api/README.md) • [API 接口规范](docs/API.zh.md) |
| **`hydra_checker`** | 异步网络探测引擎、级联协议探测、时延测定及全套匿名度裁决 | [模块说明](hydra_checker/README.md) |
| **`hydra_judge`** | 高并发 HTTP/HTTPS 请求镜像回显、客户端真实 IP 溯源与 RST 阻断防护 | [模块说明](hydra_judge/README.md) |

---

## <a id="architecture"></a>📐 系统架构 (Monorepo Architecture)

```mermaid
flowchart LR
    classDef client fill:#1e293b,stroke:#0ea5e9,stroke-width:2px,color:#f8fafc;
    classDef api fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef checker fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#f8fafc;
    classDef judge fill:#134e4a,stroke:#14b8a6,stroke-width:2px,color:#f8fafc;
    classDef storage fill:#312e81,stroke:#6366f1,stroke-width:2px,color:#f8fafc;

    subgraph Clients["客户端与业务服务"]
        Scrapers["爬虫节点 / 自动化 Agent"]:::client
        SwaggerUI["Swagger UI / 运维 CLI"]:::client
    end

    subgraph API["hydra_api 编排层"]
        Auth["X-API-Key 权限鉴权"]:::api
        Endpoints["RESTful API 路由 (/api/v1)"]:::api
        Scheduler["生命周期调度守护协程 (1s)"]:::api
        BatchWriter["MPSC 异步微批写入器 (100ms)"]:::api
        Maintenance["数据库维护例程 (1h)"]:::api
    end

    subgraph Checker["hydra_checker 探测引擎"]
        PreFlight["Bogon/预检过滤器"]:::checker
        L4Probe["阶段 1: L4 TCP SYN 探测"]:::checker
        Cascade["阶段 2: 级联协议推断协商"]:::checker
        L7Probe["阶段 3: L7 隧道与 HTTP 验证"]:::checker
        Verdict["阶段 4: 匿名度分析与裁决"]:::checker
        JudgePool["动态裁判容灾池 (Failover Pool)"]:::checker
    end

    subgraph Judges["裁判回显集群"]
        HydraJudge["hydra_judge (HMAC 防护)"]:::judge
        ExternalJudges["公网备用 Fallback 裁判"]:::judge
    end

    subgraph Storage["持久化与索引层"]
        DB[("libSQL / SQLite WAL<br/>WITHOUT ROWID (8 个聚簇索引)")]:::storage
    end

    Scrapers --> Auth
    SwaggerUI --> Auth
    Auth --> Endpoints
    Endpoints -->|"读取可用节点 (0.06 ms)"| DB

    Scheduler -->|"提取到期候选集"| DB
    Scheduler -->|"下发检测任务"| PreFlight

    PreFlight --> L4Probe --> Cascade --> L7Probe --> Verdict
    L7Probe --> JudgePool
    JudgePool -->|"带签名的验证探针"| HydraJudge
    JudgePool -.->|"自动故障转移"| ExternalJudges

    Verdict -->|"聚合检测结果"| BatchWriter
    BatchWriter -->|"BEGIN IMMEDIATE 批处理提交"| DB
    Maintenance -->|"增量垃圾回收 incremental_vacuum"| DB
```

---

## 🔄 确定性状态机与生命周期模型

节点生命周期采用完全确定性的状态机设计，杜绝可用节点丢失与僵尸节点无限循环轮询：

```mermaid
stateDiagram-v2
    [*] --> cold_queue: 初始导入系统 (state=0, strikes=0)
    cold_queue --> alive: 首次全链路验证通过 (state=1)
    cold_queue --> cooldown: 连接异常/超时 (state=2, strikes=1)

    alive --> alive: 定期轮询复检通过 (recheck_alive_sec)
    alive --> cooldown: 复检失败 或 客户端 POST /report-fail 上报

    cooldown --> alive: 隔离期复检成功 (strikes 重置为 0)
    cooldown --> cooldown: 持续失败 (strikes < max_dead_strikes)
    cooldown --> dead_permanent: 连续失败次数达到上限 (state=3)

    dead_permanent --> cold_queue: 重新导入激活 (revive_dead=true)
    dead_permanent --> [*]: 后台维护守护协程物理删除 (>30天)
```

> [!NOTE]
> 指数退避数学公式及策略调度参数说明，请参见 [CheckPolicyDto 策略定义](docs/API.zh.md#13-检测策略与调度配置-checkpolicydto)。

---

## 🔍 REST API 快速调用示例

### 1. 批量导入代理（支持纯文本或带策略的 JSON 对象）
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

### 2. 多维度筛选高可用代理（国家/地区、协议、匿名度）
```bash
curl -X GET "http://127.0.0.1:3000/api/v1/proxies?country=DE&anon=elite&protocol=socks5&limit=10" \
  -H "X-API-Key: my_secure_hydra_key_12345"
```

### 3. 上报业务不可用（主动将节点降级隔离）
```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  -d '{
    "ids": ["185.220.101.5:1080:alice:secret123"],
    "reason": "Target rate limited (HTTP 429)"
  }'
```

> 📖 查看全部 13 个接口定义与完整响应结构：[docs/API.zh.md](docs/API.zh.md)。

---

## <a id="configuration"></a>⚙️ 环境配置 (.env)

### 常用核心参数

| 配置项 | 数据类型 | 默认值 | 必填 | 详细描述 |
|---|:---:|:---:|:---:|---|
| `API_KEY` | `String` | *(无)* | **是** | 用于 `X-API-Key` 鉴权请求头的通信凭据。 |
| `LISTEN_ADDR` | `SocketAddr` | `0.0.0.0:3000` | 否 | API 与 Swagger UI 服务监听绑定的网络地址与端口。 |
| `DB_PATH` | `String` | `./data/hydra.db` | 否 | libSQL/SQLite 数据库存储路径（启用 WAL 高并发模式）。 |
| `EMBED_JUDGE` | `bool` | `false` | 否 | 是否在 API 主进程中集成启动内置 Judge 节点（All-In-One 模式）。 |
| `EMBED_JUDGE_PORT` | `u16` | `8080` | 否 | 内置 Judge 节点监听的 HTTP 端口。 |
| `JUDGE_HTTP_URL` | `Url` | `http://127.0.0.1:8080` | 否 | 用于验证明文 HTTP 代理转发能力的 Judge 端点。 |
| `JUDGE_HTTPS_URL` | `Url` | `http://127.0.0.1:8080` | 否 | 用于测试 SOCKS / CONNECT 隧道的 HTTPS Judge 端点。 |
| `JUDGE_SECRET_TOKEN` | `String` | `hydra_secret_token` | 否 | 用于校验 Judge 响应内容的静态安全签名 Token。 |
| `CHECKER_CONCURRENCY` | `usize` | `5000` | 否 | 网络检测协程最大并发处理上限。 |
| `CHECKER_REAL_IP` | `IpAddr` | *(自动)* | 否 | 宿主机公网真实出口 IP（用于高灵敏度识别 Transparent 透明代理）。 |
| `ENABLE_THIRD_PARTY_JUDGES` | `bool` | `true` | 否 | 是否启用公网第三方回显节点（如 Httpbingo）进行故障转移容灾。 |
| `JUDGE_SELECTION_STRATEGY` | `String` | `lowest_latency` | 否 | 裁判选择路由算法：`lowest_latency`, `priority`, `round_robin`。 |
| `GEOIP_AUTO_UPDATE` | `bool` | `true` | 否 | 是否在后台利用 HTTP ETag 自动增量下载最新 MaxMind 地理库。 |

<details>
<summary>👉 <b>展开高级调优参数（超时控制、GeoIP 存储路径、HMAC 轮询与调度器吞吐）</b></summary>

| 配置项 | 数据类型 | 默认值 | 详细描述 |
|---|:---:|:---:|---|
| `GEOIP_COUNTRY_PATH` | `String` | `./geo/GeoLite2-Country.mmdb` | 本地 MaxMind 国家数据库 MMDB 文件存放路径。 |
| `GEOIP_ASN_PATH` | `String` | `./geo/GeoLite2-ASN.mmdb` | 本地 MaxMind 自治系统 (ASN) 数据库 MMDB 存放路径。 |
| `GEOIP_RELOAD_SECS` | `u64` | `3600` | 内存中 MMDB 文件热重载周期（单位：秒）。 |
| `GEOIP_UPDATE_INTERVAL_SECS` | `u64` | `86400` | 检查上游 MaxMind 镜像更新的间隔时间（单位：秒）。 |
| `GEOIP_COUNTRY_URL` | `String` | *(jsdelivr 镜像)* | 用于下载最新 GeoLite2-Country.mmdb.gz 的镜像地址。 |
| `GEOIP_ASN_URL` | `String` | *(jsdelivr 镜像)* | 用于下载最新 GeoLite2-ASN.mmdb.gz 的镜像地址。 |
| `JUDGE_SECRET_KEY` | `String` | *(空)* | HMAC-SHA256 签名密钥，用于 24 小时动态滑动窗口 Token 生成。 |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS`| `u64` | `30` | 裁判健康心跳与 RTT 时延探测周期（单位：秒）。 |
| `ADDITIONAL_JUDGES` | `String` | *(空)* | 用户自定义扩展裁判节点列表（格式：`HTTP_URL\|HTTPS_URL,...`）。 |
| `CHECKER_CONNECT_TIMEOUT_MS` | `u64` | `3000` | L4 TCP 三次握手 SYN 连接最大等待超时（毫秒）。 |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | `u64` | `4000` | 隧道层握手超时（SOCKS 协商 / HTTP CONNECT 建立，毫秒）。 |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | `u64` | `5000` | 与裁判节点数据往返交互 I/O 读写超时（毫秒）。 |
| `CHECKER_MAX_READ_BYTES` | `usize` | `8192` | 允许读取的最大响应字节数（针对慢速或内存炸弹防御）。 |
| `CHECKER_LOCAL_BIND_IP` | `IpAddr` | *(空)* | 强制绑定探测套接字的外发本地网卡 IP。 |
| `SCHEDULER_BATCH_SIZE` | `usize` | `10000` | 调度器每秒最大拉取分配的到期检测候选节点数。 |
| `BATCH_FLUSH_INTERVAL_MS` | `u64` | `100` | MPSC 异步写入队列向 SQLite 刷写事物的间隔（毫秒）。 |
| `DEAD_PROXY_RETENTION_DAYS` | `u32` | `30` | 永久失效节点保留天数，逾期自动从库中物理销毁。 |
| `DB_MAINTENANCE_INTERVAL_SECS` | `u64` | `3600` | 数据库后台例行碎片整理周期（执行 `PRAGMA incremental_vacuum`）。 |
| `RUST_LOG` | `String` | `info` | 日志详细级别控制（基于 `tracing` 框架）。 |

</details>

---

## 🛠️ 参与开发与测试

```bash
# 执行整个 Cargo 工作区的全部单元测试与集成测试
cargo test --workspace

# 独立测试各个业务子模块
cargo test -p hydra_checker
cargo test -p hydra_judge
cargo test -p hydra_api

# 代码风格统一化检查与 Clippy 静态质量审查
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 🤝 贡献代码

非常欢迎提交 Issue、Pull Request 与性能优化提案！
提交代码前请仔细阅读我们的规范指南：
👉 **[贡献指南 (CONTRIBUTING.zh.md)](CONTRIBUTING.zh.md)**。

---

## 📄 开源许可证

本项目基于 **MIT License** 开源协议发布。详情请查阅 [LICENSE](LICENSE) 文件。
