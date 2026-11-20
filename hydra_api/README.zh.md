[← 返回 Hydra README](../README.zh.md)

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

# hydra_api

Hydra 代理池引擎的编排、调度检测、持久化存储与 REST API 服务模块。负责调度检测引擎（`hydra_checker`）、对接匿名度判定服务（`hydra_judge`），并通过 libSQL（SQLite WAL 模式）实现代理元数据与状态的高性能持久化管理。

## 目录结构

```
hydra_api/
├── Cargo.toml                              # Cargo 软件包清单与依赖声明
├── .env.example                            # 环境变量配置文件模板
├── docs/API.md                             # REST API 数据模型及详细规范
├── README.md                               # 模块技术文档
├── migrations/
│   └── 001_initial.sql                     # 数据表结构及 B-Tree 索引 SQL 迁移文件
├── src/
│   ├── main.rs                             # 服务入口：初始化后台任务并启动 HTTP 服务
│   ├── lib.rs                              # 核心库导出与加密提供程序初始化
│   ├── app_state.rs                        # 全局共享应用状态（AppState）
│   ├── config.rs                           # 环境变量配置解析与合法性校验
│   ├── error.rs                            # API 统一错误定义与 HTTP 状态码映射
│   ├── router.rs                           # Axum 路由分发、鉴权中间件及 Swagger UI
│   ├── db/
│   │   ├── mod.rs                          # 数据库访问层重新导出
│   │   ├── init.rs                         # libSQL 初始化、WAL PRAGMA 参数调优与迁移执行
│   │   ├── proxies.rs                      # 代理节点 CRUD 操作及到期检测批次提取
│   │   ├── sources.rs                      # 代理数据来源注册及出产率指标统计
│   │   └── proxy_sources.rs                # 代理与来源的多对多关联关系管理
│   ├── handlers/
│   │   ├── mod.rs                          # HTTP 请求处理器重新导出
│   │   ├── proxies.rs                      # 代理导入、CRUD 接口与故障上报处理器
│   │   ├── sources.rs                      # 数据来源管理接口处理器
│   │   ├── stats.rs                        # 数据库统计与内存性能遥测处理器
│   │   └── judges.rs                       # 裁判节点健康状态与连通性检测处理器
│   ├── middleware/
│   │   ├── mod.rs                          # 中间件模块重新导出
│   │   └── auth.rs                         # X-API-Key 鉴权请求头校验中间件
│   ├── models/
│   │   ├── mod.rs                          # 数据结构实体模型重新导出
│   │   ├── api.rs                          # API 请求/响应 DTO 及 utoipa OpenAPI 模型
│   │   └── db.rs                           # 数据库表记录模型（ProxyRow、SourceRow）
│   └── services/
│       ├── mod.rs                          # 后台守护服务重新导出
│       ├── scheduler.rs                    # 到期代理节点检测定时调度引擎
│       ├── batch_writer.rs                 # 非阻塞 MPSC 事务批量写入数据库缓冲区
│       ├── geoip.rs                        # 无锁 GeoIP/ASN 解析引擎（MaxMind + ArcSwap）
│       ├── geoip_updater.rs                # 基于 CDN ETag 的 GeoIP 数据库后台自动增量更新
│       ├── maintenance.rs                  # 过期死节点清理与 SQLite WAL/PRAGMA 维护任务
│       └── parser.rs                       # 原始文本多格式代理提取与 Bogon 保留 IP 过滤
└── tests/
    ├── api_integration_tests.rs            # REST API 端到端集成测试
    ├── db_tests.rs                         # 数据库 SQL 查询与架构迁移测试
    ├── models_and_parser_tests.rs          # 代理提取解析器与数据模型序列化测试
    └── scheduler_and_batch_writer_tests.rs # 调度队列逻辑与批量写入合并测试
```

## 核心子系统

- **路由与接口服务 (Axum 0.8)：** 接收并处理 HTTP 请求，强制执行 `X-API-Key` 密钥鉴权，提供内置 OpenAPI/Swagger UI 交互式文档及路由分发。
- **任务调度器 (Scheduler)：** 每秒检索到期需检测的代理（`next_check_at <= now`），按超时策略并发下发至验证检测池。
- **批量写入缓冲 (Batch Writer)：** 采用基于 MPSC 的无锁微批处理通道，汇总多工作协程的检测结果，每 100 毫秒以单一原子事务批量刷盘写入数据库。
- **GeoIP 解析引擎：** 采用基于 `ArcSwap` 的无锁内存映射机制，实时解析国家代码与 ASN 属性，支持后台基于 CDN ETag 自动热更新。
- **持久化数据库 (libSQL)：** 本地高性能存储，运行于 WAL 日志模式下，采用 `WITHOUT ROWID` 聚簇表及 8 个专用 B-Tree 索引，实现亚毫秒级复杂多维过滤。

## 环境变量配置

所有配置项均从系统环境变量或根目录 `.env` 文件读取。所有 API 接口均须附带 `X-API-Key: <API_KEY>` 请求头。

| 环境变量 | 类型 | 默认值 | 用途说明 |
| :--- | :--- | :--- | :--- |
| `LISTEN_ADDR` | String | `0.0.0.0:3000` | API 服务监听地址与网络端口 |
| `API_KEY` | String | — *(必填)* | X-API-Key 接口鉴权主密钥 |
| `DB_PATH` | String | `./data/hydra.db` | libSQL 数据库持久化存储路径 |
| `EMBED_JUDGE` | bool | `false` | 是否在 API 主进程中运行内置 Judge 裁判服务 |
| `EMBED_JUDGE_PORT` | u16 | `8080` | 内置 Judge 服务监听端口 |
| `CHECKER_CONCURRENCY` | usize | `5000` | 检测引擎并发工作协程上限 |
| `CHECKER_REAL_IP` | String | *(自动: 裁判共识)* | 宿主机公网出口 IP（用于比对透明代理；默认基于健康裁判多数票共识动态自动探测，显式配置优先） |
| `JUDGE_HTTP_URL` | String | `http://127.0.0.1:8080` | 用于 HTTP 检测的回显裁判地址 |
| `JUDGE_HTTPS_URL` | String | `http://127.0.0.1:8080` | 用于 HTTPS 隧道检测的回显裁判地址 |
| `JUDGE_SECRET_TOKEN` | String | `hydra_secret_token` | 用于验证裁判合法回显的静态令牌 |
| `JUDGE_SECRET_KEY` | String | — | HMAC 密钥（用于每日动态轮替令牌验证） |
| `ENABLE_BUILTIN_JUDGE` | bool | `auto` | 是否将内置裁判节点加入检测池（自动：若开启 EMBED_JUDGE 或自定义 URL 则为 true，否则为 false） |
| `ENABLE_THIRD_PARTY_JUDGES` | bool | `true` | 是否启用内置第三方公共裁判节点池 |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS` | u64 | `30` | 裁判节点探活与可用性检查间隔（秒） |
| `JUDGE_SELECTION_STRATEGY` | String | `lowest_latency` | 活跃裁判节点优选策略（最低延迟等） |
| `ADDITIONAL_JUDGES` | String | — | 附加的第三方裁判服务节点地址列表（逗号分隔） |
| `GEOIP_AUTO_UPDATE` | bool | `true` | 是否启用 GeoIP MMDB 数据库自动更新 |
| `GEOIP_COUNTRY_PATH` | String | `./geo/GeoLite2-Country.mmdb` | MaxMind 国家代码数据库文件路径 |
| `GEOIP_ASN_PATH` | String | `./geo/GeoLite2-ASN.mmdb` | MaxMind 自治系统号 (ASN) 数据库文件路径 |
| `GEOIP_RELOAD_SECS` | u64 | `3600` | 内存重新加载磁盘 MMDB 文件的间隔（秒） |
| `GEOIP_UPDATE_INTERVAL_SECS` | u64 | `86400` | 检查 CDN 最新 GeoIP 版本的轮询间隔（秒） |
| `GEOIP_COUNTRY_URL` | String | `https://cdn.jsdelivr.net/...` | 国家代码 MMDB 远程同步下载 URL |
| `GEOIP_ASN_URL` | String | `https://cdn.jsdelivr.net/...` | ASN 属性 MMDB 远程同步下载 URL |
| `SCHEDULER_BATCH_SIZE` | usize | `10000` | 调度器单轮提取待检代理的最大批量数 |
| `BATCH_FLUSH_INTERVAL_MS` | u64 | `100` | 批量写入事务合并刷盘最大等待间隔（毫秒） |
| `DEAD_PROXY_RETENTION_DAYS` | u32 | `30` | 失效死节点的保留归档周期（天） |
| `DB_MAINTENANCE_INTERVAL_SECS` | u64 | `3600` | 数据库后台清理维护与整理间隔（秒） |
| `RUST_LOG` | String | `info,hydra_api=debug` | 系统日志输出级别过滤规则 |

## REST API 路由接口

| 请求方法 | 路由路径 | 接口说明 |
| :--- | :--- | :--- |
| `POST` | `/api/v1/proxies/import` | 批量导入原始代理至 `cold_queue` 待检队列 |
| `GET` | `/api/v1/proxies` | 多条件过滤查询代理（按国家、协议、匿名度） |
| `GET` | `/api/v1/proxies/{id}` | 根据代理唯一 ID 获取完整元数据 |
| `PATCH` | `/api/v1/proxies/{id}` | 局部更新代理检测策略及运行参数 |
| `DELETE` | `/api/v1/proxies/{id}` | 从数据库中永久删除指定代理 |
| `POST` | `/api/v1/proxies/report-fail` | 客户端主动上报连通失败并触发静默冷却 |
| `GET` | `/api/v1/sources` | 获取来源列表及出产有效率（yield）统计 |
| `GET` | `/api/v1/sources/{name}` | 根据来源名称查询详细监控指标 |
| `DELETE` | `/api/v1/sources/{name}` | 删除指定来源并解除关联的代理记录 |
| `GET` | `/api/v1/judges` | 获取裁判节点健康状态与 RTT 延迟数据 |
| `POST` | `/api/v1/judges/health-check` | 立即触发全量裁判节点连通性巡检 |
| `GET` | `/api/v1/stats` | 获取全局代理池容量与数据库健康指标 |
| `GET` | `/api/v1/stats/engine` | 获取检测核心的内存级吞吐性能指标 |
| `GET` | `/swagger-ui` | 访问交互式 Swagger UI 在线接口文档 |
| `GET` | `/api-docs/openapi.json` | 导出 OpenAPI 3.0 规范的 JSON 定义文件 |

请求结构模型、DTO 字段定义与响应示例请参考 [../docs/API.zh.md](../docs/API.zh.md)。

## 编译与运行

### 1. 配置环境文件

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

### 2. 编译与执行

Linux / Windows:
```bash
# 开发模式运行
cargo run -p hydra_api

# 生产优化模式运行
cargo run --release -p hydra_api

# 仅构建发布版二进制可执行文件
cargo build --release -p hydra_api
```

### 3. 单元测试与集成测试

```bash
cargo test -p hydra_api
```
