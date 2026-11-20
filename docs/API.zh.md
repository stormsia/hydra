[← 返回 Hydra README](../README.zh.md) | [English](API.md) • [Русский](API.ru.md) • [简体中文](API.zh.md)

# Hydra REST API

基础访问路径 (Base URL): `http://127.0.0.1:3000`  
鉴权机制：HTTP 请求头 `X-API-Key: <token>`（通过环境变量 `API_KEY` 配置）。`/swagger-ui` 与 `/api-docs/openapi.json` 接口为公开接口，无需携带密钥。

---

## 1. 核心标准定义与参考规范

### 1.1. 生命周期状态枚举 (`ProxyState`)

| 状态字符串 (`state`) | 整数代号 | 状态定义与语义说明 |
|---|---|---|
| `cold_queue` | `0` | 新导入系统的待测代理，处于初检队列中等待分配探测任务。 |
| `alive` | `1` | 通过 Judge 探针全流程验证的高可用代理，处于活跃池，可正常对外分发。 |
| `cooldown` | `2` | 探测超时失败或由客户端上报异常后的隔离状态，按指数退避算法等待下一次复检。 |
| `dead_permanent` | `3` | 连续探测失败次数突破上限阈值，被永久标记废弃并移出复检队列。 |

### 1.2. 协议支持与匿名度分类

| 属性名称 | 可选枚举值 | 详细说明 |
|---|---|---|
| `protocol` | `socks5`, `socks4`, `http` | 网络代理传输协议。对于 `http` 协议会自动探测是否支持 CONNECT HTTPS 隧道 (`supports_https`)。 |
| `anon` | `elite` | 高匿代理 (Elite)：目标服务器完全无法检测到代理的存在，无 `Via`、`X-Forwarded-For` 等特征头，且客户端真实 IP 被彻底隐藏。 |
| | `anonymous` | 普匿代理 (Anonymous)：目标服务器能够识别出该请求经过了代理转发，但无法获取客户端的真实出口 IP。 |
| | `transparent` | 透明代理 (Transparent)：目标服务器可通过 HTTP 请求头直接提取出客户端的真实 IP 地址。 |

### 1.3. 检测策略与调度配置 (`CheckPolicyDto`)

用于精细化控制各分层网络超时、退避熔断机制及后台调度周期的策略对象。可在批量导入数据源时指定 (`POST /api/v1/proxies/import`)，亦可通过 `PATCH /api/v1/proxies/{id}` 对单节点进行热更新。

| 字段名称 (JSON) | 数据类型 | 默认值 | 取值范围 | 调度影响与检测引擎行为详解 |
|---|---|---|---|---|
| `connect_timeout_ms` | `u32` | `3000` (ms) | `100` – `60000` | 建立底层 L4 TCP SYN 连接的最大容忍等待时间。超时则判定为 `connect` 阶段失败。 |
| `handshake_timeout_ms` | `u32` | `4000` (ms) | `100` – `60000` | 执行协议握手（SOCKS 握手认证 / SSL/TLS 握手 / HTTP CONNECT 隧道）的最大超时。 |
| `rw_timeout_ms` | `u32` | `5000` (ms) | `100` – `60000` | 向裁判节点发送探针请求并等待全量响应体返回的 I/O 读写超时。 |
| `recheck_alive_sec` | `u32` | `60` (s) | `10` – `86400` | 处于 `alive` 状态的健康节点后台常规巡检周期。巡检成功后设定 `next_check_at = now + recheck_alive_sec`。 |
| `recheck_dead_sec` | `u32` | `1800` (s) | `30` – `604800` | 隔离区 (`cooldown`) 节点的初次复检等待基准时延（秒）。若配置为 `0`，则发生故障时直接降级为 `dead_permanent`。 |
| `max_dead_strikes_zero` | `u32` | `3` | `1` – `50` | 零成功率/全新节点 (`checks_success == 0`) 的最大连续失败次数。兼容别名：`max_dead_strikes_0`。 |
| `max_dead_strikes_active` | `u32` | `3` | `1` – `50` | 曾存活验证过的活跃节点 (`checks_success > 0`) 的最大连续失败次数。兼容别名：`max_dead_strikes_nonzero`, `max_dead_strikes_alive`。 |
| `stability_window_min` | `u32` | `5` (min) | `1` – `1440` | 计算短周期健康度评分 `stability_pct` 的滑动时间窗口（单位：分钟）。早于该时间的历史记录不计入统计。兼容别名：`stability_window`, `window_min`, `window_minutes`。 |
| `dead_backoff_mult_zero` | `f32` | `1.5` | `1.0` – `10.0` | 零成功率/全新节点 (`checks_success == 0`) 的隔离复检指数退避乘子。兼容别名：`dead_backoff_mult_0`, `backoff_multiplier_zero`。 |
| `dead_backoff_mult_active` | `f32` | `1.5` | `1.0` – `10.0` | 曾存活验证过的活跃节点 (`checks_success > 0`) 的隔离复检指数退避乘子。兼容别名：`dead_backoff_mult_nonzero`, `dead_backoff_mult_alive`, `backoff_multiplier_active`, `backoff_multiplier_nonzero`。 |

**隔离复检指数退避数学公式：**

当代理节点探测失败时，连续失败计数递增：`new_strikes = current_strikes + 1`。系统依据节点历史是否存在成功检测记录（`checks_success`）动态匹配差异化阈值与退避系数：
- 若 `checks_success == 0`: `effective_max_strikes = max_dead_strikes_zero`, `effective_backoff_mult = dead_backoff_mult_zero`。
- 若 `checks_success > 0`: `effective_max_strikes = max_dead_strikes_active`, `effective_backoff_mult = dead_backoff_mult_active`。

若 `strikes < effective_max_strikes`，节点进入或停留在 `cooldown` 状态，下次检测触发延迟按以下公式计算：

`interval = recheck_dead_sec * (effective_backoff_mult ^ (strikes - 1))`

> *注：* 计算出的 `interval` 会被硬性限制在 1 秒至 30 天区间内：`clamp(1, 2592000)` 秒。下一次调度时间计算为 `next_check_at = now + interval`。若 `strikes >= effective_max_strikes`，节点正式进入终态 `dead_permanent`。

> **代理唯一标识符格式 (`id`)：** 公开无密节点格式为 `ip:port`，私密认证节点格式为 `ip:port:user:pass`。在 REST API 路由路径中使用时（`/api/v1/proxies/{id}`），所有特殊符号（如 `:`、`@`、`#`、`/`）**必须**进行标准 URL 百分号编码（例如：`1.2.3.4%3A8080%3Au%40ser%3Ap%23ass`）。

---

## 2. API 接口详细规范

### 第一组：Proxies（代理管理与检索）

#### `POST /api/v1/proxies/import`
批量导入原始代理列表至 `cold_queue` 待测队列，内置格式校验、去重合并与数据源绑定。

- **请求体 (Request Body - JSON):**
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
      "max_dead_strikes_zero": 3,
      "max_dead_strikes_active": 3,
      "stability_window_min": 5,
      "dead_backoff_mult_zero": 1.5,
      "dead_backoff_mult_active": 1.5
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
  - `revive_dead` *(bool, 默认: false)*: 重置失败计数并将已永久失效的 `dead_permanent` 节点重新激活至 `cold_queue`。
  - `ignore_protocol` *(bool, 默认: false)*: 忽略传入的协议标注，强制启动级联自动协商（SOCKS5 → SOCKS4 → HTTP）。
  - `policy` *(object, 可选)*: 为该批次节点定制独立的超时及生命周期策略（详见 [1.3 节](#13-检测策略与调度配置-checkpolicydto)）。缺省时沿用系统默认配置。
  - `proxies` *(array)*: 支持字符串格式（`proto://user:pass@ip:port`、`ip:port:user:pass`、`ip:port`、`[ipv6]:port`）或结构化对象。

- **响应 `200 OK` (JSON):**
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
- **异常响应：** `400 Bad Request`（缺少必填的 `source`）、`401 Unauthorized`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s -X POST http://127.0.0.1:3000/api/v1/proxies/import -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"source":"p1","proxies":["socks5://u:p@1.2.3.4:1080","5.6.7.8:8080"]}'
  ```

---

#### `GET /api/v1/proxies`
支持多维属性交叉过滤、性能排序与分页的可用代理获取接口。

- **URL 查询参数 (Query Parameters):**
  | 参数名 | 类型 | 默认值 | 作用与过滤规则 |
  |---|---|---|---|
  | `state` | string | `alive` | 状态过滤：`alive`, `cold_queue`, `cooldown`, `dead_permanent`。 |
  | `country` | string | — | 包含的国家/地区 ISO 二位码，支持逗号分隔 (`DE` 或 `DE,NL,FR`)。 |
  | `exclude_country` | string | — | 排除指定国家/地区，支持逗号分隔 (`RU,CN`)。 |
  | `protocol` | string | — | 协议过滤：`socks5`, `http`, `socks4`。 |
  | `anon` | string | — | 匿名等级过滤：`elite`, `anonymous`, `transparent`。 |
  | `supports_https` | bool | — | 是否支持 HTTPS CONNECT 隧道 (`true`/`false`)。 |
  | `has_auth` | bool | — | 账号密码认证过滤（`true` 为私密代理，`false` 为公开免费代理）。 |
  | `max_rtt` | u32 | — | 允许的最大综合往返总时延 RTT (毫秒)。 |
  | `min_uptime` | f32 | — | 最低终身可用率阈值百分比 (0.0 — 100.0 %)。 |
  | `min_stability` | f32 | — | 最低窗口期稳定性评分 (0.0 — 100.0 %)。 |
  | `stability_window_min` | u32 | — | 指定计算稳定性的时间窗口跨度（分钟）。 |
  | `source` | string | — | 归属数据源来源名称。 |
  | `limit` | u32 | `50` | 单次提取条数。设置为 `0` 表示不限数量（全量导出）。 |
  | `offset` | u32 | `0` | 分页位移游标。 |

- **响应 `200 OK` (JSON):**
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
- **异常响应：** `400 Bad Request`、`401 Unauthorized`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/proxies?state=alive&protocol=socks5&country=DE&limit=10" -H "X-API-Key: $KEY"
  ```

---

#### `POST /api/v1/proxies/report-fail`
业务端闭环故障上报通道：主动将不可用的节点降级至 `cooldown` 隔离区，累加失败惩罚，并自动加速下一次复检。

- **请求体 (Request Body - JSON):**
  ```json
  {
    "ids": [
      "185.220.101.5:1080:myuser:mypassword",
      "195.154.255.3:8080"
    ],
    "reason": "Connection reset by peer during target handshake"
  }
  ```
  *(同时兼容单节点 `id: "..."` 与批量列表 `ids: ["..."]`)*。

- **响应 `200 OK` (JSON):**
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
- **异常响应：** `400 Bad Request`（未传 `id`/`ids` 或原因说明为空）、`401 Unauthorized`、`404 Not Found`（库内无符合条件的 `alive` 状态节点）、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"ids":["195.154.255.3:8080"],"reason":"target ban"}'
  ```

---

#### `GET /api/v1/proxies/{id}`
查询单个代理节点的完整画像元数据，包含专属 Check Policy 配置详情（详见 [1.3 节](#13-检测策略与调度配置-checkpolicydto)）、各阶段 RTT 及关联的数据源。

- **路径参数 (Path Parameters):** `id` *(string, URL 百分号编码)* — 代理唯一标识符（`ip:port` 或 `ip:port:user:pass`）。
- **响应 `200 OK` (JSON):**
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
      "max_dead_strikes_zero": 3,
      "max_dead_strikes_active": 3,
      "stability_window_min": 5,
      "dead_backoff_mult_zero": 1.5,
      "dead_backoff_mult_active": 1.5
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
- **异常响应：** `401 Unauthorized`、`404 Not Found`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY"
  ```

---

#### `PATCH /api/v1/proxies/{id}`
动态更新代理节点的备注、认证凭据、SLA 检测策略或强制触发立即复检。

- **路径参数 (Path Parameters):** `id` *(string, URL 百分号编码)*。
- **请求体 (Request Body - JSON):**
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
      "max_dead_strikes_zero": 2,
      "max_dead_strikes_active": 2,
      "stability_window_min": 5,
      "dead_backoff_mult_zero": 2.0,
      "dead_backoff_mult_active": 2.0
    }
  }
  ```
  - `policy` *(object, 可选)*: 局部或全量覆写检测超时策略（详见 [1.3 节](#13-检测策略与调度配置-checkpolicydto)）。
  - `force_recheck` *(bool, 可选)*: 设为 `true` 将当前节点的检测排期重置为即刻触发。
  - `ignore_protocol` *(bool, 可选)*: 重置缓存协议，重新触发全套协议栈自适应嗅探 (SOCKS5 → SOCKS4 → HTTP)。

- **响应：** `200 OK` (响应体为空)。
- **异常响应：** `400 Bad Request`、`401 Unauthorized`、`404 Not Found`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s -X PATCH "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"force_recheck":true,"remark":"updated"}'
  ```

---

#### `DELETE /api/v1/proxies/{id}`
从数据库中物理清除指定的代理记录及其与所有数据源的关联引用。

- **路径参数 (Path Parameters):** `id` *(string, URL 百分号编码)*。
- **响应：** `204 No Content`。
- **异常响应：** `401 Unauthorized`、`404 Not Found`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s -i -X DELETE "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY"
  ```

---

### 第二组：Sources（数据源管理与出产率统计）

#### `GET /api/v1/sources`
拉取系统中所有注册的数据源列表，并输出各数据源的存活出产率 (Yield %)、状态分布与平均时延。

- **URL 查询参数：** 无。
- **响应 `200 OK` (JSON):**
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
- **异常响应：** `401 Unauthorized`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/sources" -H "X-API-Key: $KEY"
  ```

---

#### `GET /api/v1/sources/{name}`
依据数据源的系统名称获取单一维度的深度聚合指标数据。

- **路径参数 (Path Parameters):** `name` *(string)* — 数据源标识名。
- **响应 `200 OK` (JSON):** 单个 `SourceStatsItem` 统计结构体（字段与 `GET /api/v1/sources` 一致）。
- **异常响应：** `400 Bad Request`（名称为空）、`401 Unauthorized`、`404 Not Found`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/sources/premium_pool_v1" -H "X-API-Key: $KEY"
  ```

---

#### `DELETE /api/v1/sources/{name}`
删除指定数据源。属于该数据源且未与其他任何存活数据源关联的孤立代理将被级联物理清除。

- **路径参数 (Path Parameters):** `name` *(string)* — 数据源标识名。
- **响应：** `204 No Content`。
- **异常响应：** `400 Bad Request`、`401 Unauthorized`、`404 Not Found`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s -i -X DELETE "http://127.0.0.1:3000/api/v1/sources/premium_pool_v1" -H "X-API-Key: $KEY"
  ```

---

### 第三组：Judges（裁判节点管理与健康检查）

#### `GET /api/v1/judges`
返回当前登记的全部匿名度验证裁判（内置节点与公网备用节点）列表、时延数据与主备状态。

- **URL 查询参数：** 无。
- **响应 `200 OK` (JSON):**
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
  - `status`: `healthy` (健康), `degraded` (亚健康), `unhealthy` (不可用), `unknown` (未知)。
  - `priority`: `0` 为首选主裁判（如内置 Judge），`1+` 为容灾备选节点。

- **异常响应：** `401 Unauthorized`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/judges" -H "X-API-Key: $KEY"
  ```

---

#### `POST /api/v1/judges/health-check`
强制向所有裁判节点并发发送探测探针，更新健康指标并触发主裁判重新选举（Failover 漂移）。

- **请求体：** 无。
- **响应 `200 OK` (JSON):**
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
- **异常响应：** `401 Unauthorized`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s -X POST "http://127.0.0.1:3000/api/v1/judges/health-check" -H "X-API-Key: $KEY"
  ```

---

### 第四组：Stats（全局指标与实时监控遥测）

#### `GET /api/v1/stats`
全系统宏观监控看板数据：引擎运行速率、各队列代理池存量、质量评分以及按协议、匿名度、错误原因、国家和 ASN 的多维切片统计。

- **URL 查询参数：** 无。
- **响应 `200 OK` (JSON):**
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
- **异常响应：** `401 Unauthorized`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/stats" -H "X-API-Key: $KEY"
  ```

---

#### `GET /api/v1/stats/engine`
从纯内存原子无锁计数器中提取引擎高频遥测指标（零磁盘 I/O 开销，微秒级响应）。

- **URL 查询参数：** 无。
- **响应 `200 OK` (JSON):**
  ```json
  {
    "active_workers": 128,
    "checks_per_sec": 45.2,
    "checks_completed": 15420,
    "batch_buffer_size": 15,
    "judge_healthy": true
  }
  ```
- **异常响应：** `401 Unauthorized`、`500 Internal Server Error`。
- **cURL 调用示例：**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/stats/engine" -H "X-API-Key: $KEY"
  ```

---

### OpenAPI / Swagger 交互式文档

- **`GET /swagger-ui`**: 基于浏览器直接访问的可视化交互测试界面 Swagger UI。
- **`GET /api-docs/openapi.json`**: 遵循 OpenAPI 3.0 规范的机器可读 JSON 定义。

*以上两个路由属于公共白名单，不校验 `X-API-Key` 鉴权头。*

---

## 3. 错误响应标准定义 (`ApiError`)

当请求失败或服务端发生故障时，系统会返回对应的 HTTP 状态码并附带标准统一的 JSON 错误负载：

```json
{
  "error": "not_found",
  "message": "Proxy '185.220.101.5:1080' not found"
}
```

| HTTP 状态码 | `error` 标识符 | 语义描述 |
|---|---|---|
| `400 Bad Request` | `bad_request` | 参数校验未通过或客户端提交了不合规的 JSON。 |
| `401 Unauthorized` | `unauthorized` | 缺少通信凭据或 `X-API-Key` 密钥不匹配。 |
| `404 Not Found` | `not_found` | 所请求的代理节点或指定数据源在数据库中不存在。 |
| `409 Conflict` | `conflict` | 实体唯一性约束冲突或状态不符合操作要求。 |
| `500 Internal Server Error` | `internal_error` | 底层 SQLite/libsql 存储事务异常或异步引擎运行时内部错误。 |
