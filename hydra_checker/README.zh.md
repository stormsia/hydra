[← 返回 Hydra README](../README.zh.md)

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

# Hydra Checker

基于 Rust (Tokio) 开发的高性能异步代理验证与分类核心引擎。支持前置 L4 端口探活、级联协议自动协商（SOCKS4/5、HTTP CONNECT、Plain HTTP）、裁判节点池（Judge Pool）端到端真实校验，以及严格的匿名度多维检测，彻底杜绝套接字与文件描述符泄漏。

## 目录结构

```text
hydra_checker/
├── .env.example              # 环境变量配置模板
├── Cargo.toml                # 软件包清单与依赖声明
├── Cargo.lock                # 锁定依赖项版本文件
├── README.md                 # 模块技术说明文档
├── examples/
│   └── stress_bench.rs       # 极限吞吐量与并发压力测试示例
├── src/
│   ├── judge/
│   │   ├── anonymity.rs      # 代理匿名度等级（高匿/匿名/透明）判定逻辑
│   │   ├── endpoint.rs       # 裁判节点元数据与连接实体结构
│   │   ├── health.rs         # 后台裁判节点健康探活与故障剔除
│   │   ├── mod.rs            # 裁判对接交互子系统重新导出
│   │   ├── pool.rs           # 裁判池负载均衡、权重与故障倒换 (Failover)
│   │   └── probe.rs          # 裁判 L7 探活及回显令牌校验
│   ├── pipeline/
│   │   ├── handshake.rs      # 协议握手协商与级联协议自动探测
│   │   ├── l4_probe.rs       # 前置 L4 TCP 端口可用性探测与 Bogon 过滤
│   │   ├── l7_judge.rs       # 经由代理隧道的端到端 L7 裁判请求
│   │   └── mod.rs            # 校验流水线多阶段调度编排
│   ├── pool/
│   │   ├── mod.rs            # 并发工作池模块重新导出
│   │   └── worker_pool.rs    # 基于 Tokio 信号量的全局并发度硬限制控制
│   ├── protocols/
│   │   ├── http_connect.rs   # HTTP CONNECT 隧道代理协议实现
│   │   ├── http_plain.rs     # 普通 HTTP 转发协议实现
│   │   ├── mod.rs            # 代理协议通用特征与核心 Trait
│   │   ├── socks4.rs         # SOCKS4 / SOCKS4a 协议实现
│   │   └── socks5.rs         # 带认证支持的 SOCKS5 协议实现
│   ├── transport/
│   │   ├── mock.rs           # 无网络单元测试 Mock 拨号器
│   │   ├── mod.rs            # 网络传输抽象层 (Dialer Trait)
│   │   ├── tcp.rs            # 定制 TCP 拨号器 (SO_LINGER=0, TCP_NODELAY)
│   │   └── tls.rs            # 异步 TLS 连接器与 PrefixedStream 预读缓冲
│   ├── config.rs             # 检测引擎参数解析与配置定义
│   ├── engine.rs             # 核心验证执行统一门面 (Facade)
│   ├── error.rs              # 强类型错误枚举 (ErrorReason)
│   ├── lib.rs                # 模块根与公共 API 导出
│   ├── models.rs             # 待检目标、检测结果与性能指标结构体
│   ├── net_filter.rs         # SSRF 防护及 Bogon 保留 IP 前置过滤
│   └── token.rs              # 基于 HMAC-SHA256 的每日轮替令牌计算
└── tests/
    ├── anonymity_tests.rs    # 匿名度判定规则与请求头检测测试
    ├── judge_pool_tests.rs   # 裁判池容灾与负载均衡策略测试
    ├── mock_pipeline_tests.rs# 基于 Mock 拨号器的流水线全链路测试
    ├── net_filter_tests.rs   # Bogon 过滤与 DNS 重绑定防护测试
    ├── tls_tunnel_tests.rs   # 穿透代理的 TLS 隧道建立测试
    └── token_rotation_tests.rs # HMAC 动态令牌验证测试
```

## 网络验证流水线

1. **L4 (TCP Connect)**：发起 SYN 连接握手，启用 `SO_LINGER=0`，前置拦截 Bogon/SSRF，并高精度测算 TCP RTT。
2. **Handshake（握手协商）**：协商代理协议（SOCKS5、SOCKS4、HTTP CONNECT）或按序进行级联自动探测。
3. **TLS / Judge（回显验证）**：在隧道之上建立 TLS 加密会话，向指定裁判发送 HTTP 请求并严格核验响应中的防伪令牌。
4. **Anonymity（匿名度判定）**：深度比对回显网络请求头及客户端出口 IP，精确判定等级（高匿 Elite、普通匿名 Anonymous、透明 Transparent）。当未指定 `CHECKER_REAL_IP` 时，引擎将在健康探活循环中通过健康裁判多数票共识动态自动探测真实公网出口 IP（自动过滤 bogon/私网地址）。

## 环境变量配置

| 环境变量 | 类型 | 默认值 | 用途说明 |
|---|---|---|---|
| `JUDGE_HTTP_URL` | String (URL) | `http://127.0.0.1:8080` | 用于普通 HTTP 校验的裁判地址 |
| `JUDGE_HTTPS_URL` | String (URL) | `http://127.0.0.1:8080` | 用于 HTTPS 隧道校验的裁判地址 |
| `JUDGE_SECRET_TOKEN` | String | `hydra_secret_token` | 用于验证裁判合法回显的静态令牌 |
| `JUDGE_SECRET_KEY` | Hex String | — | 用于每日动态 HMAC-SHA256 令牌轮替密钥 |
| `CHECKER_CONCURRENCY` | usize | `5000` | 全局并发验证任务协程数上限 |
| `CHECKER_CONNECT_TIMEOUT_MS` | u64 | `3000` | L4 TCP 建立连接超时（毫秒） |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | u64 | `4000` | 代理协议握手超时（毫秒） |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | u64 | `5000` | 裁判数据收发 I/O 超时（毫秒） |
| `CHECKER_MAX_READ_BYTES` | usize | `8192` | 裁判响应报文最大读取字节限制 |
| `CHECKER_LOCAL_BIND_IP` | IpAddr | — | 出站套接字本地网卡绑定 IP |
| `CHECKER_REAL_IP` | IpAddr | *(自动: 裁判共识)* | 本机外网出口公网 IP（用于判定透明代理；未指定时默认基于健康裁判多数票共识动态探测，显式配置优先） |
| `ENABLE_BUILTIN_JUDGE` | bool | `true` | 是否在检测池中启用内置/主裁判节点 |
| `ENABLE_THIRD_PARTY_JUDGES` | bool | `true` | 是否启用内置第三方公共裁判节点池 |
| `JUDGE_SELECTION_STRATEGY` | String | `lowest_latency` | 活跃裁判节点负载均衡优选策略 |
| `ADDITIONAL_JUDGES` | String | — | 附加的第三方裁判服务节点地址列表（逗号分隔） |
| `RUST_LOG` | String | `info` | 系统运行日志级别过滤规则 |

## CLI 操作命令

### 编译构建
```bash
cargo build -p hydra_checker --release
```

### 运行测试
```bash
# 运行模块所有单元与集成测试
cargo test -p hydra_checker

# 运行指定的集成测试套件
cargo test -p hydra_checker --test mock_pipeline_tests
```

### 代码检查与格式化
```bash
cargo fmt --check
cargo clippy -p hydra_checker --all-targets -- -D warnings
```

### 吞吐压力基准测试
```bash
cargo run -p hydra_checker --example stress_bench --release
```
