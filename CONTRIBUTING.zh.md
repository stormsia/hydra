# 参与贡献 Hydra (Contributing to Hydra)

感谢你关注并支持 **Hydra** 项目！我们热烈欢迎各类 Bug 报告、性能调优建议、文档改进以及代码 Pull Request。

[English](CONTRIBUTING.md) • [Русский](CONTRIBUTING.ru.md) • [简体中文](CONTRIBUTING.zh.md)

---

## 🛠️ 本地开发环境配置 (Development Setup)

Hydra 基于 Rust（2024 版本）构建，采用包含三个核心子包的 Cargo Monorepo 工作区结构：
- `hydra_api` — REST API 服务、后台调度器与 libSQL 持久化存储 (SQLite WAL)。
- `hydra_checker` — 异步高性能网络探测与代理多层级评分分类引擎。
- `hydra_judge` — 轻量级、带安全鉴权的专用 L7 镜像回显服务。

### 环境依赖
- **Rust >= 1.85**（支持 `Rust 2024` edition）
- **Cargo**（Rust 官方包管理工具）
- **SQLite / libSQL**（源码内嵌自动编译，无需安装外部数据库服务）

### 编译与测试运行

1. 克隆代码仓库：
   ```bash
   git clone https://github.com/stormsia/hydra.git
   cd hydra
   ```

2. 初始化环境变量配置文件：
   ```bash
   cp .env.example .env
   ```

3. 编译整个工作区：
   ```bash
   cargo build --workspace
   ```

4. 执行工作区全套单元与集成测试：
   ```bash
   cargo test --workspace
   ```

5. 在独立模块开发时，仅测试目标子包：
   ```bash
   cargo test -p hydra_checker
   cargo test -p hydra_judge
   cargo test -p hydra_api
   ```

6. 提交前进行代码规范与静态分析检查：
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   ```

---

## 📋 Pull Request 规范

1. **分支命名规范**：推荐使用具有明确语义的前缀：
   - `feat/feature-name` — 新功能特性
   - `fix/bug-description` — 缺陷修复
   - `perf/optimization` — 性能提升优化
   - `docs/doc-update` — 文档调整与更新
2. **Commit 提交信息**：遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范：
   - `feat(checker): add support for protocol X`
   - `fix(api): correct pagination offset handling`
   - `docs(readme): update architecture diagram`
3. **测试覆盖**：任何新增功能或缺陷修复必须在对应的 `tests/` 目录中补充单元测试或端到端集成测试用例。
4. **文档同步更新**：新增环境变量或变更 API 路由时，必须同步更新 `.env.example`、`docs/API.zh.md` 以及对应子模块的 `README.md`。

---

## 🔒 安全漏洞反馈 (Security Vulnerabilities)

如在 Hydra 中发现任何安全漏洞，**请切勿公开发布 Issue**。请通过 GitHub 的私密安全报告渠道（Security Advisories）进行负责任的漏洞披露。
