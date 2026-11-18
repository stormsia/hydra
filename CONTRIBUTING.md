# Contributing to Hydra

Thank you for your interest in **Hydra**! We warmly welcome bug reports, performance optimizations, documentation improvements, and Pull Requests.

[English](CONTRIBUTING.md) • [Русский](CONTRIBUTING.ru.md) • [简体中文](CONTRIBUTING.zh.md)

---

## 🛠️ Development Setup

Hydra is written in Rust (2024 edition) and structured as a Cargo workspace consisting of three crates:
- `hydra_api` — REST API server, background scheduler, and libSQL storage (SQLite WAL).
- `hydra_checker` — Asynchronous network verification core and proxy classification engine.
- `hydra_judge` — Lightweight authorized echo server for anonymity evaluation.

### Requirements
- **Rust >= 1.85** (with support for the `Rust 2024` edition)
- **Cargo** (standard Rust package manager)
- **SQLite / libSQL** (bundled and compiled automatically, no external database server required)

### Building and Testing

1. Clone the repository:
   ```bash
   git clone https://github.com/stormsia/hydra.git
   cd hydra
   ```

2. Create the environment configuration file:
   ```bash
   cp .env.example .env
   ```

3. Build the entire workspace:
   ```bash
   cargo build --workspace
   ```

4. Run the full workspace test suite:
   ```bash
   cargo test --workspace
   ```

5. Or test a specific crate during isolated development:
   ```bash
   cargo test -p hydra_checker
   cargo test -p hydra_judge
   cargo test -p hydra_api
   ```

6. Check formatting and linter before submitting code:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   ```

---

## 📋 Pull Request Guidelines

1. **Branch Naming**: use purpose-based prefixes:
   - `feat/feature-name` — new feature
   - `fix/bug-description` — bug fix
   - `perf/optimization` — performance improvement
   - `docs/doc-update` — documentation updates
2. **Commit Messages**: follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   - `feat(checker): add support for protocol X`
   - `fix(api): correct pagination offset handling`
   - `docs(readme): update architecture diagram`
3. **Test Coverage**: any new feature or bug fix must include unit or integration tests in the corresponding `tests/` directory.
4. **Documentation**: when introducing new environment variables or API endpoints, make sure to update `.env.example`, `docs/API.md`, and relevant module `README.md` files.

---

## 🔒 Security Vulnerabilities

If you discover a security vulnerability in Hydra, please **do not open a public issue**. Report it privately via GitHub Security Advisories.
