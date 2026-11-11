# Contributing to Hydra

Thank you for your interest in contributing to **Hydra**! We welcome bug reports, feature suggestions, documentation improvements, and pull requests.

---

## 🛠️ Development Setup

Hydra is written in Rust (2024 edition) and structured as a Cargo workspace with three primary crates:
- `hydra_api`: REST API server, scheduler, and SQLite/libSQL WAL persistence.
- `hydra_checker`: Asynchronous multi-stage proxy checking engine.
- `hydra_judge`: Authorized high-throughput echo server for proxy anonymity evaluation.

### Prerequisites
- **Rust >= 1.85** (Rust 2024 edition support)
- **Cargo** package manager
- **SQLite / libSQL**

### Building and Testing

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/hydra.git
   cd hydra
   ```

2. Copy the sample environment:
   ```bash
   cp .env.example .env
   ```

3. Build the entire workspace:
   ```bash
   cargo build --workspace
   ```

4. Run all unit and integration tests:
   ```bash
   cargo test --workspace
   ```

5. Run linter and formatting checks:
   ```bash
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all -- --check
   ```

---

## 📋 Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names:
   - `feat/feature-name`
   - `fix/bug-description`
   - `docs/readme-improvements`
   - `perf/optimization-description`
2. **Commit Messages**: Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(checker): add support for protocol X`
   - `fix(api): correct pagination offset handling`
   - `docs: update root README architecture diagram`
3. **Tests**: Ensure any new logic or bug fix includes corresponding unit or integration tests in `tests/`.
4. **Documentation**: Update code docstrings and relevant crate `README.md` files when introducing new configuration parameters or endpoints.

---

## 🔒 Security Vulnerabilities

If you discover a security vulnerability within Hydra, please do **not** open a public issue. Instead, report it privately by sending an email to `security@hydra-proxy.internal` or via GitHub Security Advisories.
