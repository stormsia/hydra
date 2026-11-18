## 📋 Description

Provide a clear and concise summary of the changes introduced in this Pull Request, explaining why they are needed.

Fixes #(issue)

---

## 🔍 Type of Change

Please mark the options that are relevant:

- [ ] 🐛 **Bug fix** (non-breaking change fixing an issue)
- [ ] ✨ **New feature** (non-breaking change adding functionality)
- [ ] ⚡ **Performance optimization** (improvements to throughput, latency, or memory allocation)
- [ ] 💥 **Breaking change** (fix or feature causing existing functionality or API to change)
- [ ] 📝 **Documentation update** (README, docs, or inline code comments)
- [ ] 🔧 **Maintenance / CI** (dependencies, GitHub Actions, tooling, refactoring)

---

## 📦 Affected Components

- [ ] `hydra_checker` (Proxy validation core & protocols)
- [ ] `hydra_judge` (Echo validation server & token guard)
- [ ] `hydra_api` (REST API server, scheduler & libSQL storage)
- [ ] Shared configuration / CI / Documentation

---

## ✅ Checklist

Before submitting your PR, please verify the following:

- [ ] My code adheres to the style guidelines of this project.
- [ ] I have formatted my code using `cargo fmt --all -- --check`.
- [ ] I have verified that `cargo clippy --workspace --all-targets` passes with no warnings.
- [ ] I have run `cargo test --workspace` and all unit & integration tests pass locally.
- [ ] I have added appropriate tests covering my changes where applicable.
- [ ] I have updated relevant documentation (`README.md`, `docs/`, or OpenAPI specs) if necessary.
- [ ] My changes do not generate new compilation warnings or security risks.
