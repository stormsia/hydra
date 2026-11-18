# Security Policy

The Hydra team takes the security of our high-performance proxy verification and orchestrator engine seriously. We appreciate responsible disclosure of potential vulnerabilities.

---

## Supported Versions

Only the latest release and the current `main` branch receive security patches and updates.

| Version | Supported          |
| ------- | ------------------ |
| `0.1.x` | :white_check_mark: |
| `main`  | :white_check_mark: |
| `< 0.1` | :x:                |

---

## Reporting a Vulnerability

> [!IMPORTANT]
> **Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Hydra, please report it privately through one of the following methods:

1. **GitHub Private Vulnerability Reporting (Preferred)**:
   Navigate to the [Security Advisories tab](https://github.com/stormsia/hydra/security/advisories) on GitHub and click **"Report a vulnerability"**. This allows secure, encrypted discussion and collaborative patching prior to public release.

2. **Direct Security Contact**:
   Send an email to **[sf_root@outlook.com](mailto:sf_root@outlook.com)** with the subject line `[SECURITY] Potential vulnerability in Hydra`.
   - If possible, include a reproducible Proof of Concept (PoC).
   - Detail the affected component (`hydra_api`, `hydra_checker`, or `hydra_judge`).
   - Describe the potential impact and attack vector (e.g., SSRF, auth bypass, DoS/OOM).

### Response Timeline

- **Initial Response**: We will acknowledge receipt of your report within **48 hours**.
- **Assessment**: We will confirm or clarify the vulnerability and determine the severity within **5 business days**.
- **Fix and Release**: We aim to produce a patch and release an advisory within **14 business days** depending on complexity.
- **Credit**: If requested, we will publicly credit the reporter in the release notes and GitHub Security Advisory.

---

## Scope & Security Architecture

Hydra is built in memory-safe Rust with explicit defenses:

| Component | Security Surface | Enforced Defenses |
| --------- | ---------------- | ----------------- |
| `hydra_api` | REST endpoints, SQLite DB | API Key authentication (`X-API-Key`), query sanitization, bounded batch buffers. |
| `hydra_checker` | Untrusted network outbound sockets | Bogon & private IP filtering (`net_filter`) to prevent internal network SSRF, zero socket leaks, bounded concurrency. |
| `hydra_judge` | Public echo listener | Daily HMAC Token rotation (`Anti-Abuse Token Guard`), instant TCP RST on unauthorized scanners, bounded connection semaphores. |

Areas of particular interest:
- Server-Side Request Forgery (SSRF) bypasses in `hydra_checker`'s bogon filter.
- Authentication bypass or privilege escalation in `hydra_api`.
- Algorithmic complexity attacks leading to socket exhaustion or unbounded memory allocation (DoS).

---

## Safe Harbor

We consider security research conducted under this policy to be authorized. We will not pursue legal action against security researchers who:
- Make a good faith effort to avoid privacy violations, data destruction, and service interruption.
- Give us reasonable time to remedy the vulnerability before disclosing it publicly.
- Do not exploit the vulnerability beyond what is strictly necessary to demonstrate proof-of-concept.
