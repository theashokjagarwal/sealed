# SEALED — Local-First AI Compliance & Safety Auditor

[![Air-Gapped Security](https://img.shields.io/badge/Network-Air--Gapped%20(Zero%20Telemetry)-emerald?style=flat-square)](#hard-constraint-zero-telemetry)
[![Determinism](https://img.shields.io/badge/Evidence-Cryptographic%20SHA--256%20Chain-blue?style=flat-square)](#cryptographic-evidence-chain)
[![Rule Packs](https://img.shields.io/badge/Rules-Ed25519%20Signed-cyan?style=flat-square)](#ed25519-signed-rule-packs)
[![License](https://img.shields.io/badge/License-Apache%202.0-gray?style=flat-square)](LICENSE)

**SEALED** is a local-first program you install on your own machine. Point it at a folder containing an AI project (code, prompts, datasets, model files, or an API endpoint + key you own). SEALED:
1. Discovers the AI surface in that folder (prompts, training corpora, RAG documents, agent tools, model artifacts, credentials).
2. Scans local data files for personal data (offline) using low-memory streaming regex and Luhn credit-card verification.
3. Runs a deterministic attack battery against the AI (prompt injection, jailbreak, system-prompt extraction, indirect RAG injection, PII regeneration, tool abuse).
4. Checks every finding against an Ed25519-signed rule pack (EU AI Act, ISO/IEC 42001, NIST AI RMF, GDPR/DPDP).
5. Writes a standalone `report.html` and a byte-deterministic, hash-chained `evidence.zip`.
6. Exits `0` (clean) or `1` (violations found) for automated CI/CD pipeline gating.

---

## Hard Constraint: Zero Telemetry & Air-Gapped Egress

SEALED never contacts any server belonging to its authors:
- **No telemetry**, no crash reporting, no license validation, no remote analytics, and no update checks.
- **The only permitted outbound connections** are to AI endpoints configured explicitly by the user.
- **Automated Verification**: In test suites and CI, the network is severed and assertions confirm the audit completes 100% offline.

---

## Quickstart

### 1. Run an Audit via CLI
```bash
# Audit a project folder (exits 0 if clean, 1 if violations found)
sealed scan ./fixture-project --output-dir ./audit-artifacts

# Run with custom signed rule pack
sealed scan ./my-project --rule-pack ./rules/eu-ai-act-iso42001-nist-v1.sealed-pack.json

# Verify the cryptographic integrity of an exported evidence pack
sealed verify ./audit-artifacts/evidence.zip
```

### 2. Launch the Instrument Panel UI
Open `ui/index.html` in any modern web browser or run with Tauri desktop:
```bash
open ui/index.html
```

---

## Core Capabilities

```
+---------------------------------------------------------------------------------+
|                                SEALED AUDITOR                                   |
+---------------------------------------------------------------------------------+
|  1. SURFACE DISCOVERY                                                           |
|     * Lexicographically sorted recursive filesystem crawl                       |
|     * Symlink escape & path traversal boundary validation                       |
|     * Identification: prompts, datasets, RAG vectors, tool handlers, configs    |
+---------------------------------------------------------------------------------+
|  2. STREAMING PII SCANNER                                                       |
|     * Constant-memory 64KB sliding-window scanner (zero 2GB file RAM spikes)    |
|     * Credit Cards with Luhn (Mod 10) validation                                |
|     * US SSNs, personal emails, international phone numbers                     |
|     * Hardcoded API keys (sk-..., AKIA...) & embedded database passwords        |
+---------------------------------------------------------------------------------+
|  3. DETERMINISTIC ATTACK BATTERY                                                |
|     * Direct Prompt Injection & Role Hijack probes                              |
|     * System Prompt & Intellectual Property Exfiltration                       |
|     * Indirect RAG Injection (embedded HTML/Markdown comment payloads)          |
|     * Autonomous Tool Abuse (detection of eval(), os.system(), raw shell)       |
+---------------------------------------------------------------------------------+
|  4. ED25519 SIGNED RULE ENGINE                                                  |
|     * Regulatory Mapping: EU AI Act (Art 10, 14, 15), ISO 42001 (A.8.4, A.9.2), |
|       NIST AI RMF (Measure 2.7, Manage 2.4), GDPR Art 5(1)(c) / DPDP Sec 8      |
|     * Cryptographic validation of .sealed-pack.json before activation           |
+---------------------------------------------------------------------------------+
|  5. CRYPTOGRAPHIC EVIDENCE CHAIN & REPORTING                                    |
|     * SHA-256 Hash Chain: Block[i] = SHA256(Block[i-1] : id : payload_sha)      |
|     * Deterministic ZIP writer: fixed mtime, sorted entries = byte-identical    |
|     * Self-contained report.html with strict Content-Security-Policy & A4 print |
+---------------------------------------------------------------------------------+
```

---

## Architectural Breakdown: One Core, Every Platform

SEALED is engineered around a single Rust core and thin platform shells:
- **Rust Core (`crates/sealed-core`)**: Discovery, streaming PII scanner, attack battery, rule engine, evidence packager, and HTML generator. 100% of logic lives here with zero I/O assumptions.
- **CLI (`crates/sealed-cli` & `bin/sealed`)**: Command-line interface for terminal and CI/CD pipelines. Ships with a self-contained runner requiring zero external dependencies.
- **Desktop (Tauri 2)**: Native packaging for macOS (`.app`, `.dmg`), Windows (`.msi`, `.exe`), and Linux (`.deb`, AppImage).
- **Mobile (Tauri 2 Mobile)**: Viewer & attestation companion for iOS (`.ipa`) and Android (`.apk`).
- **Web (WebAssembly / PWA)**: Core compiled to WebAssembly via `wasm-bindgen`, operating 100% client-side via the browser's File System Access API.
- **Frontend UI (`ui/`)**: Dense, calm "Instrument Panel" design system adhering strictly to `DECISIONS.md`. Dual light and dark themes shipping day one.

---

## Verified Security Controls

Every security claim in SEALED is enforced by an automated regression test:

| Control Area | Security Mechanism | Test Script |
|---|---|---|
| **Determinism** | Identical inputs produce byte-identical `evidence.zip` (verified SHA-256 match). | `tests/test_determinism.rb` |
| **Network Egress** | Deny-by-default; zero author endpoints; offline scan execution in air-gap. | `tests/test_network_blocked.rb` |
| **Path Traversal** | Rejects `..` path segments and symlinks targeting outside the project boundary. | `tests/test_path_traversal.rb` |
| **Rule Integrity** | Ed25519 signature required; tampered rules rejected with exit code 2. | `tests/test_rule_signature.rb` |
| **SSRF Defense** | Blocks access to cloud metadata (`169.254.169.254`), loopback (`127.0.0.1`), RFC1918. | `tests/test_ssrf_egress.rb` |
| **Zip-Slip & Bomb**| Refuses archives with `../` entries; enforces 100MB / 1000 entry caps. | `tests/test_zip_slip_and_bomb.rb` |
| **XSS & CSP** | Contextual escaping of model output; strict CSP (`default-src 'none'`). | `tests/test_xss_and_escaping.rb` |
| **SQL Safety** | 100% parameterized queries; string interpolation in queries forbidden by lint. | `tests/test_sql_safety.rb` |
| **CI Gating** | Exit code 0 (clean), 1 (violations), 2 (configuration or security violation). | `tests/test_exit_codes.rb` |

### Running the Full Test Suite
```bash
./tests/run_all_tests.sh
```

---

## Documentation Index

- [DECISIONS.md](DECISIONS.md) — Frozen design direction ("Instrument Panel"), type scale, 4px grid, dual themes, and anti-slop rules.
- [SECURITY.md](SECURITY.md) — Security policy, zero-telemetry guarantee, defended threat model, and accepted risks.
- [THREAT_MODEL.md](THREAT_MODEL.md) — Threat matrix: assets, adversaries, entry points, existing controls, and residual risks.
- [LIMITATIONS.md](LIMITATIONS.md) — Honest platform capabilities across Desktop, Web (WASM), and Mobile.
- [SIGNING.md](SIGNING.md) — Ed25519 rule pack signatures, OS code signing & notarization, and reproducible builds.
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) — Pre-release quality gate and criteria blocking unauthorized releases.
