# SEALED Security Policy & Verification

> **Honesty Declaration**:
> No software is ever completely secure. This document states plainly the threat model we defend, the automated tests proving those controls work, and the residual risks we accept. We never claim this product is unhackable.

---

## 1. Zero-Telemetry & Zero-Phone-Home Guarantee

SEALED is built from the ground up for strict confidentiality and air-gapped environments:
- **No author servers exist**: There is no analytics endpoint, no telemetry daemon, no crash reporter, no remote license server, and no remote update check.
- **Outbound connection policy**: The application will *never* attempt a network connection unless:
  1. The user explicitly initiates an active live-endpoint probe, and
  2. The user has explicitly configured the target endpoint URL.
- **Verification**: In CI and automated test suites, the test harness sets an invalid/blocked loopback socket and drops all external packets. The entire audit suite executes offline without network access.

---

## 2. Controls and Automated Tests

Every security control is accompanied by an automated regression test:

| Control | Description | Verification Test |
|---|---|---|
| **Egress Block** | Zero unexpected outbound connections. Deny-by-default. | `tests/security/egress_blocked_test` asserts full scan completes with network disabled. |
| **Path Traversal Defense** | Rejection of `../`, symlinks to `/etc`, and absolute paths outside the project root. | `tests/security/path_traversal_test` attempts scanning parent directory symlinks and confirms rejection. |
| **Zip-Slip Prevention** | Refusal to unpack archives with directory traversal or absolute destinations. | `tests/security/zip_slip_test` feeds crafted zip files containing `../../` filenames. |
| **Decompression Bomb Protection** | Hard cap on total unpacked bytes (100MB) and compression ratio (100:1). | `tests/security/bomb_defense_test` verifies early abort on high-ratio compression streams. |
| **Parser Hardening** | YAML/JSON recursive depth cap (16 levels) and input size cap (5MB). No arbitrary deserialization. | `tests/security/parser_hardening_test` feeds deeply nested JSON objects and confirms clean errors without stack overflows. |
| **Strict Contextual HTML Escaping** | Untrusted model output and user file contents escaped before insertion into `report.html`. | `tests/security/xss_escaping_test` supplies `<script>alert(1)</script>` payloads and verifies literal escaping. |
| **Ed25519 Rule Pack Signatures** | Cryptographic verification of `.sealed-pack.json` before rule activation. | `tests/security/rule_signature_test` asserts tampered rule packs are rejected immediately. |
| **Credential Redaction** | Zero exposure of configured API keys in logs, dumps, or exported evidence archives. | `tests/security/redaction_test` scans exported evidence for raw key fragments. |
| **Deterministic Evidence Generation** | Identical inputs produce byte-identical evidence archives for reproducible auditing. | `tests/security/determinism_test` runs dual passes on `./fixture-project` and asserts matching SHA-256 sums. |

---

## 3. Accepted Residual Risks

1. **Host Compromise (Physical / Root)**:
   If an adversary possesses root/administrator privileges on the machine running SEALED, they can inspect process memory, read OS Keychain records, or modify the binary on disk.
2. **User Explicit Bypass**:
   Users may bypass signature verification using `--allow-unsigned-rules` or allow internal network probing via `--allow-private-endpoints`. SEALED logs loud security warnings when these flags are invoked, but permits the operator to proceed.
3. **Malicious Models Emitting Subtle Deceptions**:
   The attack battery tests known adversarial failure modes (system prompt exfiltration, prompt injection, PII regeneration, tool abuse). A model that behaves safely during deterministic probes may still fail on edge cases in production. SEALED certifies test evidence, not perpetual safety.

---

## 4. Reporting a Vulnerability

If you discover a security flaw in SEALED, please report it via private security advisory or email the maintainers directly with a cryptographic proof-of-concept. All reports will be acknowledged within 24 hours.
