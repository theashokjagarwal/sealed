# SEALED Threat Model & Security Controls

## 1. System Overview & Core Philosophy
SEALED is an offline, local-first AI compliance and safety auditor. It executes in privileged and semi-privileged local environments (engineer workstation, CI/CD runner) and reads untrusted targets (third-party code, malicious datasets, prompt templates, crafted zip archives) and interacts with user-specified model endpoints.

**Core Threat Principle**: Every input — including project source trees, datasets, model responses, and rule packs — is treated as potentially adversarial.

---

## 2. Threat Analysis Matrix

| Asset | Adversary | Entry Point | Threat / Vector | Existing Control in SEALED | Residual Risk |
|---|---|---|---|---|---|
| **Auditor Host & CI Runner** | Malicious Repo Author | Project Folder Structure | Path traversal / symlink escape outside root (`../../etc/passwd`) | Canonical resolution check: `canonicalize(target).starts_with(project_root)`. Hard reject on boundary traversal or symlink escape. | Pathological deep symlink loops consumed before resolution (mitigated by depth cap 32 & cycle set). |
| **Auditor Host Disk** | Malicious Repo Author | Evidence Zip / Archive unpack | Zip-Slip: overwrite executable binaries or cron files | Strict entry filename sanitization: rejection of absolute paths, drive letters, and `..` segments before opening output stream. Decompression bomb ratio limit (100:1 max, 100MB cap). | Host running out of disk space from raw scan output (mitigated by disk space quota check). |
| **Evidence Integrity** | Compromised Sub-process or Tamperer | Evidence Pack ZIP & Hash Chain | Modification or excision of failed findings | Cryptographic SHA-256 hash chain: Genesis block hashes project metadata; each finding links `hash = SHA256(prev_hash + finding_bytes)`. Any modification breaks subsequent blocks. | Private key signing is external to the chain unless exported with an auditor hardware key. |
| **Internal Network / Cloud VPC** | Malicious Target Configuration | User API Endpoint String | SSRF against AWS metadata (`169.254.169.254`), loopback (`127.0.0.1`), or internal RFC1918 VPC targets | Egress filter: allow only `http`/`https`; block metadata (`169.254.169.254`), link-local (`fe80::/10`), IPv6 loopback (`::1`). Resolve DNS prior to connection and assert non-private unless `--allow-private-endpoints` flag is explicitly passed. Pin TLS, enforce 5s timeout, cap response at 2MB. | Authorized target endpoint compromised by adversary after TLS termination. |
| **Auditor UI / Browser** | Adversarial AI Model | Prompt Response / Finding Output | Stored XSS in `report.html` via malicious model output containing `<script>` or event handlers | Contextual HTML escaping across all interpolations. Zero `innerHTML` with unsanitized data. Strict CSP: `default-src 'self'; script-src 'nonce-...'; style-src 'unsafe-inline'; object-src 'none'`. No remote scripts or CDNs. | Browser zero-day CSS vulnerability in layout rendering engine. |
| **Local Database & Cache** | Unprivileged Local User | Local State / SQLite Cache | Unauthorized read of discovered system prompts or secrets | Storage file permissions enforced at `0600` (read/write by owner only). Explicit warning emitted if parent directory is world-readable (`0777`). Parameterized SQL queries only. | Root user or administrator on the local host can bypass OS file permissions. |
| **Rule Engine Integrity** | Rogue Rule Pack Author | Imported `.sealed-pack.json` | Injection of arbitrary executable rules, malicious YAML objects, or rule tampering | Ed25519 cryptographic signature verification required. Unsigned packs blocked by default (explicit bypass requires CLI confirmation). Parser limits: depth <= 16, size <= 5MB. No code execution capabilities in rule definitions. | User explicitly bypassing unsigned verification warning with `--allow-unsigned-rules`. |
| **User Secrets & API Keys** | Third-party dependencies / Logs | API keys configured for model audits | Credential exfiltration via logging, telemetry, or evidence export | Zero telemetry to author servers (enforced by code & test). API keys stored in OS Keychain (macOS Keychain, Linux SecretService, Windows Credential Manager). Keys redacted from memory dumps, evidence packs, and log messages (`sk-...` -> `sk-***`). | Malware on host capturing clipboard if user pastes secret directly. |

---

## 3. Specific Control Implementations

### 3.1 Network Egress Restriction
- Outbound traffic is blocked by default in test mode.
- In active probe mode, outbound traffic is permitted **only** to the user-supplied endpoint URL.
- No telemetry, analytics, license checking, or update checking is present in the codebase.
- Verified in automated CI with outbound sockets completely denied.

### 3.2 SQL Parameterization Assertion
- All persistence logic uses parameterized queries exclusively:
  ```rust
  // ALLOWED:
  db.execute("INSERT INTO findings (id, test_id, severity) VALUES (?1, ?2, ?3)", params![id, test_id, severity])?;
  // STRICTLY FORBIDDEN & LINT-ENFORCED:
  // format!("INSERT INTO findings VALUES ('{}')", id);
  ```
- Build-time regex check fails compilation if string formatting or concatenation is used adjacent to SQL query execution.

### 3.3 Path Traversal and Symlink Defense
- Every scanned path is validated against the canonicalized root:
  ```rust
  let canonical_root = std::fs::canonicalize(project_root)?;
  let canonical_target = std::fs::canonicalize(target_path)?;
  if !canonical_target.starts_with(&canonical_root) {
      return Err(SecurityError::PathTraversalEscape(target_path));
  }
  ```
- Symlinks pointing outside the project root are reported as security warnings and skipped during file discovery.

### 3.4 Strict HTML Report Escaping & CSP
- Every dynamic field (model output, prompt text, file path, rule clause) is strictly encoded using HTML entity escaping before rendering in `report.html`.
- Content-Security-Policy headers and `<meta>` tags restrict script execution to local static bundles with no network egress (`connect-src 'none'`).
