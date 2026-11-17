# SEALED Pre-Release Verification Checklist

Every item in this checklist must be tested and verified before any release candidate is tagged or distributed. If any check fails, the release is strictly blocked.

---

## 1. Security & Network Isolation
- [ ] **Zero Telemetry Assertion**: Automated check confirms zero network calls when scanning without endpoints.
- [ ] **Network Egress Block in CI**: `tests/security/egress_blocked_test` completes successfully with network severed.
- [ ] **SSRF & Private IP Filter**: Assert that attempts to target `169.254.169.254`, `127.0.0.1`, and `10.0.0.0/8` are rejected unless `--allow-private-endpoints` is explicitly set.
- [ ] **Path Traversal & Symlink Escapes**: Assert that paths containing `../` or symlinks pointing outside the project root are rejected.
- [ ] **Zip-Slip & Decompression Bomb Protection**: Malicious test archives rejected; ratio cap enforced.
- [ ] **Ed25519 Signature Verification**: Tampered rule pack fails with exit code `2`.
- [ ] **SQL Query Safety**: Lint passes asserting 100% parameterized queries.
- [ ] **HTML Escaping & CSP**: Strict contextual escaping in `report.html`; no console errors, no inline un-nonced scripts, no remote CDN origins.

---

## 2. Determinism & Evidence Verification
- [ ] **Byte-Identical Evidence**: Run `sealed scan ./fixture-project` twice; compute SHA-256 on both `evidence.zip` outputs; assert identical hashes.
- [ ] **Hash Chain Integrity**: Evidence timeline validates every cryptographic link (`hash = SHA256(prev_hash + finding)`).
- [ ] **Exit Code Conformance**:
  - Exit `0`: Clean project with zero violations.
  - Exit `1`: Findings discovered in project.
  - Exit `2`: Operational / configuration error (e.g. invalid signature, invalid path).

---

## 3. Performance & Resource Budgets
- [ ] **Cold Start**: CLI boots and begins scan in under 150ms.
- [ ] **Streaming Memory Flatness**: Scanning a multi-gigabyte dataset file maintains flat resident memory (< 64MB RAM).
- [ ] **UI Responsiveness**: 60fps rendering maintained while loading 1,000+ simulated findings.

---

## 4. Accessibility & UI Craft (WCAG 2.2 AA)
- [ ] **Keyboard Navigation**: Entire application operable via keyboard (`j`/`k`, `Enter`, `Esc`, `Tab`, `Cmd+K`).
- [ ] **Focus Rings**: Clearly visible on both Dark and Light themes.
- [ ] **Contrast Ratios**: All text and state indicators achieve >= 4.5:1 contrast against their respective surfaces.
- [ ] **Reduced Motion**: Respects `prefers-reduced-motion` with instantaneous transitions.
- [ ] **Zero Slop**: Verified absence of gradients, emojis-as-icons, fake testimonials, lorem ipsum, and uninformative spinners.

---

## 5. Artifacts & Documentation
- [ ] `README.md`, `SECURITY.md`, `THREAT_MODEL.md`, `LIMITATIONS.md`, `DECISIONS.md`, and `SIGNING.md` are up to date and contain zero unverified marketing claims.
- [ ] Pinned dependencies locked in `Cargo.lock`.
- [ ] SHA-256 sums published and signed.
