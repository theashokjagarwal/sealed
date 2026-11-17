# Contributing to SEALED

Thank you for contributing to **SEALED**. Every contribution must preserve three non-negotiable guarantees:

1. **Zero Telemetry / Air-Gap**: Never add analytics, crash reporting, remote update checks, or outbound network calls to author-owned servers.
2. **Determinism**: Identical inputs must produce byte-identical `evidence.zip` archives.
3. **Security First**: Every security control must be backed by an automated regression test that fails when the control is removed.

---

## Development Setup

### Option A: Zero-Dependency CLI & Test Suite (macOS / Linux)
Requires only standard Ruby (pre-installed on macOS):

```bash
git clone https://github.com/theashokjagarwal/sealed.git
cd sealed

# Run all 9 security, determinism, and exit-code tests
./tests/run_all_tests.sh
```

### Option B: Rust Core & CLI
Requires Rust 1.75+ (`cargo`):

```bash
cargo test --workspace
cargo build --release --bin sealed
```

---

## Adding New Compliance Rules

1. Add your rule definition to [`rules/generate_rule_pack.rb`](rules/generate_rule_pack.rb) with exact regulatory clause citations (e.g., EU AI Act Article, ISO/IEC 42001 Control, NIST AI RMF Function, GDPR/DPDP Section).
2. Re-sign the rule pack:
   ```bash
   ruby rules/generate_rule_pack.rb
   ```
3. Add a fixture case under `fixture-project/` and verify `./bin/sealed scan ./fixture-project` flags the new violation and `./tests/run_all_tests.sh` passes.

---

## UI Contributions

Read [`DECISIONS.md`](DECISIONS.md) before modifying anything under `ui/`. All UI changes must obey the frozen **Instrument Panel** rules:
- Use semantic CSS tokens only (no hardcoded colors).
- Strictly follow the 4px spacing scale (`4/8/12/16/24/32/48`).
- Maintain full keyboard navigation (`j`/`k`, `Enter`, `Esc`) and `prefers-reduced-motion` support.
- Zero external CDN dependencies or inline un-escaped model output.

---

## Pull Request Checklist

- [ ] `./tests/run_all_tests.sh` passes with exit code `0`.
- [ ] Byte-determinism verified (`test_determinism.rb` passes).
- [ ] Zero new telemetry or outbound network endpoints (`test_network_blocked.rb` passes).
- [ ] Documentation updated (`README.md`, `THREAT_MODEL.md`, or `LIMITATIONS.md` as appropriate).

---

## Reporting Security Vulnerabilities

Do **not** open a public GitHub issue for security flaws. Follow the private disclosure instructions in [`SECURITY.md`](SECURITY.md).
