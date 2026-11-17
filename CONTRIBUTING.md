# Contributing to SEALED

Every contribution must preserve three core guarantees:

1. **Zero Telemetry / Air-Gap**: Never add analytics, crash reporting, remote update checks, or outbound network calls to author-owned servers.
2. **Byte-Determinism**: Identical inputs must produce byte-identical `evidence.zip` archives.
3. **Zero External Dependencies**: Core modules rely strictly on standard libraries (Python 3 stdlib, C++17 stdlib, Java 17 stdlib, Vanilla JS/HTML/CSS).

---

## Development Setup

```bash
git clone https://github.com/theashokjagarwal/sealed.git
cd sealed

# 1. Run all 9 security, air-gap & determinism tests (Python 3)
python3 tests/run_all_tests.py

# 2. Build & test the C++17 streaming PII/Luhn scanner
g++ -std=c++17 -O2 -Wall -Wextra -o native_cpp/sealed_fast_scanner native_cpp/sealed_fast_scanner.cpp
./native_cpp/sealed_fast_scanner ./fixture-project

# 3. Compile & test the Java standalone evidence verifier
javac java_cli/SealedVerifier.java
java -cp java_cli SealedVerifier ./evidence.zip

# 4. Launch the Instrument Panel Workbench UI locally
python3 sealed.py serve --port 8787
```

---

## Adding Compliance Rules

1. Add your rule definition to [`rules/generate_rule_pack.py`](rules/generate_rule_pack.py) with exact regulatory citations.
2. Re-sign the rule pack with Ed25519:
   ```bash
   python3 rules/generate_rule_pack.py
   ```
3. Verify `./tests/run_all_tests.py` passes cleanly.

---

## UI Contributions

Read [`DECISIONS.md`](DECISIONS.md) before modifying `ui/`. All UI changes must obey the frozen **Instrument Panel** system:
- Semantic CSS tokens only (zero hardcoded colors, zero gradients).
- 4px strict spacing scale and max 8px border radius.
- Full keyboard navigation (`⌘K`, `1`–`8`, `j`/`k`, `t`, `Esc`) and `prefers-reduced-motion` support.
