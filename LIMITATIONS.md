# SEALED Platform Capabilities & Limitations

We state our platform limits honestly rather than pretending all operating systems offer identical access models.

---

## Target Matrix Comparison

| Capability | Desktop (macOS / Linux / Windows) | Web (WASM / Browser PWA) | Mobile Companion (iOS / Android) |
|---|---|---|---|
| **Arbitrary Folder Scanning** | **Full Support** — direct local filesystem walk | **Restricted** — Requires user grant via File System Access API per folder | **Unsupported** — OS sandbox prohibits arbitrary filesystem traversal |
| **Streaming File Scanning (2GB+)** | **Full Support** — low-memory chunked streaming | **Limited** — Constrained by browser tab memory and quota | **Unsupported** — Cannot access project source trees |
| **Offline Rule Engine & Controls** | **Full Support** | **Full Support** (in-browser WASM execution) | **Full Support** |
| **Hash-Chain Verification** | **Full Support** | **Full Support** | **Full Support** — verify exported `evidence.zip` on-device |
| **Evidence Pack Review & Sign-Off**| **Full Support** | **Full Support** | **Full Support** — mobile executive sign-off & attestation |
| **Live AI Endpoint Probing** | **Full Support** | **Restricted** — Subject to browser CORS policy unless using proxy | **Full Support** — Direct HTTPS connection to configured AI API |
| **Native Probe Model Execution** | **Full Support** (via local binary or Ollama/Llama.cpp) | **Unsupported** — Cannot spawn native subprocesses in browser | **Unsupported** — Cannot spawn external binaries |
| **OS Keychain Key Storage** | **Full Support** (macOS Keychain / SecretService / WinCred) | **IndexedDB / WebCrypto** (scoped to browser origin) | **OS Keystore / Keychain** |
| **Deterministic Evidence Export** | **Full Support** | **Full Support** (client-side generated ZIP) | **Full Support** |
| **CI/CD Automation (CLI)** | **Full Support** (`sealed scan ./path`) | N/A (interactive web context) | N/A |

---

## Detailed Platform Constraints

### 1. Desktop: macOS, Linux, Windows (Primary Full-Power Target)
- The desktop application and CLI are the unrestricted audit targets.
- Capable of recursive filesystem crawling, symlink resolution checks, local database persistence, OS keychain integration, and running deterministic attack batteries.
- Recommended for CI/CD pipelines, pre-commit hooks, and developer workstations.

### 2. Web Application: Client-Side WebAssembly (PWA)
- Runs 100% in the client's browser using `sealed-core` compiled to WebAssembly.
- **Zero data upload**: Files selected by the user never leave their browser. No backend server is contacted.
- **File System Access API**: Supported on modern Chromium engines. Users must explicitly select the directory and grant read permissions when prompted.
- **CORS Constraints**: Live probing against third-party AI APIs requires the target endpoint to allow cross-origin requests, or the operator must use the desktop CLI.

### 3. Mobile: iOS & Android (Viewer & Attestation Companion)
- Due to mobile operating system sandboxing, third-party apps cannot freely traverse arbitrary directory paths or inspect repositories on the host device.
- **Intended Role**: SEALED Mobile is a **review and verification companion**:
  - Open and inspect exported `evidence.zip` bundles from auditors or CI runs.
  - Re-compute cryptographic SHA-256 hash chains locally to confirm zero tampering.
  - Review findings against EU AI Act, NIST AI RMF, and ISO 42001 clauses.
  - Capture auditor biometric sign-off and append attestation signatures.
  - Run remote endpoint probes against user-configured endpoints and API keys stored in the device Secure Enclave / Keystore.
