# SEALED Code Signing, Notarization & Cryptographic Verification

This document specifies the cryptographic identity, packaging, code signing, and notarization workflows across platforms, and the security implications of running unsigned builds.

---

## 1. Cryptographic Signatures for Rule Packs

All official SEALED rule packs (e.g. `eu-ai-act-iso42001-nist-v1.sealed-pack.json`) are cryptographically signed using **Ed25519**.

### Structure of a Signed Rule Pack
```json
{
  "header": {
    "pack_id": "sealed-official-eu-nist-iso",
    "version": "1.0.0",
    "timestamp": 1735689600,
    "issuer": "SEALED Official Core Governance",
    "public_key": "6a9f8b41...<hex-encoded Ed25519 public key>"
  },
  "rules": [ ... ],
  "signature": "<hex-encoded Ed25519 signature over canonical header+rules JSON>"
}
```

### Verification Flow
1. SEALED extracts `header` and `rules`.
2. Computes the canonical RFC 8785 JSON representation of `{header, rules}`.
3. Verifies the signature against the embedded or trusted root public key.
4. **Behavior on Failure**:
   - If the signature is invalid or missing, SEALED aborts execution with exit code `2`.
   - In the Desktop UI, an alert modal opens explaining that the rule pack has been modified or originates from an untrusted author.
   - Bypassing requires explicit flag `--allow-unsigned-rules` (CLI) or clicking "Accept Risk & Load Unsigned Pack" with a written explanation (UI).

---

## 2. Platform Binary Code Signing & Notarization

### 2.1 macOS (.app / .dmg / CLI)
- **Identity**: Developer ID Application certificate (`Developer ID Application: SEALED Security Inc (XXXXXXXXXX)`).
- **Hardened Runtime**: Enabled with flags `--options runtime --timestamp`.
- **Entitlements**:
  - `com.apple.security.keychain`: Access to local OS Keychain for API credentials.
  - `com.apple.security.network.client`: User-configured outbound connections only.
  - `com.apple.security.files.user-selected.read-only`: Access to user-chosen directories.
- **Notarization**: Submitted to Apple notary service (`xcrun notarytool submit`).
- **Unsigned Build Warning**: macOS Gatekeeper will display `"SEALED cannot be opened because Apple cannot check it for malicious software"`. Users must manually allow it via System Settings -> Privacy & Security.

### 2.2 Windows (.msi / .exe)
- **Identity**: EV (Extended Validation) Authenticode Certificate.
- **Timestamp Server**: Authenticode RFC 3161 timestamping (`http://timestamp.digicert.com`).
- **SmartScreen**: EV signed binaries bypass Windows SmartScreen warnings immediately; unsigned binaries show `"Windows protected your PC - Unknown Publisher"`.

### 2.3 Linux (.deb / AppImage)
- **Identity**: GPG Key (`4096R/SEALED-RELEASE-SIGNING-KEY`).
- Package repositories provide signed `.asc` detach signatures and `Release.gpg` validation.

---

## 3. Reproducible Builds & Verification

SEALED guarantees byte-reproducible releases from public source commits:
1. **Pinned Toolchain**: Pinned in `rust-toolchain.toml`.
2. **Locked Dependencies**: All dependencies are locked in `Cargo.lock`.
3. **Environment Standardization**:
   - `SOURCE_DATE_EPOCH` is set to the git commit UNIX timestamp.
   - Rust compiler flag `-C remap-path-prefix` strips local machine paths.
4. **Publishing Hashes**: Every GitHub Release includes a signed `SHA256SUMS.txt` and `SHA256SUMS.txt.asc` enabling verification:
   ```bash
   shasum -a 256 -c SHA256SUMS.txt
   gpg --verify SHA256SUMS.txt.asc
   ```
