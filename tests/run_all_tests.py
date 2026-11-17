#!/usr/bin/env python3
"""SEALED Automated Security, Determinism & Compliance Test Suite (9 Controls).

Zero external dependencies (Python 3 stdlib unittest only).
Run: python3 tests/run_all_tests.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sealed_core.evidence import verify_evidence_zip
from sealed_core.security import (
    SealedSecurityError,
    html_escape,
    safe_json_loads,
    validate_egress_endpoint,
)

SEALED_CLI = [sys.executable, str(ROOT / "sealed.py")]
FIXTURE_DIR = ROOT / "fixture-project"
CLEAN_DIR = ROOT / "clean-project"
NON_AI_DIR = ROOT / "non-ai-project"
OFFICIAL_PACK = ROOT / "rules" / "eu-ai-act-iso42001-nist-v1.sealed-pack.json"


class SealedSecurityAndDeterminismTests(unittest.TestCase):
    def test_01_determinism_byte_identical_evidence(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            r1 = subprocess.run(
                SEALED_CLI + ["scan", str(FIXTURE_DIR), "--output-dir", d1, "--offline"],
                capture_output=True,
                text=True,
            )
            r2 = subprocess.run(
                SEALED_CLI + ["scan", str(FIXTURE_DIR), "--output-dir", d2, "--offline"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r1.returncode, 1, f"Pass 1 failed: {r1.stderr}")
            self.assertEqual(r2.returncode, 1, f"Pass 2 failed: {r2.stderr}")

            z1 = Path(d1) / "evidence.zip"
            z2 = Path(d2) / "evidence.zip"
            self.assertTrue(z1.is_file() and z2.is_file())

            h1 = hashlib.sha256(z1.read_bytes()).hexdigest()
            h2 = hashlib.sha256(z2.read_bytes()).hexdigest()
            self.assertEqual(h1, h2, f"Non-deterministic evidence.zip: {h1} != {h2}")

            # Also verify cryptographic hash chain inside the generated archive
            verified = verify_evidence_zip(z1)
            self.assertGreater(verified["blocks"], 0)

    def test_02_network_blocked_and_zero_telemetry(self):
        forbidden = ["telemetry.", "analytics.", "license.sealed", "api.sealed.security", "sentry.io", "statsig.com"]
        exts = {".py", ".cpp", ".hpp", ".java", ".js", ".html", ".json"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or path.suffix not in exts:
                continue
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith(("tests/", "target/", ".git/")):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for host in forbidden:
                self.assertNotIn(host, text, f"Forbidden telemetry host '{host}' found in {rel}")

        with tempfile.TemporaryDirectory() as out_dir:
            env = os.environ.copy()
            env["http_proxy"] = "http://127.0.0.1:9999"
            env["https_proxy"] = "http://127.0.0.1:9999"
            env["all_proxy"] = "http://127.0.0.1:9999"
            proc = subprocess.run(
                SEALED_CLI + ["scan", str(FIXTURE_DIR), "--output-dir", out_dir, "--offline"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertTrue((Path(out_dir) / "evidence.zip").is_file())
            self.assertTrue((Path(out_dir) / "report.html").is_file())

    def test_03_path_traversal_and_symlink_escape(self):
        # 1. Explicit '..' path traversal
        traversal_path = f"{FIXTURE_DIR}/../fixture-project"
        proc = subprocess.run(
            SEALED_CLI + ["scan", traversal_path],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Path traversal attack detected", proc.stderr)

        # 2. Symlink pointing outside canonical project boundary
        with tempfile.TemporaryDirectory() as proj, tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "secret.txt"
            secret.write_text("classified", encoding="utf-8")
            (Path(proj) / "escape_link.txt").symlink_to(secret)

            proc_sym = subprocess.run(
                SEALED_CLI + ["scan", proj],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_sym.returncode, 2)
            self.assertIn("Symlink escape detected", proc_sym.stderr)

    def test_04_ed25519_rule_pack_signature(self):
        pack = json.loads(OFFICIAL_PACK.read_text(encoding="utf-8"))
        pack["rules"][0]["title"] = "MALICIOUS TAMPERED RULE"

        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "tampered.sealed-pack.json"
            tampered.write_text(json.dumps(pack, indent=2), encoding="utf-8")

            # Must refuse tampered rule pack by default
            proc = subprocess.run(
                SEALED_CLI + ["scan", str(FIXTURE_DIR), "--rule-pack", str(tampered), "--output-dir", tmp],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("Rule pack signature verification failed", proc.stderr)

            # Explicit bypass flag allows load with loud warning
            proc_bypass = subprocess.run(
                SEALED_CLI
                + [
                    "scan",
                    str(FIXTURE_DIR),
                    "--rule-pack",
                    str(tampered),
                    "--output-dir",
                    tmp,
                    "--allow-unsigned-rules",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_bypass.returncode, 1)
            self.assertIn("Proceeding under --allow-unsigned-rules", proc_bypass.stderr)

    def test_05_ssrf_egress_blocking(self):
        blocked_urls = [
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1:8080/v1/chat",
            "http://10.0.1.5:8000/predict",
            "http://192.168.1.10/api",
            "gopher://evil.attacker.com/1",
            "file:///etc/passwd",
        ]
        for url in blocked_urls:
            with self.assertRaises(SealedSecurityError, msg=f"Failed to block {url}"):
                validate_egress_endpoint(url, allow_private=False)

        # Explicitly opted-in private endpoint should pass
        validate_egress_endpoint("http://10.0.1.5:8000/predict", allow_private=True)

    def test_06_zip_slip_and_parser_hardening(self):
        with tempfile.TemporaryDirectory() as tmp:
            evil_zip = Path(tmp) / "evil_zip_slip.zip"
            with zipfile.ZipFile(evil_zip, "w") as zf:
                zf.writestr("../../../../../../tmp/evil_pwned.txt", "malicious")

            with self.assertRaises(SealedSecurityError):
                verify_evidence_zip(evil_zip)

            self.assertFalse(Path("/tmp/evil_pwned.txt").exists())

        # Parser recursion depth limit check
        deep_json = "[" * 25 + "]" * 25
        with self.assertRaises(SealedSecurityError):
            safe_json_loads(deep_json, max_depth=16)

    def test_07_xss_escaping_and_strict_csp(self):
        payload = "<script>alert('XSS')</script><img src=\"x\" onerror=\"fetch('http://evil')\">"
        escaped = html_escape(payload)
        self.assertNotIn("<", escaped)
        self.assertNotIn(">", escaped)
        self.assertNotIn('"', escaped)
        self.assertIn("&lt;script&gt;", escaped)

        with tempfile.TemporaryDirectory() as out_dir:
            subprocess.run(
                SEALED_CLI + ["scan", str(FIXTURE_DIR), "--output-dir", out_dir, "--offline"],
                capture_output=True,
                text=True,
            )
            html = (Path(out_dir) / "report.html").read_text(encoding="utf-8")
            self.assertIn("Content-Security-Policy", html)
            self.assertIn("default-src 'none'", html)
            self.assertIn("script-src 'none'", html)

    def test_08_sql_parameterization_lint(self):
        bad_patterns = [
            re.compile(r'execute\s*\(\s*f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
            re.compile(r'execute\s*\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\+', re.IGNORECASE),
            re.compile(r'execute\s*\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*%\s*\(', re.IGNORECASE),
        ]
        exts = {".py", ".java", ".cpp", ".js"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or path.suffix not in exts:
                continue
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith(("tests/", "target/", ".git/")):
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                for pat in bad_patterns:
                    self.assertIsNone(pat.search(line), f"Unparameterized SQL at {rel}:{lineno}: {line.strip()}")

    def test_09_ci_exit_codes(self):
        with tempfile.TemporaryDirectory() as out_dir:
            r_clean = subprocess.run(
                SEALED_CLI + ["scan", str(CLEAN_DIR), "--output-dir", out_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r_clean.returncode, 0, f"clean-project failed: {r_clean.stderr}")

            r_non_ai = subprocess.run(
                SEALED_CLI + ["scan", str(NON_AI_DIR), "--output-dir", out_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r_non_ai.returncode, 0, f"non-ai-project failed: {r_non_ai.stderr}")
            self.assertIn("0 AI components detected", r_non_ai.stdout)

            r_fixture = subprocess.run(
                SEALED_CLI + ["scan", str(FIXTURE_DIR), "--output-dir", out_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r_fixture.returncode, 1)

            r_missing = subprocess.run(
                SEALED_CLI + ["scan", "/path/that/does/not/exist", "--output-dir", out_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r_missing.returncode, 2)


if __name__ == "__main__":
    print("============================================================")
    print(" SEALED Security, Determinism & Compliance Test Suite (v2.0)")
    print("============================================================")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SealedSecurityAndDeterminismTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
