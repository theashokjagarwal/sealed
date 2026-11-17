#!/usr/bin/env python3
"""SEALED CLI — Local-First AI Compliance & Safety Auditor.

Commands:
  python3 sealed.py scan <path>     Run offline compliance & safety audit
  python3 sealed.py verify <zip>    Verify SHA-256 hash chain & Zip-Slip safety
  python3 sealed.py serve           Launch the local Instrument Panel Web UI
"""

import argparse
import functools
import http.server
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_RULE_PACK = ROOT_DIR / "rules" / "eu-ai-act-iso42001-nist-v1.sealed-pack.json"

from sealed_core import __version__
from sealed_core.auditor import run_audit
from sealed_core.evidence import verify_evidence_zip
from sealed_core.security import SealedRulePackError, SealedSecurityError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sealed",
        description="SEALED — Local-First AI Compliance & Safety Auditor (Zero Telemetry)",
    )
    parser.add_argument("--version", action="version", version=f"SEALED v{__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Audit a project directory offline")
    scan_p.add_argument("project_path", type=Path, help="Target project folder to scan")
    scan_p.add_argument(
        "-r", "--rule-pack", type=Path, default=DEFAULT_RULE_PACK, help="Signed rule pack path"
    )
    scan_p.add_argument(
        "-o", "--output-dir", type=Path, default=Path("."), help="Output directory for artifacts"
    )
    scan_p.add_argument(
        "--offline", action="store_true", default=True, help="Enforce offline air-gapped mode"
    )
    scan_p.add_argument(
        "--allow-unsigned-rules",
        action="store_true",
        default=False,
        help="UNSAFE: allow unsigned or untrusted rule packs",
    )

    verify_p = sub.add_parser("verify", help="Verify evidence.zip hash chain and archive safety")
    verify_p.add_argument("zip_path", type=Path, help="Path to evidence.zip")

    serve_p = sub.add_parser("serve", help="Launch local air-gapped Instrument Panel UI")
    serve_p.add_argument("--port", type=int, default=8787, help="Localhost port (default: 8787)")

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        print("============================================================")
        print(f" SEALED — Local-First AI Compliance & Safety Auditor v{__version__}")
        print(f" Target:    {args.project_path}")
        print(f" Rule Pack: {args.rule_pack}")
        print(" Mode:      OFFLINE | Network Egress: DENIED")
        print("============================================================")

        try:
            result = run_audit(
                project_path=args.project_path,
                rule_pack_path=args.rule_pack,
                output_dir=args.output_dir,
                allow_unsigned=args.allow_unsigned_rules,
            )
        except SealedSecurityError as exc:
            print(f"[FATAL SECURITY VIOLATION] {exc}", file=sys.stderr)
            return 2
        except SealedRulePackError as exc:
            print(f"[FATAL RULE PACK ERROR] {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"[FATAL AUDIT ERROR] {exc}", file=sys.stderr)
            return 2

        if result["ai_surfaces"] == 0:
            print(" [i] Surface Discovery: 0 AI components detected (traditional deterministic software).")
        else:
            print(
                f" [i] Surface Discovery: {result['ai_surfaces']} AI surfaces cataloged "
                f"across {result['files_scanned']} text files."
            )

        print(f" [+] Written audit report: {result['report_path']}")
        print(f" [+] Written deterministic evidence pack: {result['zip_path']}")
        print(f"     Hash Chain Blocks: {len(result['chain'])}")
        print(f"     Final Chain Hash:   {result['manifest']['final_chain_hash']}")
        print("------------------------------------------------------------")

        if result["has_violations"]:
            print(
                f" [!] AUDIT FAILED: Discovered {len(result['findings'])} compliance & safety violations.",
                file=sys.stderr,
            )
            for f in result["findings"]:
                print(
                    f"     * [{f['severity']}] {f['control_id']} - {f['title']} ({f['file_path']}:{f['line_number']})",
                    file=sys.stderr,
                )
            return 1

        print(" [OK] AUDIT PASSED: Zero compliance or safety violations discovered.")
        return 0

    if args.command == "verify":
        print(f"Verifying evidence pack: {args.zip_path}")
        try:
            info = verify_evidence_zip(args.zip_path)
            print(
                f" [OK] Hash chain verified: {info['blocks']} blocks with intact cryptographic continuity."
            )
            print(f"      Final Chain Hash: {info['final_chain_hash']}")
            return 0
        except SealedSecurityError as exc:
            print(f"[FAIL] Verification failed: {exc}", file=sys.stderr)
            return 2

    if args.command == "serve":
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT_DIR))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler)
        print(f"SEALED Instrument Panel running locally at http://127.0.0.1:{args.port}/ui/index.html")
        print("Bound strictly to 127.0.0.1 (zero external network egress). Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
