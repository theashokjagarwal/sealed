"""Main SEALED 5-stage compliance and safety audit orchestrator."""

import hashlib
from pathlib import Path
from typing import Any, Dict, List

from . import __version__
from .attack_battery import run_attack_battery
from .data_scan import scan_file_streaming
from .discovery import discover_project
from .evidence import build_hash_chain, export_deterministic_zip
from .report import generate_report_html
from .rule_engine import RuleEngine


def run_audit(
    project_path: Path,
    rule_pack_path: Path,
    output_dir: Path,
    allow_unsigned: bool = False,
) -> Dict[str, Any]:
    """Execute the complete offline audit pipeline and write report.html + evidence.zip."""
    # Stage 1: Verify rule pack Ed25519 signature
    rule_engine = RuleEngine.load_and_verify(rule_pack_path, allow_unsigned=allow_unsigned)

    # Stage 2: Deterministic surface discovery + symlink boundary validation
    canon_root, discovered_files, ai_surface_count = discover_project(project_path)

    findings: List[Dict[str, Any]] = []
    finding_idx = 1

    # Stage 3a: Streaming PII & secret scan
    for df in discovered_files:
        pii_hits = scan_file_streaming(df.absolute_path, df.relative_path)
        for hit in pii_hits:
            rule = rule_engine.map_target(hit.detection_target)
            if not rule:
                continue
            findings.append(
                {
                    "finding_id": f"SEALED-F-{finding_idx:04d}",
                    "rule_id": rule["id"],
                    "control_id": rule["control_id"],
                    "framework": rule["framework"],
                    "clause": rule["clause"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "title": rule["title"],
                    "file_path": hit.file_path,
                    "line_number": hit.line_number,
                    "request_id": f"req_pii_{finding_idx:04d}",
                    "raw_probe": "Offline streaming regex + Luhn Mod-10 checksum detector",
                    "raw_response": f"Identified unmasked token: {hit.masked_value}",
                    "evidence": f"Context line: {hit.snippet}",
                    "accepted_risk": False,
                    "accepted_reason": None,
                }
            )
            finding_idx += 1

    # Stage 3b: Deterministic adversarial attack battery
    attack_hits = run_attack_battery(discovered_files)
    for hit in attack_hits:
        rule = rule_engine.map_target(hit.detection_target)
        if not rule:
            continue
        findings.append(
            {
                "finding_id": f"SEALED-F-{finding_idx:04d}",
                "rule_id": rule["id"],
                "control_id": rule["control_id"],
                "framework": rule["framework"],
                "clause": rule["clause"],
                "severity": rule["severity"],
                "category": rule["category"],
                "title": rule["title"],
                "file_path": hit.file_path,
                "line_number": hit.line_number,
                "request_id": f"req_atk_{finding_idx:04d}",
                "raw_probe": hit.raw_probe,
                "raw_response": hit.raw_response,
                "evidence": hit.evidence,
                "accepted_risk": False,
                "accepted_reason": None,
            }
        )
        finding_idx += 1

    findings.sort(key=lambda item: item["finding_id"])

    # Stage 4: Build SHA-256 cryptographic hash chain
    genesis_hash, chain = build_hash_chain(
        findings=findings,
        project_root=str(canon_root),
        pack_id=rule_engine.header["pack_id"],
    )
    final_hash = chain[-1]["block_hash"] if chain else genesis_hash

    manifest = {
        "manifest_version": "1.0.0",
        "generator": f"SEALED Auditor v{__version__} (Python Core)",
        "project_root_hash": hashlib.sha256(str(canon_root).encode("utf-8")).hexdigest(),
        "rule_pack_id": rule_engine.header["pack_id"],
        "rule_pack_version": rule_engine.header["version"],
        "ai_surfaces_discovered": ai_surface_count,
        "total_findings": len(findings),
        "final_chain_hash": final_hash,
        "attestation_statement": (
            "This evidence bundle is deterministically compiled and cryptographically hash-chained "
            "at execution time. The underlying SHA-256 links authenticate record sequence and "
            "tamper-evident continuity."
        ),
        "limitations_disclaimer": (
            "Passing this audit certifies conformity against the active probe battery and signed "
            "rules at the tested commit. It does not certify zero risk for out-of-distribution "
            "inputs or subsequent runtime modifications."
        ),
    }

    # Stage 5: Export standalone report.html and byte-deterministic evidence.zip
    output_dir.mkdir(parents=True, exist_ok=True)
    report_html = generate_report_html(manifest, findings)
    report_path = output_dir / "report.html"
    report_path.write_text(report_html, encoding="utf-8")

    zip_path = output_dir / "evidence.zip"
    export_deterministic_zip(zip_path, manifest, chain, findings, report_html)

    return {
        "ai_surfaces": ai_surface_count,
        "files_scanned": len(discovered_files),
        "findings": findings,
        "chain": chain,
        "manifest": manifest,
        "report_path": str(report_path),
        "zip_path": str(zip_path),
        "has_violations": bool(findings),
    }
