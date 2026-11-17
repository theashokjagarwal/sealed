"""Cryptographic SHA-256 hash chain, deterministic ZIP writer, and Zip-Slip safe verifier."""

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .security import SealedSecurityError

DETERMINISTIC_EPOCH = 1_735_689_600  # 2025-01-01 00:00:00 UTC
DETERMINISTIC_ZIP_TIME = (2025, 1, 1, 0, 0, 0)
MAX_ZIP_ENTRIES = 1000
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_COMPRESSION_RATIO = 100.0


def compute_genesis_hash(project_root: str, pack_id: str) -> str:
    return hashlib.sha256(f"SEALED_GENESIS_V1:{project_root}:{pack_id}".encode("utf-8")).hexdigest()


def build_hash_chain(
    findings: List[Dict[str, Any]], project_root: str, pack_id: str
) -> Tuple[str, List[Dict[str, Any]]]:
    """Build a tamper-evident SHA-256 hash chain over canonical findings."""
    genesis = compute_genesis_hash(project_root, pack_id)
    prev_hash = genesis
    chain: List[Dict[str, Any]] = []

    for idx, finding in enumerate(findings):
        payload_json = json.dumps(finding, separators=(",", ":"), ensure_ascii=False)
        payload_sha = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        block_input = f"{prev_hash}:{finding['finding_id']}:{payload_sha}".encode("utf-8")
        block_hash = hashlib.sha256(block_input).hexdigest()

        chain.append(
            {
                "index": idx,
                "timestamp_epoch": DETERMINISTIC_EPOCH,
                "prev_hash": prev_hash,
                "block_hash": block_hash,
                "finding_id": finding["finding_id"],
                "finding_summary": f"{finding['control_id']}: {finding['title']} ({finding['file_path']})",
                "payload_sha256": payload_sha,
            }
        )
        prev_hash = block_hash

    return genesis, chain


def export_deterministic_zip(
    output_zip_path: Path,
    manifest: Dict[str, Any],
    chain: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    report_html: str,
) -> None:
    """Write a byte-deterministic evidence.zip archive with fixed timestamps and sorted entries."""
    entries = sorted(
        [
            ("chain.json", json.dumps(chain, indent=2, ensure_ascii=False).encode("utf-8")),
            ("findings.json", json.dumps(findings, indent=2, ensure_ascii=False).encode("utf-8")),
            ("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")),
            ("report.html", report_html.encode("utf-8")),
        ],
        key=lambda item: item[0],
    )

    with zipfile.ZipFile(output_zip_path, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(filename=name, date_time=DETERMINISTIC_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # UNIX
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data)


def verify_evidence_zip(zip_path: Path) -> Dict[str, Any]:
    """Verify archive safety (Zip-Slip / decompression bomb) and cryptographic SHA-256 chain."""
    if not zip_path.is_file():
        raise SealedSecurityError(f"Evidence archive not found: '{zip_path}'")

    try:
        zf = zipfile.ZipFile(zip_path, "r")
    except zipfile.BadZipFile as exc:
        raise SealedSecurityError(f"Corrupt ZIP archive: {exc}") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise SealedSecurityError(
                f"Zip entry count ({len(infos)}) exceeded limit of {MAX_ZIP_ENTRIES}"
            )

        total_uncompressed = 0
        extracted: Dict[str, bytes] = {}

        for info in infos:
            name = info.filename
            # Strict Zip-Slip rejection
            if name.startswith("/") or name.startswith("\\") or re.match(r"^[A-Za-z]:", name):
                raise SealedSecurityError(f"Zip-Slip detected: absolute path entry '{name}'")
            if ".." in re.split(r"[\\/]", name):
                raise SealedSecurityError(f"Zip-Slip detected: parent traversal entry '{name}'")

            # Decompression bomb checks
            if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_COMPRESSION_RATIO:
                raise SealedSecurityError(
                    f"Decompression bomb detected on '{name}': ratio exceeded {MAX_COMPRESSION_RATIO}:1"
                )

            data = zf.read(info)
            total_uncompressed += len(data)
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise SealedSecurityError(
                    f"Decompression bomb detected: total size exceeded {MAX_UNCOMPRESSED_BYTES} bytes"
                )
            extracted[name] = data

    if "chain.json" not in extracted or "manifest.json" not in extracted:
        raise SealedSecurityError("Evidence archive missing required 'chain.json' or 'manifest.json'")

    chain = json.loads(extracted["chain.json"].decode("utf-8"))
    manifest = json.loads(extracted["manifest.json"].decode("utf-8"))

    # Verify cryptographic SHA-256 link continuity
    for idx, block in enumerate(chain):
        if idx > 0 and block["prev_hash"] != chain[idx - 1]["block_hash"]:
            raise SealedSecurityError(f"Hash chain link broken at block {idx}")

        recomputed = hashlib.sha256(
            f"{block['prev_hash']}:{block['finding_id']}:{block['payload_sha256']}".encode("utf-8")
        ).hexdigest()
        if recomputed != block["block_hash"]:
            raise SealedSecurityError(
                f"Hash tamper detected at block {idx}: expected {recomputed}, found {block['block_hash']}"
            )

    if chain and chain[-1]["block_hash"] != manifest.get("final_chain_hash"):
        raise SealedSecurityError("Final chain hash does not match manifest.json")

    return {"blocks": len(chain), "final_chain_hash": manifest.get("final_chain_hash"), "manifest": manifest}
