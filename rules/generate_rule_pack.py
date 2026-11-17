#!/usr/bin/env python3
"""Generate and Ed25519-sign the official SEALED compliance rule pack."""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sealed_core import ed25519


def main() -> None:
    master_seed = bytes.fromhex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )
    pub_bytes = ed25519.public_key(master_seed)
    pub_hex = pub_bytes.hex()

    rules_dir = Path(__file__).resolve().parent
    (rules_dir / "official_root.pub").write_text(f"{pub_hex}\n", encoding="utf-8")

    rules = [
        {
            "id": "SEALED-RULE-001",
            "control_id": "EU-AI-ACT-ART-15",
            "framework": "EU AI Act",
            "clause": "Article 15(1) & (4): Robustness, Cybersecurity and Resistance to Adversarial Exploitation",
            "severity": "CRITICAL",
            "category": "Adversarial Robustness",
            "title": "Direct Prompt Injection & System Override Defense",
            "description": "High-risk AI systems must be resilient against third-party attempts to alter their output, bypass guardrails, or exploit vulnerabilities through prompt injection.",
            "detection_target": "prompt_injection",
        },
        {
            "id": "SEALED-RULE-002",
            "control_id": "EU-AI-ACT-ART-15-EXT",
            "framework": "EU AI Act",
            "clause": "Article 15(1): Resilience against System Prompt Extraction",
            "severity": "HIGH",
            "category": "Confidentiality & Extraction",
            "title": "System Prompt & Intellectual Property Exfiltration",
            "description": "AI models must prevent unauthorized disclosure of underlying system prompts, proprietary guardrails, and operational context to untrusted users.",
            "detection_target": "system_prompt_extraction",
        },
        {
            "id": "SEALED-RULE-003",
            "control_id": "ISO-42001-A.8.4",
            "framework": "ISO/IEC 42001",
            "clause": "Control A.8.4: Robustness and Resilience of AI Systems",
            "severity": "HIGH",
            "category": "Adversarial Robustness",
            "title": "Indirect Prompt Injection in Retrieved Context (RAG)",
            "description": "Systems utilizing retrieval-augmented generation (RAG) must sanitize or neutralize untrusted data retrieved from external documents to prevent secondary injection payloads.",
            "detection_target": "indirect_injection",
        },
        {
            "id": "SEALED-RULE-004",
            "control_id": "NIST-AI-RMF-MEASURE-2.7",
            "framework": "NIST AI RMF",
            "clause": "Measure 2.7: AI System Security and Resilience against Attacks",
            "severity": "CRITICAL",
            "category": "Safety & Jailbreak",
            "title": "Jailbreak & Safety Boundary Bypass",
            "description": "AI systems shall be evaluated against roleplay-based and hypothetical jailbreak attacks that coerce the model into generating harmful, dangerous, or illegal content.",
            "detection_target": "jailbreak",
        },
        {
            "id": "SEALED-RULE-005",
            "control_id": "GDPR-ART-5-1-C",
            "framework": "GDPR / DPDP",
            "clause": "GDPR Art. 5(1)(c) & DPDP Sec. 8: Data Minimization & PII Leakage",
            "severity": "HIGH",
            "category": "Data Privacy",
            "title": "Unmasked Personal Identifiable Information (PII) in Local Datasets",
            "description": "Datasets, prompts, and log stores must not contain plaintext personal identifiers (credit cards, SSNs, personal emails, phone numbers) without explicit tokenization or masking.",
            "detection_target": "pii_leakage",
        },
        {
            "id": "SEALED-RULE-006",
            "control_id": "ISO-42001-A.9.2",
            "framework": "ISO/IEC 42001",
            "clause": "Control A.9.2: Access Control and Operational Boundaries",
            "severity": "CRITICAL",
            "category": "Agent Safety & Tool Abuse",
            "title": "Unrestricted Arbitrary Code Execution / Tool Abuse",
            "description": "AI agent tool definitions must not expose arbitrary shell commands, raw code eval, or un-sandboxed system access to autonomous model invocation.",
            "detection_target": "tool_abuse",
        },
        {
            "id": "SEALED-RULE-007",
            "control_id": "NIST-AI-RMF-MANAGE-2.4",
            "framework": "NIST AI RMF",
            "clause": "Manage 2.4: Privacy Risk Mitigation & PII Regeneration",
            "severity": "MEDIUM",
            "category": "Data Privacy",
            "title": "Model PII Regeneration via Targeted Probes",
            "description": "Models must not memorize or regurgitate training data containing personal confidential records when queried with targeted prefixes.",
            "detection_target": "pii_regeneration",
        },
        {
            "id": "SEALED-RULE-008",
            "control_id": "GDPR-ART-32",
            "framework": "GDPR / DPDP",
            "clause": "GDPR Art. 32: Security of Processing — Credential Exposure",
            "severity": "CRITICAL",
            "category": "Credential Security",
            "title": "Exposed API Keys and Secrets in Source or Environment Configs",
            "description": "API keys, bearer tokens, and private connection credentials must never reside in source control, prompt templates, or unencrypted local files.",
            "detection_target": "credential_exposure",
        },
    ]

    header = {
        "pack_id": "sealed-official-eu-nist-iso",
        "version": "1.0.0",
        "issuer": "SEALED Official Core Governance",
        "published_at": "2026-01-01T00:00:00Z",
        "public_key": pub_hex,
    }

    payload_for_signing = json.dumps(
        {"header": header, "rules": rules}, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    canonical_hash = hashlib.sha256(payload_for_signing).hexdigest()
    sig_hex = ed25519.sign(master_seed, payload_for_signing).hex()

    pack = {
        "header": header,
        "rules": rules,
        "payload_hash": canonical_hash,
        "signature": sig_hex,
    }

    out_path = rules_dir / "eu-ai-act-iso42001-nist-v1.sealed-pack.json"
    out_path.write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Rule pack generated and signed: {out_path}")
    print(f"Public Key: {pub_hex}")
    print(f"Signature:  {sig_hex[:32]}...")


if __name__ == "__main__":
    main()
