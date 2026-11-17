# frozen_string_literal: true

require 'json'
require 'digest'
require_relative 'ed25519'

# 1. Deterministic Master Key for SEALED Official Release Authority
# (In production, root key is stored in hardware security module / HSM)
master_seed = ['0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'].pack('H*')
private_key = master_seed
public_key = Ed25519.public_key(private_key)

pub_hex = public_key.unpack1('H*')
File.write(File.expand_path('official_root.pub', __dir__), "#{pub_hex}\n")

rules = [
  {
    'id' => 'SEALED-RULE-001',
    'control_id' => 'EU-AI-ACT-ART-15',
    'framework' => 'EU AI Act',
    'clause' => 'Article 15(1) & (4): Robustness, Cybersecurity and Resistance to Adversarial Exploitation',
    'severity' => 'CRITICAL',
    'category' => 'Adversarial Robustness',
    'title' => 'Direct Prompt Injection & System Override Defense',
    'description' => 'High-risk AI systems must be resilient against third-party attempts to alter their output, bypass guardrails, or exploit vulnerabilities through prompt injection.',
    'detection_target' => 'prompt_injection'
  },
  {
    'id' => 'SEALED-RULE-002',
    'control_id' => 'EU-AI-ACT-ART-15-EXT',
    'framework' => 'EU AI Act',
    'clause' => 'Article 15(1): Resilience against System Prompt Extraction',
    'severity' => 'HIGH',
    'category' => 'Confidentiality & Extraction',
    'title' => 'System Prompt & Intellectual Property Exfiltration',
    'description' => 'AI models must prevent unauthorized disclosure of underlying system prompts, proprietary guardrails, and operational context to untrusted users.',
    'detection_target' => 'system_prompt_extraction'
  },
  {
    'id' => 'SEALED-RULE-003',
    'control_id' => 'ISO-42001-A.8.4',
    'framework' => 'ISO/IEC 42001',
    'clause' => 'Control A.8.4: Robustness and Resilience of AI Systems',
    'severity' => 'HIGH',
    'category' => 'Adversarial Robustness',
    'title' => 'Indirect Prompt Injection in Retrieved Context (RAG)',
    'description' => 'Systems utilizing retrieval-augmented generation (RAG) must sanitize or neutralize untrusted data retrieved from external documents to prevent secondary injection payloads.',
    'detection_target' => 'indirect_injection'
  },
  {
    'id' => 'SEALED-RULE-004',
    'control_id' => 'NIST-AI-RMF-MEASURE-2.7',
    'framework' => 'NIST AI RMF',
    'clause' => 'Measure 2.7: AI System Security and Resilience against Attacks',
    'severity' => 'CRITICAL',
    'category' => 'Safety & Jailbreak',
    'title' => 'Jailbreak & Safety Boundary Bypass',
    'description' => 'AI systems shall be evaluated against roleplay-based and hypothetical jailbreak attacks that coerce the model into generating harmful, dangerous, or illegal content.',
    'detection_target' => 'jailbreak'
  },
  {
    'id' => 'SEALED-RULE-005',
    'control_id' => 'GDPR-ART-5-1-C',
    'framework' => 'GDPR / DPDP',
    'clause' => 'GDPR Art. 5(1)(c) & DPDP Sec. 8: Data Minimization & PII Leakage',
    'severity' => 'HIGH',
    'category' => 'Data Privacy',
    'title' => 'Unmasked Personal Identifiable Information (PII) in Local Datasets',
    'description' => 'Datasets, prompts, and log stores must not contain plaintext personal identifiers (credit cards, SSNs, personal emails, phone numbers) without explicit tokenization or masking.',
    'detection_target' => 'pii_leakage'
  },
  {
    'id' => 'SEALED-RULE-006',
    'control_id' => 'ISO-42001-A.9.2',
    'framework' => 'ISO/IEC 42001',
    'clause' => 'Control A.9.2: Access Control and Operational Boundaries',
    'severity' => 'CRITICAL',
    'category' => 'Agent Safety & Tool Abuse',
    'title' => 'Unrestricted Arbitrary Code Execution / Tool Abuse',
    'description' => 'AI agent tool definitions must not expose arbitrary shell commands, raw code eval, or un-sandboxed system access to autonomous model invocation.',
    'detection_target' => 'tool_abuse'
  },
  {
    'id' => 'SEALED-RULE-007',
    'control_id' => 'NIST-AI-RMF-MANAGE-2.4',
    'framework' => 'NIST AI RMF',
    'clause' => 'Manage 2.4: Privacy Risk Mitigation & PII Regeneration',
    'severity' => 'MEDIUM',
    'category' => 'Data Privacy',
    'title' => 'Model PII Regeneration via Targeted Probes',
    'description' => 'Models must not memorize or regurgitate training data containing personal confidential records when queried with targeted prefixes.',
    'detection_target' => 'pii_regeneration'
  },
  {
    'id' => 'SEALED-RULE-008',
    'control_id' => 'GDPR-ART-32',
    'framework' => 'GDPR / DPDP',
    'clause' => 'GDPR Art. 32: Security of Processing — Credential Exposure',
    'severity' => 'CRITICAL',
    'category' => 'Credential Security',
    'title' => 'Exposed API Keys and Secrets in Source or Environment Configs',
    'description' => 'API keys, bearer tokens, and private connection credentials must never reside in source control, prompt templates, or unencrypted local files.',
    'detection_target' => 'credential_exposure'
  }
]

header = {
  'pack_id' => 'sealed-official-eu-nist-iso',
  'version' => '1.0.0',
  'issuer' => 'SEALED Official Core Governance',
  'published_at' => '2026-01-01T00:00:00Z',
  'public_key' => pub_hex
}

payload_for_signing = JSON.generate({ 'header' => header, 'rules' => rules })
canonical_hash = Digest::SHA256.hexdigest(payload_for_signing)
signature_bytes = Ed25519.sign(private_key, payload_for_signing)
sig_hex = signature_bytes.unpack1('H*')

pack = {
  'header' => header,
  'rules' => rules,
  'payload_hash' => canonical_hash,
  'signature' => sig_hex
}

output_path = File.expand_path('eu-ai-act-iso42001-nist-v1.sealed-pack.json', __dir__)
File.write(output_path, JSON.pretty_generate(pack) + "\n")
puts "Rule pack generated and signed successfully: #{output_path}"
puts "Public Key: #{pub_hex}"
puts "Signature:  #{sig_hex[0..32]}..."
