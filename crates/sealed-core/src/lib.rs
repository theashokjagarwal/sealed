//! SEALED Core Audit Engine Library.
//! Zero network egress by default. Deterministic, local-first safety and compliance auditor.

pub mod security;
pub mod discovery;
pub mod data_scan;
pub mod attack_battery;
pub mod rule_engine;
pub mod evidence;
pub mod report;

use std::path::Path;
use thiserror::Error;

use security::{validate_path_containment, SecurityError};
use discovery::{DiscoveryEngine, SurfaceKind};
use data_scan::{StreamingPiiScanner, PiiType};
use attack_battery::AttackBattery;
use rule_engine::{RuleEngine, EvaluatedFinding, RulePackError};
use evidence::{EvidenceManager, EvidenceManifest, ChainBlock};
use report::ReportGenerator;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Security violation: {0}")]
    Security(#[from] SecurityError),
    #[error("Rule pack error: {0}")]
    RulePack(#[from] RulePackError),
    #[error("I/O error during audit: {0}")]
    Io(#[from] std::io::Error),
}

pub struct AuditReportResult {
    pub findings: Vec<EvaluatedFinding>,
    pub chain: Vec<ChainBlock>,
    pub manifest: EvidenceManifest,
    pub report_html: String,
    pub has_violations: bool,
}

pub struct AuditRunner {
    pub allow_unsigned_rules: bool,
    pub allow_private_endpoints: bool,
    pub offline_only: bool,
}

impl Default for AuditRunner {
    fn default() -> Self {
        Self {
            allow_unsigned_rules: false,
            allow_private_endpoints: false,
            offline_only: true,
        }
    }
}

impl AuditRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn run_audit(
        &self,
        project_dir: &Path,
        rule_pack_path: &Path,
    ) -> Result<AuditReportResult, AuditError> {
        let canonical_root = validate_path_containment(project_dir, project_dir)?;

        // 1. Load and cryptographically verify Rule Pack
        let rule_engine = RuleEngine::load_and_verify(rule_pack_path, self.allow_unsigned_rules)?;

        // 2. Discover AI Surfaces
        let discovery = DiscoveryEngine::default();
        let surfaces = discovery.scan_project(&canonical_root)?;

        let mut findings = Vec::new();
        let mut finding_counter = 1;

        // 3. Streaming PII Scan on datasets, configs, and prompts
        let pii_scanner = StreamingPiiScanner::default();
        for s in &surfaces {
            if s.kind == SurfaceKind::TrainingData || s.kind == SurfaceKind::SecretConfig {
                if let Ok(pii_items) = pii_scanner.scan_file(&s.absolute_path, &s.relative_path) {
                    for item in pii_items {
                        let rule_target = if item.pii_type == PiiType::ApiSecretKey {
                            "credential_exposure"
                        } else {
                            "pii_leakage"
                        };

                        if let Some(rule) = rule_engine.map_target_to_rule(rule_target) {
                            findings.push(EvaluatedFinding {
                                finding_id: format!("SEALED-F-{:04}", finding_counter),
                                rule_id: rule.id.clone(),
                                control_id: rule.control_id.clone(),
                                framework: rule.framework.clone(),
                                clause: rule.clause.clone(),
                                severity: rule.severity.clone(),
                                category: rule.category.clone(),
                                title: rule.title.clone(),
                                file_path: item.file_path,
                                line_number: item.line_number,
                                request_id: format!("req_pii_{:04}", finding_counter),
                                raw_probe: "Offline streaming regex + Luhn checksum detection".into(),
                                raw_response: format!("Identified unredacted identifier token: {}", item.masked_value),
                                evidence: format!("Context line: {}", item.context_snippet),
                                accepted_risk: false,
                                accepted_reason: None,
                            });
                            finding_counter += 1;
                        }
                    }
                }
            }
        }

        // 4. Run Deterministic Attack Battery Probes
        let attack_results = AttackBattery::run_offline_probes(&canonical_root);
        for res in attack_results {
            if res.succeeded {
                let rule_target = match res.vector {
                    attack_battery::AttackVector::DirectPromptInjection => "prompt_injection",
                    attack_battery::AttackVector::SystemPromptExtraction => "system_prompt_extraction",
                    attack_battery::AttackVector::IndirectPromptInjection => "indirect_injection",
                    attack_battery::AttackVector::JailbreakBypass => "jailbreak",
                    attack_battery::AttackVector::ToolAbuseArbitraryExecution => "tool_abuse",
                    attack_battery::AttackVector::PiiRegeneration => "pii_regeneration",
                };

                if let Some(rule) = rule_engine.map_target_to_rule(rule_target) {
                    findings.push(EvaluatedFinding {
                        finding_id: format!("SEALED-F-{:04}", finding_counter),
                        rule_id: rule.id.clone(),
                        control_id: rule.control_id.clone(),
                        framework: rule.framework.clone(),
                        clause: rule.clause.clone(),
                        severity: rule.severity.clone(),
                        category: rule.category.clone(),
                        title: rule.title.clone(),
                        file_path: res.target_file,
                        line_number: 1,
                        request_id: res.request_id,
                        raw_probe: res.probe_payload,
                        raw_response: res.model_response,
                        evidence: res.evidence_snippet,
                        accepted_risk: false,
                        accepted_reason: None,
                    });
                    finding_counter += 1;
                }
            }
        }

        // 5. Construct Cryptographic Hash Chain
        let mut evidence_mgr = EvidenceManager::default();
        let chain = evidence_mgr.build_chain(
            &findings,
            &canonical_root.display().to_string(),
            &rule_engine.pack.header.pack_id,
        );

        let final_hash = chain.last()
            .map(|b| b.block_hash.clone())
            .unwrap_or_else(|| EvidenceManager::compute_genesis_hash(
                &canonical_root.display().to_string(),
                &rule_engine.pack.header.pack_id,
            ));

        let manifest = EvidenceManifest {
            manifest_version: "1.0.0".into(),
            generator: "SEALED Auditor v1.0.0 (Rust Core)".into(),
            project_root_hash: EvidenceManager::compute_genesis_hash(&canonical_root.display().to_string(), "ROOT"),
            rule_pack_id: rule_engine.pack.header.pack_id.clone(),
            rule_pack_version: rule_engine.pack.header.version.clone(),
            total_findings: findings.len(),
            final_chain_hash: final_hash,
            attestation_statement: "This evidence bundle is deterministically compiled and cryptographically hash-chained at execution time. The underlying SHA-256 links authenticate record sequence and tamper-evident continuity.".into(),
            limitations_disclaimer: "Passing this audit certifies conformity against the active probe battery and signed rules at the tested commit. It does not certify zero risk for out-of-distribution inputs or subsequent runtime modifications.".into(),
        };

        // 6. Generate HTML Report
        let report_html = ReportGenerator::generate_html(&manifest, &findings);
        let has_violations = !findings.is_empty();

        Ok(AuditReportResult {
            findings,
            chain,
            manifest,
            report_html,
            has_violations,
        })
    }
}
