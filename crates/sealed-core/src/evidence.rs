//! Cryptographic Evidence Hash Chain and Deterministic ZIP Packager.
//! Enforces zero nondeterminism (normalized timestamps, sorted directory entries).

use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::rule_engine::EvaluatedFinding;
use crate::security::SecurityError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBlock {
    pub index: usize,
    pub timestamp_epoch: u64,
    pub prev_hash: String,
    pub block_hash: String,
    pub finding_id: String,
    pub finding_summary: String,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    pub manifest_version: String,
    pub generator: String,
    pub project_root_hash: String,
    pub rule_pack_id: String,
    pub rule_pack_version: String,
    pub total_findings: usize,
    pub final_chain_hash: String,
    pub attestation_statement: String,
    pub limitations_disclaimer: String,
}

pub struct EvidenceManager {
    chain: Vec<ChainBlock>,
}

impl Default for EvidenceManager {
    fn default() -> Self {
        Self { chain: Vec::new() }
    }
}

impl EvidenceManager {
    pub const GENESIS_HASH: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";
    pub const DETERMINISTIC_EPOCH: u64 = 1735689600; // 2025-01-01 00:00:00 UTC

    pub fn build_chain(&mut self, findings: &[EvaluatedFinding], project_path: &str, pack_id: &str) -> Vec<ChainBlock> {
        self.chain.clear();
        let mut prev = Self::compute_genesis_hash(project_path, pack_id);

        for (idx, f) in findings.iter().enumerate() {
            let payload_json = serde_json::to_string(f).unwrap_or_default();
            let payload_sha = format!("{:x}", Sha256::digest(payload_json.as_bytes()));

            let mut hasher = Sha256::new();
            hasher.update(prev.as_bytes());
            hasher.update(b":");
            hasher.update(f.finding_id.as_bytes());
            hasher.update(b":");
            hasher.update(payload_sha.as_bytes());
            let block_hash = format!("{:x}", hasher.finalize());

            let block = ChainBlock {
                index: idx,
                timestamp_epoch: Self::DETERMINISTIC_EPOCH,
                prev_hash: prev.clone(),
                block_hash: block_hash.clone(),
                finding_id: f.finding_id.clone(),
                finding_summary: format!("{}: {} ({})", f.control_id, f.title, f.file_path),
                payload_sha256: payload_sha,
            };

            prev = block_hash;
            self.chain.push(block);
        }

        self.chain.clone()
    }

    pub fn compute_genesis_hash(project_path: &str, pack_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"SEALED_GENESIS_V1:");
        hasher.update(project_path.as_bytes());
        hasher.update(b":");
        hasher.update(pack_id.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verifies the cryptographic continuity of an existing hash chain.
    pub fn verify_chain(chain: &[ChainBlock], genesis_hash: &str) -> bool {
        let mut expected_prev = genesis_hash.to_string();
        for block in chain {
            if block.prev_hash != expected_prev {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(block.prev_hash.as_bytes());
            hasher.update(b":");
            hasher.update(block.finding_id.as_bytes());
            hasher.update(b":");
            hasher.update(block.payload_sha256.as_bytes());
            let recomputed = format!("{:x}", hasher.finalize());
            if block.block_hash != recomputed {
                return false;
            }
            expected_prev = block.block_hash.clone();
        }
        true
    }

    /// Exports evidence to a strictly deterministic, zip-slip protected ZIP file.
    pub fn export_deterministic_zip(
        output_zip_path: &Path,
        manifest: &EvidenceManifest,
        chain: &[ChainBlock],
        findings: &[EvaluatedFinding],
        report_html_bytes: &[u8],
    ) -> Result<(), SecurityError> {
        let file = File::create(output_zip_path)
            .map_err(|e| SecurityError::PathTraversal(format!("Failed to create zip file: {}", e)))?;
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644)
            .last_modified_time(zip::DateTime::from_date_and_time(2025, 1, 1, 0, 0, 0).unwrap());

        // File 1: manifest.json (Sorted entries)
        zip.start_file("manifest.json", options)
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
        let manifest_bytes = serde_json::to_string_pretty(manifest).unwrap_or_default();
        zip.write_all(manifest_bytes.as_bytes())
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

        // File 2: chain.json
        zip.start_file("chain.json", options)
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
        let chain_bytes = serde_json::to_string_pretty(chain).unwrap_or_default();
        zip.write_all(chain_bytes.as_bytes())
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

        // File 3: findings.json
        zip.start_file("findings.json", options)
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
        let findings_bytes = serde_json::to_string_pretty(findings).unwrap_or_default();
        zip.write_all(findings_bytes.as_bytes())
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

        // File 4: report.html
        zip.start_file("report.html", options)
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
        zip.write_all(report_html_bytes)
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

        zip.finish()
            .map_err(|e| SecurityError::PathTraversal(format!("Zip finalize failed: {}", e)))?;

        Ok(())
    }

    /// Zip-Slip defense for unpacking evidence packs.
    pub fn safely_extract_archive(zip_path: &Path, destination_dir: &Path) -> Result<(), SecurityError> {
        let file = File::open(zip_path)
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

        let canonical_dest = destination_dir.canonicalize()
            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

        let mut total_unpacked_bytes: usize = 0;
        const MAX_TOTAL_BYTES: usize = 100 * 1024 * 1024; // 100 MB cap
        const MAX_ENTRIES: usize = 1000;

        if archive.len() > MAX_ENTRIES {
            return Err(SecurityError::ParserLimitExceeded("Zip entry count exceeded cap".into()));
        }

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

            let enclosed_name = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => return Err(SecurityError::PathTraversal("ZipSlip detected: illegal entry name".into())),
            };

            let outpath = canonical_dest.join(enclosed_name);

            if file.name().ends_with('/') {
                std::fs::create_dir_all(&outpath)
                    .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        std::fs::create_dir_all(p)
                            .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
                    }
                }
                let mut outfile = File::create(&outpath)
                    .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

                let mut buffer = [0u8; 8192];
                loop {
                    let n = file.read(&mut buffer)
                        .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
                    if n == 0 { break; }
                    total_unpacked_bytes += n;
                    if total_unpacked_bytes > MAX_TOTAL_BYTES {
                        return Err(SecurityError::DecompressionBomb(total_unpacked_bytes));
                    }
                    outfile.write_all(&buffer[..n])
                        .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;
                }
            }
        }

        Ok(())
    }
}
