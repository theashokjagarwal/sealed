//! Rule Engine and Cryptographic Rule Pack Verification.
//! Supports EU AI Act, ISO/IEC 42001, NIST AI RMF, GDPR/DPDP.

use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

#[derive(Error, Debug)]
pub enum RulePackError {
    #[error("I/O error reading rule pack: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Rule pack is missing signature")]
    MissingSignature,
    #[error("Cryptographic signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("Rule pack exceeds allowable size limits")]
    SizeLimitExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHeader {
    pub pack_id: String,
    pub version: String,
    pub issuer: String,
    pub published_at: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub control_id: String,
    pub framework: String,
    pub clause: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub detection_target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRulePack {
    pub header: RuleHeader,
    pub rules: Vec<RuleDefinition>,
    pub payload_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatedFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub control_id: String,
    pub framework: String,
    pub clause: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub file_path: String,
    pub line_number: usize,
    pub request_id: String,
    pub raw_probe: String,
    pub raw_response: String,
    pub evidence: String,
    pub accepted_risk: bool,
    pub accepted_reason: Option<String>,
}

pub struct RuleEngine {
    pub pack: SignedRulePack,
}

impl RuleEngine {
    pub fn load_and_verify(path: &Path, allow_unsigned: bool) -> Result<Self, RulePackError> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > 5 * 1024 * 1024 {
            return Err(RulePackError::SizeLimitExceeded);
        }

        let content = fs::read_to_string(path)?;
        let pack: SignedRulePack = serde_json::from_str(&content)?;

        if !allow_unsigned {
            Self::verify_signature(&pack)?;
        }

        Ok(Self { pack })
    }

    pub fn verify_signature(pack: &SignedRulePack) -> Result<(), RulePackError> {
        let pub_bytes = hex::decode(&pack.header.public_key)
            .map_err(|e| RulePackError::InvalidSignature(format!("Hex decode public key error: {}", e)))?;
        let sig_bytes = hex::decode(&pack.signature)
            .map_err(|e| RulePackError::InvalidSignature(format!("Hex decode signature error: {}", e)))?;

        let verifying_key = VerifyingKey::from_bytes(
            pub_bytes.as_slice().try_into()
                .map_err(|_| RulePackError::InvalidSignature("Invalid public key length".into()))?
        ).map_err(|e| RulePackError::InvalidSignature(e.to_string()))?;

        let signature = Signature::from_bytes(
            sig_bytes.as_slice().try_into()
                .map_err(|_| RulePackError::InvalidSignature("Invalid signature length".into()))?
        );

        let signed_payload = serde_json::json!({
            "header": pack.header,
            "rules": pack.rules,
        }).to_string();

        verifying_key.verify(signed_payload.as_bytes(), &signature)
            .map_err(|e| RulePackError::InvalidSignature(format!("Ed25519 signature mismatch: {}", e)))?;

        Ok(())
    }

    pub fn map_target_to_rule(&self, target: &str) -> Option<&RuleDefinition> {
        self.pack.rules.iter().find(|r| r.detection_target == target)
    }
}

// Minimal hex decoder helper without external crate requirement
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if s.len() % 2 != 0 {
            return Err("Odd length hex string");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex character"))
            .collect()
    }
}
