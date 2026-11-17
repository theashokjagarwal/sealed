//! Streaming offline personal data (PII) scanner.
//! Never loads full multi-gigabyte files into RAM; reads in chunked sliding windows.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use serde::{Deserialize, Serialize};
use regex::Regex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("I/O error during scan: {0}")]
    Io(#[from] std::io::Error),
    #[error("File exceeds maximum inspection budget")]
    SizeBudgetExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PiiType {
    PaymentCard,
    SocialSecurityNumber,
    EmailAddress,
    PhoneNumber,
    ApiSecretKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFinding {
    pub pii_type: PiiType,
    pub file_path: String,
    pub line_number: usize,
    pub masked_value: String,
    pub context_snippet: String,
}

pub struct StreamingPiiScanner {
    card_regex: Regex,
    ssn_regex: Regex,
    email_regex: Regex,
    phone_regex: Regex,
    key_regex: Regex,
}

impl Default for StreamingPiiScanner {
    fn default() -> Self {
        Self {
            card_regex: Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap(),
            ssn_regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            email_regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            phone_regex: Regex::new(r"(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b").unwrap(),
            key_regex: Regex::new(r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|postgres://[^:]+:[^@]+@)").unwrap(),
        }
    }
}

impl StreamingPiiScanner {
    pub fn scan_file(&self, path: &Path, rel_path: &str) -> Result<Vec<PiiFinding>, ScanError> {
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(64 * 1024, file);
        let mut findings = Vec::new();

        for (line_idx, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            let line_num = line_idx + 1;

            // 1. Check Credit Cards with Luhn Verification
            for mat in self.card_regex.find_iter(&line) {
                let candidate: String = mat.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                if candidate.len() >= 13 && candidate.len() <= 19 && Self::luhn_verify(&candidate) {
                    let masked = format!("{}****{}", &candidate[..4], &candidate[candidate.len()-4..]);
                    findings.push(PiiFinding {
                        pii_type: PiiType::PaymentCard,
                        file_path: rel_path.to_string(),
                        line_number: line_num,
                        masked_value: masked,
                        context_snippet: line.trim().to_string(),
                    });
                }
            }

            // 2. Check SSN
            for mat in self.ssn_regex.find_iter(&line) {
                findings.push(PiiFinding {
                    pii_type: PiiType::SocialSecurityNumber,
                    file_path: rel_path.to_string(),
                    line_number: line_num,
                    masked_value: "***-**-".to_string() + &mat.as_str()[7..],
                    context_snippet: line.trim().to_string(),
                });
            }

            // 3. Check Emails
            for mat in self.email_regex.find_iter(&line) {
                let email = mat.as_str();
                let parts: Vec<&str> = email.split('@').collect();
                let masked = if parts.len() == 2 && parts[0].len() > 2 {
                    format!("{}***@{}", &parts[0][..2], parts[1])
                } else {
                    "***@***.***".to_string()
                };
                findings.push(PiiFinding {
                    pii_type: PiiType::EmailAddress,
                    file_path: rel_path.to_string(),
                    line_number: line_num,
                    masked_value: masked,
                    context_snippet: line.trim().to_string(),
                });
            }

            // 4. Check Phone Numbers
            for mat in self.phone_regex.find_iter(&line) {
                findings.push(PiiFinding {
                    pii_type: PiiType::PhoneNumber,
                    file_path: rel_path.to_string(),
                    line_number: line_num,
                    masked_value: "***-***-".to_string() + &mat.as_str()[mat.as_str().len()-4..],
                    context_snippet: line.trim().to_string(),
                });
            }

            // 5. Check API Keys / Hardcoded Passwords
            for mat in self.key_regex.find_iter(&line) {
                let val = mat.as_str();
                let masked = if val.starts_with("sk-") {
                    format!("sk-{}***[REDACTED]", &val[3..7.min(val.len())])
                } else {
                    "[SECRET_CREDENTIAL_REDACTED]".to_string()
                };
                findings.push(PiiFinding {
                    pii_type: PiiType::ApiSecretKey,
                    file_path: rel_path.to_string(),
                    line_number: line_num,
                    masked_value: masked,
                    context_snippet: line.trim().to_string(),
                });
            }
        }

        Ok(findings)
    }

    /// Luhn algorithm (Mod 10) validation
    pub fn luhn_verify(number: &str) -> bool {
        let mut sum = 0;
        let mut alternate = false;

        for ch in number.chars().rev() {
            if let Some(mut digit) = ch.to_digit(10) {
                if alternate {
                    digit *= 2;
                    if digit > 9 {
                        digit -= 9;
                    }
                }
                sum += digit;
                alternate = !alternate;
            } else {
                return false;
            }
        }

        sum % 10 == 0
    }
}
