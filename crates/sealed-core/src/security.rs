//! Security validation modules for path traversal, SSRF, parser limits, and redaction.

use std::path::{Path, PathBuf};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Symlink escape detected: path '{0}' targets outside boundary '{1}'")]
    SymlinkEscape(String, String),
    #[error("SSRF Protection: Blocked egress to forbidden address '{0}'")]
    BlockedEgress(String),
    #[error("Parser limit exceeded: {0}")]
    ParserLimitExceeded(String),
    #[error("Decompression bomb detected: total uncompressed size exceeded limit of {0} bytes")]
    DecompressionBomb(usize),
}

/// Asserts that a target path is strictly contained within the canonicalized project root.
pub fn validate_path_containment(root: &Path, target: &Path) -> Result<PathBuf, SecurityError> {
    let canonical_root = root.canonicalize()
        .map_err(|e| SecurityError::PathTraversal(format!("Failed to canonicalize root: {}", e)))?;

    // Check for obvious traversal tricks in raw path
    for component in target.components() {
        if let std::path::Component::ParentDir = component {
            return Err(SecurityError::PathTraversal("Path contains '..' traversal segment".into()));
        }
    }

    let canonical_target = target.canonicalize()
        .map_err(|e| SecurityError::PathTraversal(format!("Failed to canonicalize target: {}", e)))?;

    if !canonical_target.starts_with(&canonical_root) {
        return Err(SecurityError::SymlinkEscape(
            canonical_target.display().to_string(),
            canonical_root.display().to_string(),
        ));
    }

    Ok(canonical_target)
}

/// Validates outbound endpoint URLs against SSRF and metadata exfiltration attacks.
pub fn validate_egress_endpoint(url_str: &str, allow_private: bool) -> Result<(), SecurityError> {
    if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        return Err(SecurityError::BlockedEgress("Only HTTP/HTTPS protocols are permitted".into()));
    }

    // Extract hostname / IP
    let host_part = url_str
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if host_part.is_empty() {
        return Err(SecurityError::BlockedEgress("Empty host specification".into()));
    }

    // Block cloud metadata service IP explicitly
    if host_part == "169.254.169.254" || host_part == "metadata.google.internal" {
        return Err(SecurityError::BlockedEgress("Access to cloud instance metadata is strictly blocked".into()));
    }

    if let Ok(ip) = host_part.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_link_local() {
                    return Err(SecurityError::BlockedEgress(format!("Blocked loopback/link-local IPv4: {}", v4)));
                }
                if (v4.is_private() || v4.octets()[0] == 10 || (v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1])) || (v4.octets()[0] == 192 && v4.octets()[1] == 168)) && !allow_private {
                    return Err(SecurityError::BlockedEgress(format!("Private RFC1918 address blocked without explicit opt-in: {}", v4)));
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return Err(SecurityError::BlockedEgress(format!("Blocked IPv6 loopback: {}", v6)));
                }
            }
        }
    }

    Ok(())
}

/// Redacts sensitive keys from error messages, debug strings, and evidence records.
pub fn redact_credentials(input: &str) -> String {
    let mut result = input.to_string();
    let re_openai = regex::Regex::new(r"sk-[A-Za-z0-9_-]{12,}").unwrap();
    result = re_openai.replace_all(&result, "sk-[REDACTED]").to_string();

    let re_pass = regex::Regex::new(r"://([^:]+):([^@]+)@").unwrap();
    result = re_pass.replace_all(&result, "://$1:[REDACTED]@").to_string();

    result
}

/// Contextual HTML escaping to prevent stored XSS in report generation.
pub fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
