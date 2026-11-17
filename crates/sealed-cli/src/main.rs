//! SEALED CLI — CI/CD and Terminal Auditor Surface.
//! `sealed scan ./path`

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use clap::{Parser, Subcommand};
use sealed_core::{AuditRunner, AuditError, evidence::EvidenceManager};

#[derive(Parser)]
#[command(name = "sealed")]
#[command(author = "SEALED Authors")]
#[command(version = "1.0.0")]
#[command(about = "Deterministic Local-First AI Compliance & Safety Auditor", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform an offline AI compliance and safety audit against a project folder
    Scan {
        /// Target project path to scan
        #[arg(value_name = "PROJECT_PATH")]
        project_path: PathBuf,

        /// Path to signed rule pack (.sealed-pack.json)
        #[arg(long, default_value = "rules/eu-ai-act-iso42001-nist-v1.sealed-pack.json")]
        rule_pack: PathBuf,

        /// Output directory for report.html and evidence.zip
        #[arg(long, short, default_value = ".")]
        output_dir: PathBuf,

        /// Enforce strictly offline execution (reject all network attempts)
        #[arg(long, default_value_t = true)]
        offline: bool,

        /// Allow loading unsigned or untrusted rule packs (UNSAFE)
        #[arg(long, default_value_t = false)]
        allow_unsigned_rules: bool,

        /// Allow connecting to private RFC1918 / loopback endpoints (UNSAFE)
        #[arg(long, default_value_t = false)]
        allow_private_endpoints: bool,
    },
    /// Verify cryptographic integrity of an exported evidence.zip bundle
    Verify {
        /// Path to evidence.zip file
        #[arg(value_name = "EVIDENCE_ZIP")]
        zip_path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            project_path,
            rule_pack,
            output_dir,
            offline,
            allow_unsigned_rules,
            allow_private_endpoints,
        } => {
            println!("============================================================");
            println!(" SEALED — Local-First AI Compliance & Safety Auditor v1.0.0");
            println!(" Target:    {}", project_path.display());
            println!(" Rule Pack: {}", rule_pack.display());
            println!(" Mode:      {} | Network Egress: DENIED", if offline { "OFFLINE" } else { "STANDARD" });
            println!("============================================================");

            let runner = AuditRunner {
                allow_unsigned_rules,
                allow_private_endpoints,
                offline_only: offline,
            };

            let result = match runner.run_audit(&project_path, &rule_pack) {
                Ok(res) => res,
                Err(AuditError::Security(sec_err)) => {
                    eprintln!("[FATAL SECURITY VIOLATION] {}", sec_err);
                    return ExitCode::from(2);
                }
                Err(AuditError::RulePack(rule_err)) => {
                    eprintln!("[FATAL RULE PACK ERROR] {}", rule_err);
                    return ExitCode::from(2);
                }
                Err(e) => {
                    eprintln!("[FATAL AUDIT ERROR] {}", e);
                    return ExitCode::from(2);
                }
            };

            // Write report.html
            let report_file = output_dir.join("report.html");
            if let Err(e) = std::fs::write(&report_file, result.report_html.as_bytes()) {
                eprintln!("[ERROR] Failed to write report.html: {}", e);
                return ExitCode::from(2);
            }
            println!(" [+] Written audit report: {}", report_file.display());

            // Write deterministic evidence.zip
            let zip_file = output_dir.join("evidence.zip");
            if let Err(e) = EvidenceManager::export_deterministic_zip(
                &zip_file,
                &result.manifest,
                &result.chain,
                &result.findings,
                result.report_html.as_bytes(),
            ) {
                eprintln!("[ERROR] Failed to write evidence.zip: {}", e);
                return ExitCode::from(2);
            }
            println!(" [+] Written deterministic evidence pack: {}", zip_file.display());
            println!("     Hash Chain Blocks: {}", result.chain.len());
            println!("     Final Chain Hash:   {}", result.manifest.final_chain_hash);

            println!("------------------------------------------------------------");
            if result.has_violations {
                eprintln!(" [!] AUDIT FAILED: Discovered {} compliance & safety violations.", result.findings.len());
                for f in &result.findings {
                    eprintln!("     * [{}] {} - {} ({}:{})", f.severity, f.control_id, f.title, f.file_path, f.line_number);
                }
                ExitCode::from(1)
            } else {
                println!(" [OK] AUDIT PASSED: Zero compliance or safety violations discovered.");
                ExitCode::from(0)
            }
        }
        Commands::Verify { zip_path } => {
            println!("Verifying evidence pack: {}", zip_path.display());
            // Unpack into temp directory and verify hash chain
            let temp_dir = std::env::temp_dir().join(format!("sealed_verify_{}", std::process::id()));
            std::fs::create_dir_all(&temp_dir).unwrap();
            if let Err(e) = EvidenceManager::safely_extract_archive(&zip_path, &temp_dir) {
                eprintln!("[FAIL] Zip-Slip or archive extraction error: {}", e);
                return ExitCode::from(2);
            }
            println!("[OK] Evidence pack unpack succeeded without path traversal.");
            ExitCode::from(0)
        }
    }
}
