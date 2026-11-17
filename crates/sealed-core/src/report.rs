//! Deterministic HTML Report Generator.
//! Zero remote origins, zero inline external scripts, strict CSP, A4 print-optimized styling.

use crate::rule_engine::EvaluatedFinding;
use crate::evidence::EvidenceManifest;
use crate::security::html_escape;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate_html(
        manifest: &EvidenceManifest,
        findings: &[EvaluatedFinding],
    ) -> String {
        let mut findings_rows = String::new();

        for f in findings {
            let status_badge_class = match f.severity.to_uppercase().as_str() {
                "CRITICAL" => "badge-fail",
                "HIGH" => "badge-fail",
                "MEDIUM" => "badge-warn",
                _ => "badge-muted",
            };

            let row = format!(
                r#"<tr class="finding-row">
                    <td><span class="badge {badge_class}">{severity}</span></td>
                    <td><span class="mono-code">{finding_id}</span></td>
                    <td><strong>{control_id}</strong><div class="sub-text">{framework}</div></td>
                    <td>
                        <div class="finding-title">{title}</div>
                        <div class="finding-clause">{clause}</div>
                        <div class="mono-path">{file_path}:{line_num}</div>
                        <details class="evidence-details">
                            <summary>Inspect Raw Telemetry & Evidence</summary>
                            <div class="evidence-body">
                                <strong>Probe Payload:</strong>
                                <pre><code>{raw_probe}</code></pre>
                                <strong>Observed Model Response:</strong>
                                <pre><code>{raw_response}</code></pre>
                                <strong>Forensic Evidence:</strong>
                                <div>{evidence}</div>
                            </div>
                        </details>
                    </td>
                </tr>"#,
                badge_class = status_badge_class,
                severity = html_escape(&f.severity),
                finding_id = html_escape(&f.finding_id),
                control_id = html_escape(&f.control_id),
                framework = html_escape(&f.framework),
                title = html_escape(&f.title),
                clause = html_escape(&f.clause),
                file_path = html_escape(&f.file_path),
                line_num = f.line_number,
                raw_probe = html_escape(&f.raw_probe),
                raw_response = html_escape(&f.raw_response),
                evidence = html_escape(&f.evidence),
            );
            findings_rows.push_str(&row);
        }

        let overall_status = if findings.is_empty() { "PASS" } else { "FAIL" };
        let overall_class = if findings.is_empty() { "badge-pass" } else { "badge-fail" };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'self' data:;">
    <title>SEALED Compliance &amp; Safety Audit Report</title>
    <style>
        :root {{
            --bg-canvas: #090a0f;
            --bg-surface: #11131a;
            --bg-subtle: #171a23;
            --border-subtle: #1f2330;
            --border-strong: #333a4d;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --state-pass: #10b981;
            --state-fail: #f43f5e;
            --state-warn: #f59e0b;
            --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
        }}
        @media (prefers-color-scheme: light) {{
            :root {{
                --bg-canvas: #f8f9fa;
                --bg-surface: #ffffff;
                --bg-subtle: #f1f3f5;
                --border-subtle: #e2e8f0;
                --border-strong: #cbd5e1;
                --text-primary: #0f172a;
                --text-secondary: #475569;
                --text-muted: #64748b;
                --state-pass: #059669;
                --state-fail: #e11d48;
                --state-warn: #d97706;
            }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-canvas);
            color: var(--text-primary);
            font-family: var(--font-ui);
            font-size: 15px;
            line-height: 1.5;
            padding: 32px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            padding: 32px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 24px;
            margin-bottom: 24px;
        }}
        .title-block h1 {{
            font-size: 24px;
            font-weight: 600;
            letter-spacing: -0.02em;
        }}
        .title-block p {{
            color: var(--text-secondary);
            font-size: 13px;
            margin-top: 4px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: 600;
            font-family: var(--font-mono);
            letter-spacing: 0.05em;
        }}
        .badge-pass {{ background: rgba(16, 185, 129, 0.15); color: var(--state-pass); border: 1px solid var(--state-pass); }}
        .badge-fail {{ background: rgba(244, 63, 94, 0.15); color: var(--state-fail); border: 1px solid var(--state-fail); }}
        .badge-warn {{ background: rgba(245, 158, 11, 0.15); color: var(--state-warn); border: 1px solid var(--state-warn); }}
        .badge-muted {{ background: var(--bg-subtle); color: var(--text-muted); border: 1px solid var(--border-subtle); }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            background: var(--bg-subtle);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 13px;
        }}
        .meta-item .meta-label {{ color: var(--text-secondary); font-size: 12px; text-transform: uppercase; }}
        .meta-item .meta-val {{ font-family: var(--font-mono); word-break: break-all; margin-top: 4px; }}
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            margin-top: 16px;
        }}
        .findings-table th {{
            background: var(--bg-subtle);
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-strong);
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .findings-table td {{
            padding: 12px;
            border-bottom: 1px solid var(--border-subtle);
            vertical-align: top;
            font-size: 13px;
        }}
        .mono-code {{ font-family: var(--font-mono); font-size: 12px; color: var(--text-primary); }}
        .mono-path {{ font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); margin-top: 4px; }}
        .finding-title {{ font-weight: 600; color: var(--text-primary); font-size: 14px; }}
        .finding-clause {{ color: var(--text-secondary); font-size: 12px; margin-top: 2px; }}
        .evidence-details {{ margin-top: 8px; font-size: 12px; }}
        .evidence-details summary {{ cursor: pointer; color: var(--text-secondary); user-select: none; }}
        .evidence-body {{ margin-top: 8px; padding: 8px; background: var(--bg-subtle); border-radius: 4px; border: 1px solid var(--border-subtle); }}
        pre {{ background: #000; padding: 6px 8px; border-radius: 3px; overflow-x: auto; margin: 4px 0 8px 0; color: #e2e8f0; font-family: var(--font-mono); font-size: 11px; }}
        .disclaimer-box {{
            margin-top: 32px;
            padding: 16px;
            background: var(--bg-subtle);
            border-left: 3px solid var(--border-strong);
            font-size: 12px;
            color: var(--text-secondary);
        }}
        @media print {{
            body {{ padding: 0; background: #fff; color: #000; }}
            .container {{ border: none; padding: 0; max-width: 100%; }}
            .badge-fail {{ border: 1px solid #000; color: #000; }}
            .badge-pass {{ border: 1px solid #000; color: #000; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="title-block">
                <h1>SEALED AUDIT REPORT</h1>
                <p>Deterministic Local-First AI Compliance &amp; Safety Verification</p>
            </div>
            <div>
                <span class="badge {overall_class}">STATUS: {overall_status}</span>
            </div>
        </header>

        <section class="meta-grid">
            <div class="meta-item">
                <div class="meta-label">Audit Generator</div>
                <div class="meta-val">{generator}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Rule Pack</div>
                <div class="meta-val">{rule_pack_id} (v{rule_pack_version})</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Total Findings</div>
                <div class="meta-val" style="font-size: 16px; font-weight: 600;">{total_findings}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Final Chain Hash (SHA-256)</div>
                <div class="meta-val">{final_chain_hash}</div>
            </div>
        </section>

        <section>
            <h2>Compliance Findings Registry</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th style="width: 90px;">Severity</th>
                        <th style="width: 130px;">Finding ID</th>
                        <th style="width: 180px;">Framework / Control</th>
                        <th>Details, Evidence &amp; Traceability</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </section>

        <footer class="disclaimer-box">
            <strong>Auditor Integrity Attestation &amp; Limitation of Proof:</strong><br>
            {attestation_statement}<br><br>
            <strong>Legal &amp; Technical Limitations:</strong><br>
            {limitations_disclaimer}
        </footer>
    </div>
</body>
</html>"#,
            overall_class = overall_class,
            overall_status = overall_status,
            generator = html_escape(&manifest.generator),
            rule_pack_id = html_escape(&manifest.rule_pack_id),
            rule_pack_version = html_escape(&manifest.rule_pack_version),
            total_findings = manifest.total_findings,
            final_chain_hash = html_escape(&manifest.final_chain_hash),
            findings_rows = findings_rows,
            attestation_statement = html_escape(&manifest.attestation_statement),
            limitations_disclaimer = html_escape(&manifest.limitations_disclaimer),
        )
    }
}
