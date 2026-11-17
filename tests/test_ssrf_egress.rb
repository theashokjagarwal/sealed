# frozen_string_literal: true
# Test 5: SSRF Egress Filter & Private Address Blocking

PROJECT_ROOT = File.expand_path('..', __dir__)
require_relative '../rules/ed25519'

# Test Security.validate_egress_endpoint directly from sealed binary runner
load File.join(PROJECT_ROOT, 'bin', 'sealed')

puts ">> [TEST: SSRF & EGRESS] Testing metadata service blocking..."
begin
  Security.validate_egress_endpoint("http://169.254.169.254/latest/meta-data", false)
  abort("[FAIL] Failed to block cloud metadata IP 169.254.169.254!")
rescue SealedSecurityError => e
  puts "   Blocked 169.254.169.254: #{e.message}"
end

puts ">> [TEST: SSRF & EGRESS] Testing loopback blocking..."
begin
  Security.validate_egress_endpoint("http://127.0.0.1:8080/v1/chat", false)
  abort("[FAIL] Failed to block loopback 127.0.0.1!")
rescue SealedSecurityError => e
  puts "   Blocked 127.0.0.1: #{e.message}"
end

puts ">> [TEST: SSRF & EGRESS] Testing private RFC1918 blocking without flag..."
begin
  Security.validate_egress_endpoint("http://10.0.1.5:8000/predict", false)
  abort("[FAIL] Failed to block RFC1918 10.0.1.5 without opt-in!")
rescue SealedSecurityError => e
  puts "   Blocked 10.0.1.5: #{e.message}"
end

puts ">> [TEST: SSRF & EGRESS] Testing private RFC1918 allowance WITH flag..."
begin
  Security.validate_egress_endpoint("http://10.0.1.5:8000/predict", true)
  puts "   Allowed 10.0.1.5 when allow_private is explicitly true."
rescue SealedSecurityError => e
  abort("[FAIL] Unexpected rejection with allow_private true: #{e.message}")
end

puts ">> [TEST: SSRF & EGRESS] Testing non-HTTP scheme blocking..."
begin
  Security.validate_egress_endpoint("gopher://evil.attacker.com/1", false)
  abort("[FAIL] Failed to block non-HTTP scheme!")
rescue SealedSecurityError => e
  puts "   Blocked non-HTTP scheme: #{e.message}"
end

puts ">> [PASS: SSRF & EGRESS CONTROLS] All network boundary defenses verified!"
exit 0
