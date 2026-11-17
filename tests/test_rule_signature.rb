# frozen_string_literal: true
# Test 4: Ed25519 Rule Pack Cryptographic Verification

require 'json'
require 'fileutils'

PROJECT_ROOT = File.expand_path('..', __dir__)
SEALED_BIN = File.join(PROJECT_ROOT, 'bin', 'sealed')
ORIGINAL_PACK = File.join(PROJECT_ROOT, 'rules', 'eu-ai-act-iso42001-nist-v1.sealed-pack.json')

puts ">> [TEST: ED25519 RULE PACK] Testing tampered rule pack rejection..."
pack_data = JSON.parse(File.read(ORIGINAL_PACK))
# Modify rule without updating signature
pack_data['rules'][0]['title'] = "MALICIOUS MODIFIED RULE"

tampered_pack_path = '/tmp/tampered_rule_pack.json'
File.write(tampered_pack_path, JSON.pretty_generate(pack_data))

cmd = "#{SEALED_BIN} scan #{PROJECT_ROOT}/fixture-project --rule-pack #{tampered_pack_path} 2>&1"
output = `#{cmd}`
exit_code = $?.exitstatus

unless exit_code == 2 && output.include?('Rule pack signature verification failed')
  abort(">> [FAIL: ED25519] Expected exit code 2 on tampered rule pack, got #{exit_code}: #{output}")
end
puts "   Tampered rule pack rejected with exit code 2."

puts ">> [TEST: ED25519 RULE PACK] Testing explicit user bypass flag --allow-unsigned-rules..."
cmd_bypass = "#{SEALED_BIN} scan #{PROJECT_ROOT}/fixture-project --rule-pack #{tampered_pack_path} --allow-unsigned-rules 2>&1"
output_bypass = `#{cmd_bypass}`
exit_bypass = $?.exitstatus

unless output_bypass.include?('Proceeding under --allow-unsigned-rules')
  abort(">> [FAIL: ED25519 BYPASS] Warning was not emitted during bypass: #{output_bypass}")
end
puts "   Bypass flag allowed execution and logged loud security warning."

FileUtils.rm_f(tampered_pack_path)
puts ">> [PASS: ED25519 RULE PACK SIGNATURES] Cryptographic controls verified!"
exit 0
