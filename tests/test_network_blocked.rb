# frozen_string_literal: true
# Test 2: Zero Telemetry & Network Egress Blocked Assertion

require 'fileutils'

PROJECT_ROOT = File.expand_path('..', __dir__)
SEALED_BIN = File.join(PROJECT_ROOT, 'bin', 'sealed')
FIXTURE_DIR = File.join(PROJECT_ROOT, 'fixture-project')
out_dir = '/tmp/sealed_offline_test'
FileUtils.rm_rf(out_dir)

puts ">> [TEST: NETWORK EGRESS] Asserting zero hardcoded telemetry/license endpoints in codebase..."
forbidden_hosts = ['telemetry.', 'analytics.', 'license.sealed', 'api.sealed.security', 'sentry.io', 'statsig.com', 'segment.io']

Dir.glob(File.join(PROJECT_ROOT, '**', '*.{rb,rs,js,html,json}')).each do |file|
  next if file.include?('/tests/') || file.include?('/target/')
  content = File.read(file)
  forbidden_hosts.each do |host|
    if content.include?(host)
      abort("[FAIL] Found forbidden telemetry string '#{host}' in #{file}")
    end
  end
end
puts "   Zero telemetry endpoints found in codebase."

puts ">> [TEST: NETWORK EGRESS] Executing scan in simulated air-gap (http_proxy invalid, offline flag enforced)..."
cmd = "http_proxy=http://127.0.0.1:9999 https_proxy=http://127.0.0.1:9999 all_proxy=http://127.0.0.1:9999 #{SEALED_BIN} scan #{FIXTURE_DIR} --output-dir #{out_dir} --offline > /dev/null 2>&1"
system(cmd)
exit_code = $?.exitstatus

if exit_code == 1 && File.file?(File.join(out_dir, 'evidence.zip')) && File.file?(File.join(out_dir, 'report.html'))
  puts ">> [PASS: NETWORK EGRESS] Full audit completed successfully with network blocked!"
  exit 0
else
  abort(">> [FAIL: NETWORK EGRESS] Audit failed to execute under network severance (exit code: #{exit_code})")
end
