# frozen_string_literal: true
# Test 9: CLI Exit Codes for CI/CD Gates

PROJECT_ROOT = File.expand_path('..', __dir__)
SEALED_BIN = File.join(PROJECT_ROOT, 'bin', 'sealed')

puts ">> [TEST: EXIT CODES] Testing clean project exit code (expected: 0)..."
system("#{SEALED_BIN} scan #{PROJECT_ROOT}/clean-project --output-dir /tmp/clean_test > /dev/null 2>&1")
clean_code = $?.exitstatus
unless clean_code == 0
  abort("[FAIL] Expected exit 0 for clean project, got #{clean_code}")
end
puts "   clean-project exited with 0 (PASSED)."

puts ">> [TEST: EXIT CODES] Testing fixture project with violations (expected: 1)..."
system("#{SEALED_BIN} scan #{PROJECT_ROOT}/fixture-project --output-dir /tmp/fixture_test > /dev/null 2>&1")
fixture_code = $?.exitstatus
unless fixture_code == 1
  abort("[FAIL] Expected exit 1 for project with violations, got #{fixture_code}")
end
puts "   fixture-project exited with 1 (VIOLATIONS DETECTED)."

puts ">> [TEST: EXIT CODES] Testing non-existent path operational error (expected: 2)..."
system("#{SEALED_BIN} scan /path/does/not/exist --output-dir /tmp/err_test > /dev/null 2>&1")
err_code = $?.exitstatus
unless err_code == 2
  abort("[FAIL] Expected exit 2 for non-existent path, got #{err_code}")
end
puts "   non-existent path exited with 2 (OPERATIONAL ERROR)."

puts ">> [PASS: EXIT CODES] CI exit codes 0, 1, 2 verified!"
exit 0
