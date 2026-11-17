# frozen_string_literal: true
# Test 1: Deterministic Byte-Identical Evidence Output

require 'digest'
require 'fileutils'

PROJECT_ROOT = File.expand_path('..', __dir__)
SEALED_BIN = File.join(PROJECT_ROOT, 'bin', 'sealed')
FIXTURE_DIR = File.join(PROJECT_ROOT, 'fixture-project')

out1 = '/tmp/sealed_determ_test_1'
out2 = '/tmp/sealed_determ_test_2'
FileUtils.rm_rf(out1)
FileUtils.rm_rf(out2)
FileUtils.mkdir_p(out1)
FileUtils.mkdir_p(out2)

puts ">> [TEST: DETERMINISM] Running scan pass 1..."
system("#{SEALED_BIN} scan #{FIXTURE_DIR} --output-dir #{out1} > /dev/null 2>&1")
exit_code1 = $?.exitstatus

puts ">> [TEST: DETERMINISM] Running scan pass 2..."
system("#{SEALED_BIN} scan #{FIXTURE_DIR} --output-dir #{out2} > /dev/null 2>&1")
exit_code2 = $?.exitstatus

zip1 = File.join(out1, 'evidence.zip')
zip2 = File.join(out2, 'evidence.zip')

unless File.file?(zip1) && File.file?(zip2)
  abort("[FAIL] One or both evidence.zip files were not generated!")
end

hash1 = Digest::SHA256.file(zip1).hexdigest
hash2 = Digest::SHA256.file(zip2).hexdigest

puts "   Pass 1 evidence.zip SHA-256: #{hash1}"
puts "   Pass 2 evidence.zip SHA-256: #{hash2}"

if hash1 == hash2 && exit_code1 == 1 && exit_code2 == 1
  puts ">> [PASS: DETERMINISM] Byte-identical evidence.zip produced across consecutive runs!"
  exit 0
else
  abort(">> [FAIL: DETERMINISM] Evidence archives differ or unexpected exit codes!")
end
