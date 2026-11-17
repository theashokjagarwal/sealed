# frozen_string_literal: true
# Test 3: Path Traversal & Symlink Escape Defense

require 'fileutils'

PROJECT_ROOT = File.expand_path('..', __dir__)
SEALED_BIN = File.join(PROJECT_ROOT, 'bin', 'sealed')

puts ">> [TEST: PATH TRAVERSAL] Testing traversal via '..' component..."
cmd_traversal = "#{SEALED_BIN} scan #{PROJECT_ROOT}/fixture-project/../fixture-project 2>&1"
output_traversal = `#{cmd_traversal}`
exit_traversal = $?.exitstatus

unless exit_traversal == 2 && output_traversal.include?('Path traversal attack detected')
  abort(">> [FAIL: PATH TRAVERSAL] Expected exit 2 with traversal error, got exit #{exit_traversal}: #{output_traversal}")
end
puts "   Traversal '..' rejected as expected (exit 2)."

puts ">> [TEST: SYMLINK ESCAPE] Testing symlink pointing outside project boundary..."
temp_dir = '/tmp/sealed_symlink_test'
outside_dir = '/tmp/sealed_outside_secret'
FileUtils.rm_rf(temp_dir)
FileUtils.rm_rf(outside_dir)
FileUtils.mkdir_p(temp_dir)
FileUtils.mkdir_p(outside_dir)

# Create an outside secret and a symlink inside the project pointing to it
File.write(File.join(outside_dir, 'secret.txt'), 'classified')
File.symlink(File.join(outside_dir, 'secret.txt'), File.join(temp_dir, 'escape_link.txt'))

cmd_symlink = "#{SEALED_BIN} scan #{temp_dir} 2>&1"
output_symlink = `#{cmd_symlink}`
exit_symlink = $?.exitstatus

unless exit_symlink == 2 && output_symlink.include?('Symlink escape detected')
  abort(">> [FAIL: SYMLINK ESCAPE] Expected exit 2 with symlink escape error, got exit #{exit_symlink}: #{output_symlink}")
end
puts "   Symlink escape rejected as expected (exit 2)."

FileUtils.rm_rf(temp_dir)
FileUtils.rm_rf(outside_dir)
puts ">> [PASS: PATH TRAVERSAL & SYMLINK DEFENSE] Controls successfully verified!"
exit 0
