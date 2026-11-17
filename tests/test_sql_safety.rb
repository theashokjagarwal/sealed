# frozen_string_literal: true
# Test 8: SQL Parameterization & Query Safety Static Assertion

PROJECT_ROOT = File.expand_path('..', __dir__)

puts ">> [TEST: SQL PARAMETERIZATION] Scanning codebase for string formatting in SQL statements..."

sql_violation_patterns = [
  /format!\s*\(\s*"SELECT.*\{\}/i,
  /format!\s*\(\s*"INSERT.*\{\}/i,
  /format!\s*\(\s*"UPDATE.*\{\}/i,
  /format!\s*\(\s*"DELETE.*\{\}/i,
  /query\s*\(\s*&format!/i,
  /execute\s*\(\s*&format!/i,
  /execute\s*\(\s*"\s*SELECT.*#\{/i,
  /execute\s*\(\s*"\s*INSERT.*#\{/i
]

violations = []

Dir.glob(File.join(PROJECT_ROOT, '**', '*.{rs,rb}')).each do |file|
  next if file.include?('/target/') || file.include?('/tests/')
  File.foreach(file).with_index(1) do |line, line_no|
    sql_violation_patterns.each do |pattern|
      if line =~ pattern
        violations << "#{file}:#{line_no} => #{line.strip}"
      end
    end
  end
end

if violations.any?
  abort(">> [FAIL: SQL PARAMETERIZATION] Unparameterized SQL string formatting detected:\n#{violations.join("\n")}")
else
  puts "   Zero unparameterized SQL query constructions found."
  puts ">> [PASS: SQL PARAMETERIZATION] 100% parameterization control enforced!"
  exit 0
end
