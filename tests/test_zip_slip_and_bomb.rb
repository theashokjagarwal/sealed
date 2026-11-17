# frozen_string_literal: true
# Test 6: Zip-Slip and Archive Decompression Defense

require 'fileutils'
require 'zlib'

PROJECT_ROOT = File.expand_path('..', __dir__)
SEALED_BIN = File.join(PROJECT_ROOT, 'bin', 'sealed')

puts ">> [TEST: ZIP-SLIP] Crafting malicious zip-slip archive..."
evil_zip_path = '/tmp/evil_zip_slip.zip'
evil_entry = '../../../../../../../../../../../../tmp/evil_pwned.txt'

# Write manual zip archive with traversal path in central directory
File.open(evil_zip_path, 'wb') do |io|
  data = "malicious payload"
  crc = Zlib.crc32(data)
  compressed = Zlib::Deflate.deflate(data)[2..-5]

  # Local header
  io.write([0x04034b50, 20, 0, 8, 0, 0, crc, compressed.bytesize, data.bytesize, evil_entry.bytesize, 0].pack("VvvvvvVVVvv") + evil_entry)
  io.write(compressed)

  # Central Directory
  cd_offset = io.pos
  io.write([0x02014b50, 20, 20, 0, 8, 0, 0, crc, compressed.bytesize, data.bytesize, evil_entry.bytesize, 0, 0, 0, 0, 0o100644 << 16, 0].pack("VvvvvvvVVVvvvvvVV") + evil_entry)
  cd_size = io.pos - cd_offset

  # EOCD
  io.write([0x06054b50, 0, 0, 1, 1, cd_size, cd_offset, 0].pack("VvvvvVVv"))
end

cmd = "#{SEALED_BIN} verify #{evil_zip_path} 2>&1"
output = `#{cmd}`
exit_code = $?.exitstatus

target_pwned = '/tmp/evil_pwned.txt'
if File.exist?(target_pwned)
  FileUtils.rm_f(target_pwned)
  abort(">> [FAIL: ZIP-SLIP] Malicious archive escaped boundary and wrote to #{target_pwned}!")
end

unless exit_code != 0
  abort(">> [FAIL: ZIP-SLIP] Archive verification did not fail on malicious archive!")
end

puts "   Zip-slip traversal successfully intercepted and prevented."
FileUtils.rm_f(evil_zip_path)

puts ">> [PASS: ZIP-SLIP DEFENSE] Controls successfully verified!"
exit 0
