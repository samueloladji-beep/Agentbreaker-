require_relative 'lib/vaultak'

puts "=== Ruby SDK Test ==="

# Test 1: Normal file write
vt = Vaultak::Client.new(
  api_key: 'vtk_waX4mySWXNBnQ1BhV6P0gZWVaINYlE18OiF5ziSMd9Y',
  blocked_resources: ['*.env', 'prod.*']
)

puts "Test 1: Normal file write..."
vt.monitor('ruby-test-agent') do
  File.write('/tmp/ruby_test.txt', 'hello from ruby agent')
  puts "  File write logged"
end

# Test 2: Blocked resource
puts "Test 2: Blocked .env file..."
begin
  vt.monitor('ruby-test-agent') do
    File.write('/tmp/test.env', 'SECRET=blocked')
    puts "  ERROR: should have been blocked"
  end
rescue Vaultak::VaultakBlockError => e
  puts "  Blocked correctly: #{e.message}"
end

# Test 3: Rollback
puts "Test 3: File rollback..."
File.write('/tmp/rollback_ruby.txt', 'original content')
vt2 = Vaultak::Client.new(
  api_key: 'vtk_waX4mySWXNBnQ1BhV6P0gZWVaINYlE18OiF5ziSMd9Y',
  rollback_threshold: 40
)
begin
  vt2.monitor('rollback-test') do
    File.write('/tmp/rollback_ruby.txt', 'modified by agent')
    puts "  File write intercepted"
    vt2.intercept('delete', 'prod.database', {})
  end
rescue Vaultak::VaultakPauseError
  content = File.read('/tmp/rollback_ruby.txt')
  puts "  Content after rollback: #{content}"
  puts content == 'original content' ? "  ROLLBACK SUCCESSFUL" : "  ROLLBACK FAILED"
end

puts "=== Tests complete ==="
