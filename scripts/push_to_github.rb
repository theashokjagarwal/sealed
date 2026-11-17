#!/usr/bin/env ruby
# frozen_string_literal: true
# Push SEALED directly to GitHub via the GitHub REST Git Data API.
# Requires zero local `git` installation (uses macOS built-in Ruby stdlib only).
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx ruby scripts/push_to_github.rb <owner> <repo> [--private]

require 'net/http'
require 'uri'
require 'json'
require 'base64'
require 'pathname'

TOKEN = ENV['GITHUB_TOKEN']
OWNER = ARGV[0]
REPO  = ARGV[1]
PRIVATE_REPO = ARGV.include?('--private')

if TOKEN.nil? || TOKEN.empty? || OWNER.nil? || REPO.nil?
  warn <<~USAGE
    Usage:
      GITHUB_TOKEN=<your_pat> ruby scripts/push_to_github.rb <github_username> <repo_name> [--private]

    Create a token at: https://github.com/settings/tokens/new (scope: repo)
  USAGE
  exit 1
end

ROOT = File.expand_path('..', __dir__)
API  = 'https://api.github.com'

def api_request(method, path, body = nil)
  uri = URI("#{API}#{path}")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.read_timeout = 30

  klass = {
    get: Net::HTTP::Get,
    post: Net::HTTP::Post,
    patch: Net::HTTP::Patch,
    put: Net::HTTP::Put
  }.fetch(method)

  req = klass.new(uri)
  req['Authorization'] = "Bearer #{TOKEN}"
  req['Accept'] = 'application/vnd.github+json'
  req['X-GitHub-Api-Version'] = '2022-11-28'
  req['User-Agent'] = 'sealed-github-pusher'
  if body
    req['Content-Type'] = 'application/json'
    req.body = JSON.generate(body)
  end

  res = http.request(req)
  parsed = res.body && !res.body.empty? ? JSON.parse(res.body) : {}
  [res.code.to_i, parsed]
end

# 1. Check if repo exists; if not, create it initialized with main branch
code, repo_info = api_request(:get, "/repos/#{OWNER}/#{REPO}")
if code == 404
  puts "[1/5] Creating repository #{OWNER}/#{REPO} (#{PRIVATE_REPO ? 'private' : 'public'})..."
  c_code, c_res = api_request(:post, '/user/repos', {
    name: REPO,
    description: 'SEALED — Local-first AI compliance and safety auditor',
    private: PRIVATE_REPO,
    auto_init: true
  })
  unless [200, 201].include?(c_code)
    abort "[ERROR] Failed to create repo (HTTP #{c_code}): #{c_res['message']}"
  end
  sleep 2
  default_branch = c_res['default_branch'] || 'main'
elsif code == 200
  puts "[1/5] Found existing repository #{OWNER}/#{REPO}."
  default_branch = repo_info['default_branch'] || 'main'
else
  abort "[ERROR] GitHub API check failed (HTTP #{code}): #{repo_info['message']}"
end

# 2. Fetch current HEAD commit (if repo is completely empty, bootstrap with README)
ref_code, ref_data = api_request(:get, "/repos/#{OWNER}/#{REPO}/git/ref/heads/#{default_branch}")
if ref_code == 409 || ref_code == 404
  puts "[2/5] Repository is empty; bootstrapping initial #{default_branch} branch..."
  boot_code, boot_res = api_request(:put, "/repos/#{OWNER}/#{REPO}/contents/README.md", {
    message: 'Bootstrap repository',
    content: Base64.strict_encode64("# SEALED\n"),
    branch: default_branch
  })
  unless [200, 201].include?(boot_code)
    abort "[ERROR] Failed to bootstrap empty repo (HTTP #{boot_code}): #{boot_res['message']}"
  end
  ref_code, ref_data = api_request(:get, "/repos/#{OWNER}/#{REPO}/git/ref/heads/#{default_branch}")
end

unless ref_code == 200
  abort "[ERROR] Could not read ref heads/#{default_branch} (HTTP #{ref_code}): #{ref_data['message']}"
end

parent_sha = ref_data.dig('object', 'sha')

# 3. Collect project files
SKIP_DIRS = %w[.git target audit-artifacts].freeze
SKIP_FILES = %w[.DS_Store].freeze

files = Dir.glob(File.join(ROOT, '**', '*'), File::FNM_DOTMATCH).sort.select do |path|
  next false unless File.file?(path)

  rel = Pathname.new(path).relative_path_from(Pathname.new(ROOT)).to_s
  parts = rel.split('/')
  next false if parts.any? { |p| SKIP_DIRS.include?(p) }
  next false if SKIP_FILES.include?(File.basename(path))
  next false if rel.end_with?('.tmp', '.swp')

  true
end

puts "[3/5] Uploading #{files.size} files as Git blobs..."
tree_entries = []

files.each_with_index do |path, idx|
  rel = Pathname.new(path).relative_path_from(Pathname.new(ROOT)).to_s
  raw = File.binread(path)
  b_code, b_res = api_request(:post, "/repos/#{OWNER}/#{REPO}/git/blobs", {
    content: Base64.strict_encode64(raw),
    encoding: 'base64'
  })
  unless [200, 201].include?(b_code)
    abort "[ERROR] Failed to upload blob for #{rel} (HTTP #{b_code}): #{b_res['message']}"
  end

  mode = File.executable?(path) ? '100755' : '100644'
  tree_entries << {
    path: rel,
    mode: mode,
    type: 'blob',
    sha: b_res['sha']
  }
  printf "\r      Uploaded %d/%d (%s)          ", idx + 1, files.size, rel
end
puts ''

# 4. Create Git tree and commit
puts '[4/5] Creating Git tree and commit...'
t_code, t_res = api_request(:post, "/repos/#{OWNER}/#{REPO}/git/trees", {
  tree: tree_entries
})
unless [200, 201].include?(t_code)
  abort "[ERROR] Failed to create tree (HTTP #{t_code}): #{t_res['message']}"
end

commit_msg = ENV['COMMIT_MESSAGE'] || 'Initial commit: SEALED local-first AI compliance and safety auditor'
cm_code, cm_res = api_request(:post, "/repos/#{OWNER}/#{REPO}/git/commits", {
  message: commit_msg,
  tree: t_res['sha'],
  parents: [parent_sha]
})
unless [200, 201].include?(cm_code)
  abort "[ERROR] Failed to create commit (HTTP #{cm_code}): #{cm_res['message']}"
end

# 5. Move branch ref to new commit
puts "[5/5] Updating refs/heads/#{default_branch}..."
u_code, u_res = api_request(:patch, "/repos/#{OWNER}/#{REPO}/git/refs/heads/#{default_branch}", {
  sha: cm_res['sha'],
  force: false
})
unless u_code == 200
  abort "[ERROR] Failed to update branch ref (HTTP #{u_code}): #{u_res['message']}"
end

puts "\n[OK] Pushed #{files.size} files to https://github.com/#{OWNER}/#{REPO}"
