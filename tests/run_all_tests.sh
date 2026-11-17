#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "============================================================"
echo " SEALED Security, Determinism & Compliance Test Suite"
echo "============================================================"

echo ""
ruby "$DIR/test_determinism.rb"

echo ""
ruby "$DIR/test_network_blocked.rb"

echo ""
ruby "$DIR/test_path_traversal.rb"

echo ""
ruby "$DIR/test_rule_signature.rb"

echo ""
ruby "$DIR/test_ssrf_egress.rb"

echo ""
ruby "$DIR/test_zip_slip_and_bomb.rb"

echo ""
ruby "$DIR/test_xss_and_escaping.rb"

echo ""
ruby "$DIR/test_sql_safety.rb"

echo ""
ruby "$DIR/test_exit_codes.rb"

echo ""
echo "============================================================"
echo " ALL 9 TESTS PASSED: Controls and Determinism Verified!"
echo "============================================================"
