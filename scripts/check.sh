#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --test tests/*.test.mjs
for test_file in tests/*-test.py; do
  python3 "$test_file"
done
node scripts/validate-catalog.mjs
node scripts/verify-security-startup.mjs
