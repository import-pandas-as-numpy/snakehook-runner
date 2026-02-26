#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "--yes-i-know-this-runs-untrusted-code" ]]; then
  echo "Refusing to run. Pass --yes-i-know-this-runs-untrusted-code"
  exit 1
fi

echo "Manual smoke script placeholder."
echo "Run this only outside CI with explicit local controls."
