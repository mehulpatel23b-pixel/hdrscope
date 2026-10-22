#!/usr/bin/env bash
# Example: gate a deploy on security-header posture.
# Fails (exit 1) if any listed host grades below B.
set -euo pipefail

TARGETS=(
  "https://example.com"
)

for url in "${TARGETS[@]}"; do
  echo "==> auditing $url"
  hdrscope "$url" --min-grade B
done

echo "All targets at grade B or better. ✅"
