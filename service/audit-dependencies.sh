#!/usr/bin/env sh
set -eu

# pySigma 1.4.0 declares DiskCache but does not import or use it in the
# conversion service. PYSEC-2026-2447 requires an application to deserialize
# an attacker-written cache entry; this service never creates or reads one.
python3 -m pip_audit \
  --requirement "$(dirname "$0")/requirements.txt" \
  --ignore-vuln PYSEC-2026-2447
