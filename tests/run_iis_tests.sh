#!/usr/bin/env bash
set -euo pipefail

# Tests the IIS threat enumeration capabilities on the Windows Server VM
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Running JJ-RS IIS Threat Detection Tests"
python3 "${SCRIPT_DIR}/test_iis_threats.py"
