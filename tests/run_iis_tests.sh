#!/usr/bin/env bash
set -euo pipefail

# Tests the IIS threat enumeration capabilities on the Windows Server VM
echo "============================================================"
echo " JJ-RS IIS Threat Detection Test Suite (Host Runner)"
echo "============================================================"

# 1. Check if VM is running
echo "[*] Checking VM status..."
vm_status="$(vagrant status win2019)"
if ! grep -q "running" <<< "${vm_status}"; then
    echo "[!] Error: 'win2019' VM is not running. Please run 'vagrant up win2019' first." >&2
    exit 1
fi
echo "[+] VM is running."

# 2. Check if compiled binary exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_PATH="${REPO_DIR}/target/x86_64-pc-windows-gnu/debug/jj-rs.exe"

if [[ ! -f "${BIN_PATH}" ]]; then
    echo "[!] Warning: '${BIN_PATH}' not found."
    echo "[*] Please compile with: nix develop .#windows -c cargo build --target x86_64-pc-windows-gnu"
fi

# 3. Execute test script on Windows VM via WinRM
ps_cmd='powershell -NoProfile -ExecutionPolicy Bypass -File C:\vagrant\tests\test_iis_threats.ps1'
echo "[*] Executing test suite inside VM: ${ps_cmd}"
echo ""

start_time="$(date +%s)"

set +e
vagrant winrm win2019 -c "${ps_cmd}"
res=$?
set -e

end_time="$(date +%s)"
elapsed=$((end_time - start_time))

echo "[*] Test run completed in ${elapsed} seconds."
if [[ ${res} -ne 0 ]]; then
    echo "[!] Some tests failed (exit code ${res})."
    exit "${res}"
else
    echo "[+] All tests passed successfully!"
fi
