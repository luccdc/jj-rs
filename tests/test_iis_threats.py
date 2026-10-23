#!/usr/bin/env python3
"""
Integration test suite for `jj enum iis-sites` threat detection on Windows.
Runs against the `win2019` Vagrant VM over WinRM.
"""

import sys
import subprocess
import time

def run_winrm(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["vagrant", "winrm", "win2019", "-c", cmd],
        capture_output=True,
        text=True,
    )

def main():
    print("=" * 60)
    print(" JJ-RS IIS Threat Detection Test Suite (Host Runner)")
    print("=" * 60)

    # 1. Check if VM is running
    print("[*] Checking VM status...")
    status_proc = subprocess.run(["vagrant", "status", "win2019"], capture_output=True, text=True)
    if "running" not in status_proc.stdout:
        print("[!] Error: 'win2019' VM is not running. Please run 'vagrant up win2019' first.")
        sys.exit(1)
    print("[+] VM is running.")

    # 2. Execute test script on Windows VM via shared folder
    ps_cmd = r'powershell -NoProfile -ExecutionPolicy Bypass -File \\vboxsrv\vagrant\tests\test_iis_threats.ps1'
    print(f"[*] Executing test suite inside VM: {ps_cmd}\n")
    
    start_time = time.time()
    res = run_winrm(ps_cmd)
    elapsed = time.time() - start_time

    print(res.stdout)
    if res.stderr.strip():
        print("STDERR:\n", res.stderr)

    print(f"[*] Test run completed in {elapsed:.2f} seconds.")
    if res.returncode != 0:
        print("[!] Some tests failed.")
        sys.exit(res.returncode)
    else:
        print("[+] All tests passed successfully!")

if __name__ == "__main__":
    main()
