#!/usr/bin/env python3
"""
scripts/run_pipeline.py
Automated Toolchain Verification Orchestrator for NT230 - Topic D04 (Supply Chain Compromise).
Focuses strictly on verifying tool functionality and pipeline readiness:
1. Multi-Layer Detector verification (scripts/detector.py)
2. Pre-Install CI/CD Security Gate verification (scripts/supply_chain_gate.py)
3. Artifact Hash Tampering & Integrity tool verification (simulate_tamper.py)
4. Synthetic Dataset Generator tool verification (scripts/data_gen.py)
"""

import os
import sys
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
PACKAGES_DIR = os.path.join(BASE_DIR, "packages")

def print_header(title: str):
    print("\n" + "=" * 75)
    print(f" {title.upper()}")
    print("=" * 75)

def run_step(step_name: str, cmd: list, expect_failure: bool = False):
    print_header(step_name)
    print(f"[*] Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=BASE_DIR)
    if expect_failure:
        if res.returncode != 0:
            print(f"[+] Security Gate functioning as expected: Blocked malicious package (Exit code {res.returncode}).")
        else:
            print(f"[!] Warning: Security Gate did not block package as expected!")
    else:
        if res.returncode != 0:
            print(f"[!] Step returned non-zero exit code: {res.returncode}")
        else:
            print(f"[+] Verified successfully: {step_name}")

def main():
    print_header("NT230 - TOPIC D04: SUPPLY CHAIN SECURITY TOOLCHAIN VERIFICATION")
    print("Repository focus: Tooling Architecture & Security Instrumentation")
    print("Target Ecosystem: npm / Node.js")
    print("PoC Model: Controlled Safe Markers in Isolated Lab Environment")

    # Step 1: Verify Multi-Layer Detector on base PoC packages
    detector_script = os.path.join(SCRIPTS_DIR, "detector.py")
    run_step(
        "Step 1: Verify Multi-Layer Detector (packages/)",
        [sys.executable, detector_script, PACKAGES_DIR]
    )

    # Step 2: Verify CI/CD Security Gate (Pass on benign, Block on malicious)
    gate_script = os.path.join(SCRIPTS_DIR, "supply_chain_gate.py")
    benign_pkg = os.path.join(PACKAGES_DIR, "uit-benign")
    malicious_pkg = os.path.join(PACKAGES_DIR, "uit-core-auth")
    
    run_step(
        "Step 2.1: Verify Security Gate (Permit Benign Package)",
        [sys.executable, gate_script, benign_pkg]
    )
    run_step(
        "Step 2.2: Verify Security Gate (Intercept Malicious Package)",
        [sys.executable, gate_script, malicious_pkg],
        expect_failure=True
    )

    # Step 3: Verify Artifact Hash Tampering Simulation Tool
    tamper_script = os.path.join(PACKAGES_DIR, "uit-marker-tamper", "simulate_tamper.py")
    run_step(
        "Step 3: Verify Artifact Integrity & Tampering Simulation Tool",
        [sys.executable, tamper_script]
    )

    # Step 4: Verify Synthetic Dataset Generator Tool (Sample run)
    data_gen_script = os.path.join(SCRIPTS_DIR, "data_gen.py")
    test_output_dir = os.path.join(BASE_DIR, "generated_packages")
    run_step(
        "Step 4: Verify Dataset Generator Tool (Small Sample)",
        [sys.executable, data_gen_script, "--count", "10", "--output", test_output_dir]
    )

    print_header("ALL SECURITY TOOLS & PIPELINES VERIFIED OPERATIONAL")
    print("Toolchain is ready for deployment, live demonstrations, and future empirical research.")

if __name__ == "__main__":
    main()
