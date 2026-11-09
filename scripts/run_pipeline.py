#!/usr/bin/env python3
"""
scripts/run_pipeline.py
Automated Toolchain Verification Orchestrator for NT230 - Topic D04 (Supply Chain Compromise).
Executes end-to-end verification of all project requirements:
1. Artifact Hash Tampering & Integrity Simulation (packages/uit-marker-tamper/simulate_tamper.py)
2. Multi-Layer Detector scan on all 6 base packages (3 Benign + 3 Malicious PoCs)
3. Pre-Install CI/CD Security Gate verification (Benign PASS vs Malicious/Tampered BLOCK)
4. Synthetic Dataset Generation & Quantitative Evaluation (Precision, Recall, F1, FPR, Latency)
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
            print("[!] Warning: Security Gate did not block package as expected!")
            sys.exit(1)
    else:
        if res.returncode != 0:
            print(f"[!] Step returned non-zero exit code: {res.returncode}")
            sys.exit(res.returncode)
        else:
            print(f"[+] Verified successfully: {step_name}")


def main():
    print_header("NT230 - TOPIC D04: SUPPLY CHAIN SECURITY TOOLCHAIN VERIFICATION")
    print("Repository focus: Tooling Architecture, Dependency Graph & Runtime Sandbox Instrumentation")
    print("Target Ecosystem: npm / Node.js (MITRE ATT&CK T1195.002)")
    print("PoC Corpus      : 3 Benign Baseline Packages + 3 Malicious Supply Chain PoC Variants")

    detector_script = os.path.join(SCRIPTS_DIR, "detector.py")
    gate_script = os.path.join(SCRIPTS_DIR, "supply_chain_gate.py")
    tamper_script = os.path.join(PACKAGES_DIR, "uit-marker-tamper", "simulate_tamper.py")
    data_gen_script = os.path.join(SCRIPTS_DIR, "data_gen.py")
    evaluate_script = os.path.join(SCRIPTS_DIR, "evaluate.py")
    test_output_dir = os.path.join(BASE_DIR, "generated_packages")

    # Step 1: Run Artifact Hash Tampering Simulation first so integrity_manifest.json is ready
    run_step(
        "Step 1: Prepare Artifact Integrity & Tampering Simulation (uit-marker-tamper)",
        [sys.executable, tamper_script]
    )

    # Step 2: Verify Multi-Layer Detector on all 6 base packages (3 Benign + 3 Malicious PoCs)
    run_step(
        "Step 2: Verify Multi-Layer Detector on 6 Base Packages (3 Benign + 3 Malicious PoCs)",
        [sys.executable, detector_script, PACKAGES_DIR]
    )

    # Step 3: Verify CI/CD Security Gate (Pass on 3 Benign, Block on Malicious & Tampered)
    run_step(
        "Step 3.1: Verify Security Gate (Permit Benign Baseline: uit-benign)",
        [sys.executable, gate_script, os.path.join(PACKAGES_DIR, "uit-benign")]
    )
    run_step(
        "Step 3.2: Verify Security Gate (Permit Whitelisted Native Addon: uit-benign-native)",
        [sys.executable, gate_script, os.path.join(PACKAGES_DIR, "uit-benign-native")]
    )
    run_step(
        "Step 3.3: Verify Security Gate (Permit Minified SVG Bundle: uit-benign-minified)",
        [sys.executable, gate_script, os.path.join(PACKAGES_DIR, "uit-benign-minified")]
    )
    run_step(
        "Step 3.4: Verify Security Gate (Intercept Dependency Confusion: uit-core-auth)",
        [sys.executable, gate_script, os.path.join(PACKAGES_DIR, "uit-core-auth")],
        expect_failure=True
    )
    run_step(
        "Step 3.5: Verify Security Gate (Intercept Tampered Artifact: uit-marker-tamper)",
        [sys.executable, gate_script, os.path.join(PACKAGES_DIR, "uit-marker-tamper")],
        expect_failure=True
    )

    # Step 4: Verify Synthetic Dataset Generator & Quantitative Evaluation Engine
    run_step(
        "Step 4.1: Generate Synthetic Package Corpus (100 Packages across 5 Categories)",
        [sys.executable, data_gen_script, "--count", "100", "--output", test_output_dir]
    )
    run_step(
        "Step 4.2: Run Quantitative Evaluation & Telemetry Benchmark (Precision/Recall/F1/FPR/Latency)",
        [sys.executable, evaluate_script, "--dataset", test_output_dir]
    )

    print_header("ALL SECURITY TOOLS & PIPELINES VERIFIED OPERATIONAL")
    print("Toolchain is 100% verified for live demonstration, CI/CD enforcement, and empirical evaluation.")


if __name__ == "__main__":
    main()
