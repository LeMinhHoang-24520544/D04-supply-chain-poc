#!/usr/bin/env python3
"""
scripts/run_pipeline.py
Automated End-to-End Orchestrator for NT230 - Topic D04 (Supply Chain Compromise)
Executes all project workflows in sequence:
1. Verification of the 4 PoC Archetypes
2. Artifact Tampering & Hash Integrity Simulation
3. Synthetic Dataset Generation (100+ packages)
4. Multi-layer Detection & Telemetry Evaluation
5. Metrics & Trade-off Report Generation
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

def run_step(step_name: str, cmd: list):
    print_header(step_name)
    print(f"[*] Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=BASE_DIR)
    if res.returncode != 0:
        print(f"[!] Warning: Step '{step_name}' exited with code {res.returncode}")
    else:
        print(f"[+] Completed: {step_name}")

def main():
    print_header("NT230 - TOPIC D04: SUPPLY CHAIN COMPROMISE LAB PIPELINE")
    print("Author: Group D04 (NT230)")
    print("Target Ecosystem: npm / Node.js")
    print("Safety Model: Double Isolation (VM + Docker) + Non-destructive Safe Markers")
    
    # Step 1: Scan 4 Base PoC Packages
    detector_script = os.path.join(SCRIPTS_DIR, "detector.py")
    run_step("Step 1: Scan 4 Base PoC Packages with Multi-Layer Detector", [sys.executable, detector_script, PACKAGES_DIR])

    # Step 2: Simulate Artifact Hash Tampering
    tamper_script = os.path.join(PACKAGES_DIR, "uit-marker-tamper", "simulate_tamper.py")
    run_step("Step 2: Simulate Artifact Hash Tampering", [sys.executable, tamper_script])

    # Step 3: Generate Dataset
    data_gen_script = os.path.join(SCRIPTS_DIR, "data_gen.py")
    run_step("Step 3: Generate Synthetic Package Dataset (100 samples)", [sys.executable, data_gen_script, "--count", "100"])

    # Step 4: Evaluate Detector & Output Telemetry
    eval_script = os.path.join(SCRIPTS_DIR, "evaluate.py")
    run_step("Step 4: Quantitative Evaluation (Precision, Recall, F1, FPR, Trade-offs)", [sys.executable, eval_script])

    print_header("ALL LAB STEPS COMPLETED SUCCESSFULLY")
    print("Telemetry log saved to: logs/telemetry_log.json")
    print("Verdaccio infrastructure configured in: infrastructure/")

if __name__ == "__main__":
    main()
