#!/usr/bin/env python3
"""
scripts/supply_chain_gate.py
Automated Supply Chain Security Gate for CI/CD Pipelines & Developer Pre-commit Hooks.
Course: NT230 - Topic D04: Supply Chain Compromise

Acts as an admission controller / policy enforcer:
- Audits root project dependencies or staging packages before 'npm install'.
- Intercepts Dependency Confusion (untrusted namespace version bumps).
- Intercepts untrusted lifecycle script hooks.
- Halts pipeline execution (Exit Code 1) if high-risk indicators are identified.
"""

import os
import sys
import argparse
from detector import SupplyChainDetector

def run_gate(target_dir: str, threshold: int = 35) -> int:
    print("=" * 65)
    print(" [CI/CD GATE] SUPPLY CHAIN PRE-INSTALL POLICY ENFORCER")
    print(f" Target Path: {target_dir}")
    print(f" Policy Risk Threshold: {threshold}")
    print("=" * 65)

    detector = SupplyChainDetector(enable_whitelist=True, risk_threshold=threshold)
    result = detector.scan_package(target_dir)

    print(f"Package Scanned : {result.get('package_name', 'Unknown')}")
    print(f"Version         : {result.get('version', 'Unknown')}")
    print(f"Evaluated Risk  : {result.get('risk_score', 0)} / {threshold}")
    print(f"Gate Decision   : {result.get('verdict', 'UNKNOWN')}")
    print("-" * 65)

    if result.get("findings"):
        print("Violation Details:")
        for f in result["findings"]:
            print(f" [!] {f['severity']:<8} | {f['layer']:<22} | {f['rule']}")
            print(f"     Details: {f['detail']}")
        print("-" * 65)

    if result.get("verdict") == "MALICIOUS":
        print("\n[GATE FAILED] BLOCKED: Supply chain compromise indicators detected!")
        print("Policy action: ABORTING build to prevent code execution on runner.")
        print("=" * 65)
        return 1
    else:
        print("\n[GATE PASSED] Package verified safe. Proceeding with dependency resolution.")
        print("=" * 65)
        return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Supply Chain Pre-Install CI/CD Gate")
    parser.add_argument("target", help="Directory of package to audit before install")
    parser.add_argument("--threshold", type=int, default=35, help="Policy risk threshold")
    args = parser.parse_args()

    sys.exit(run_gate(args.target, args.threshold))
