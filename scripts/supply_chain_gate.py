#!/usr/bin/env python3
"""
scripts/supply_chain_gate.py
Automated Supply Chain Security Gate for CI/CD Pipelines & Developer Pre-commit Hooks.
Course: NT230 - Topic D04: Supply Chain Compromise

Acts as an admission controller / policy enforcer:
- Audits root project dependencies, staging package directories, or .tgz tarballs before 'npm install'.
- Intercepts Dependency Confusion (untrusted namespace version bumps & dependency graph anomalies).
- Intercepts untrusted lifecycle script hooks & runtime sandbox violations.
- Verifies SHA-512 artifact hash integrity against tampering.
- Halts pipeline execution (Exit Code 1) if high-risk indicators are identified.
"""

import os
import sys
import argparse
from typing import Optional
from detector import SupplyChainDetector


def run_gate(
    target_dir: str,
    threshold: int = 35,
    tarball_path: Optional[str] = None,
    expected_hash: Optional[str] = None
) -> int:
    print("=" * 70)
    print(" [CI/CD GATE] SUPPLY CHAIN PRE-INSTALL POLICY ENFORCER")
    print(f" Target Path          : {target_dir}")
    print(f" Policy Risk Threshold: {threshold}")
    if tarball_path:
        print(f" Artifact Tarball     : {tarball_path}")
    print("=" * 70)

    detector = SupplyChainDetector(enable_whitelist=True, risk_threshold=threshold)
    result = detector.scan_package(target_dir, tarball_path=tarball_path, expected_sha512=expected_hash)

    graph_info = result.get("dependency_graph", {})
    integrity_info = result.get("integrity_check")

    print(f"Package Scanned : {result.get('package_name', 'Unknown')}")
    print(f"Version         : {result.get('version', 'Unknown')}")
    print(f"Dep Graph Nodes : {graph_info.get('total_nodes', 1)} (Direct: {graph_info.get('direct_dependencies_count', 0)}, Transitive: {graph_info.get('transitive_dependencies_count', 0)})")
    if integrity_info:
        print(f"Integrity Check : {integrity_info.get('status')} (Matched: {integrity_info.get('matched')})")
    print(f"Evaluated Risk  : {result.get('risk_score', 0)} / {threshold}")
    print(f"Gate Decision   : {result.get('verdict', 'UNKNOWN')}")
    print("-" * 70)

    if result.get("findings"):
        print("Audit Findings:")
        for f in result["findings"]:
            print(f" [!] {f['severity']:<8} | {f['layer']:<28} | {f['rule']}")
            print(f"     Details: {f['detail']}")
        print("-" * 70)

    if result.get("verdict") == "MALICIOUS" or result.get("verdict") == "ERROR":
        print("\n[GATE FAILED] BLOCKED: Supply chain compromise indicators detected!")
        print("Policy action: ABORTING build to prevent untrusted code execution on runner.")
        print("=" * 70)
        return 1
    else:
        print("\n[GATE PASSED] Package verified safe. Proceeding with dependency resolution.")
        print("=" * 70)
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Supply Chain Pre-Install CI/CD Gate")
    parser.add_argument("target", help="Directory or .tgz tarball of package to audit before install")
    parser.add_argument("--threshold", type=int, default=35, help="Policy risk threshold (default: 35)")
    parser.add_argument("--tarball", type=str, default=None, help="Optional path to .tgz artifact for SHA-512 integrity check")
    parser.add_argument("--expected-hash", type=str, default=None, help="Expected sha512-... integrity hash for verification")
    args = parser.parse_args()

    sys.exit(run_gate(args.target, args.threshold, args.tarball, args.expected_hash))
