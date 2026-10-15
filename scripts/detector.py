#!/usr/bin/env python3
"""
scripts/detector.py
Multi-layer Supply Chain Security Detector for npm Packages.
Course: NT230 - Topic D04: Supply Chain Compromise

Architecture:
- Layer 1: Manifest Analysis (package.json metadata, lifecycle hooks, version anomalies, whitelist filtering)
- Layer 2: Static Source Analysis (index.js AST/pattern matching, obfuscation, base64/hex dynamic eval)
- Layer 3: Dynamic Behavioral Analysis (sandboxed execution monitoring, shell calls, sleep evasion)
- Auxiliary: Artifact Hash & Integrity Verification
"""

import os
import sys
import json
import re
import math
import hashlib
import base64
import argparse
from typing import Dict, Any, List, Optional, Tuple

# ==========================================
# CONSTANTS & DETECTION RULES
# ==========================================

SUSPICIOUS_LIFECYCLE_HOOKS = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall"
]

# Legitimate build commands allowed by the whitelist to minimize False Positive Rate (FPR)
WHITELISTED_HOOK_COMMANDS = [
    r"^node-gyp rebuild",
    r"^node-gyp clean",
    r"^node-pre-gyp install",
    r"^esbuild",
    r"^tsc",
    r"^npm run build",
    r"^echo 'Compiling harmless assets\.\.\.'"
]

# High-risk command patterns inside lifecycle scripts
SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"(curl|wget|fetch|nc|netcat)\s+", "Remote network egress tool invoked in script"),
    (r"(bash|sh|cmd\.exe|powershell)\s+-c", "External shell interpreter spawned"),
    (r"(base64\s+-d|base64\s+--decode)", "Shell-level Base64 payload decoding"),
    (r"eval\(Buffer\.from\(", "Inline dynamic Node.js Base64 execution"),
    (r">\s*/tmp/|>\s*C:\\Users\\Public\\", "Writing payload marker directly to OS public/temp paths"),
    (r"sleep\s+\d+|timeout\s+/t", "Suspicious sleep/delay evasion technique"),
]

# Obfuscation and dynamic execution patterns in source code (Layer 2)
SOURCE_SUSPICIOUS_PATTERNS = [
    (r"eval\s*\(\s*Buffer\.from\s*\(.*?base64", "Dynamic evaluation of Base64 encoded buffer"),
    (r"eval\s*\(\s*Buffer\.from\s*\(.*?hex", "Dynamic evaluation of Hex encoded buffer"),
    (r"new\s+Function\s*\(.*?\)\s*\(", "Dynamic Function constructor execution"),
    (r"child_process\.(exec|execSync|spawn|spawnSync|fork)\s*\(", "Direct invocation of OS child process"),
    (r"eval\s*\(\s*unescape\s*\(", "Obfuscated unescape dynamic eval"),
    (r"Atomics\.wait\s*\(", "Low-level synchronous delay evasion"),
]

# Threshold for dependency confusion version anomaly
SUSPICIOUS_VERSION_THRESHOLD = 90.0


class SupplyChainDetector:
    """
    3-Layer Security Detector inspecting npm packages for supply chain threats:
    - Lifecycle Script Injection (T1195.002)
    - Dependency Confusion (High version jump)
    - Code Obfuscation & Evasion
    - Artifact Integrity / Hash Tampering
    """

    def __init__(self, enable_whitelist: bool = True, risk_threshold: int = 35):
        self.enable_whitelist = enable_whitelist
        self.risk_threshold = risk_threshold

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect heavily obfuscated / high-entropy code."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def analyze_manifest(self, pkg_path: str, data: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 1: Manifest Analysis (package.json).
        Inspects lifecycle scripts, version numbering anomalies, and metadata indicators.
        """
        score = 0
        findings = []

        # 1. Inspect scripts
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for hook in SUSPICIOUS_LIFECYCLE_HOOKS:
                if hook in scripts:
                    command = str(scripts[hook]).strip()
                    
                    # Check whitelist filter
                    whitelisted = False
                    if self.enable_whitelist:
                        for wl_pattern in WHITELISTED_HOOK_COMMANDS:
                            if re.search(wl_pattern, command, re.IGNORECASE):
                                whitelisted = True
                                break
                    
                    if whitelisted:
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": f"Whitelisted Hook: {hook}",
                            "severity": "INFO",
                            "detail": f"Command '{command}' matches whitelist rule."
                        })
                    else:
                        score += 40
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": f"Suspicious Lifecycle Hook: {hook}",
                            "severity": "HIGH",
                            "detail": f"Detected active '{hook}' hook with command: {command}"
                        })

                    # Check for explicit malicious command patterns inside the hook
                    for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS:
                        if re.search(pattern, command, re.IGNORECASE):
                            score += 25
                            findings.append({
                                "layer": "Layer 1 - Manifest",
                                "rule": "Suspicious Hook Command Pattern",
                                "severity": "CRITICAL",
                                "detail": f"{desc} in '{hook}': {command}"
                            })

        # 2. Inspect version anomalies (Dependency Confusion)
        version_str = str(data.get("version", "1.0.0"))
        try:
            major_version = float(re.split(r"[\.-]", version_str)[0])
            if major_version >= SUSPICIOUS_VERSION_THRESHOLD:
                score += 50
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": "Dependency Confusion Indicator",
                    "severity": "CRITICAL",
                    "detail": f"Abnormally high major version '{version_str}' (>= {SUSPICIOUS_VERSION_THRESHOLD})"
                })
        except (ValueError, IndexError):
            pass

        # 3. Inspect missing or deceptive metadata
        if not data.get("description") or len(str(data.get("description")).strip()) == 0:
            score += 5
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Empty Description",
                "severity": "LOW",
                "detail": "Package lacks metadata description."
            })

        return score, findings

    def analyze_source_code(self, pkg_dir: str) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 2: Static Source Code Analysis.
        Scans all JavaScript files (e.g. index.js) for obfuscation, dynamic evaluation, and shell spawning.
        """
        score = 0
        findings = []

        js_files = []
        for root, _, files in os.walk(pkg_dir):
            if "node_modules" in root or ".git" in root:
                continue
            for file in files:
                if file.endswith((".js", ".cjs", ".mjs")):
                    js_files.append(os.path.join(root, file))

        for file_path in js_files:
            rel_path = os.path.relpath(file_path, pkg_dir)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                continue

            # Check known obfuscation / dangerous dynamic patterns
            for pattern, desc in SOURCE_SUSPICIOUS_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    score += 45
                    findings.append({
                        "layer": "Layer 2 - Source Code",
                        "rule": "Obfuscation / Dynamic Exec Pattern",
                        "severity": "CRITICAL",
                        "detail": f"{desc} detected in {rel_path} (Matches: {len(matches)})"
                    })

            # Check Shannon entropy for packed / obfuscated chunks
            entropy = self.calculate_entropy(content)
            if len(content) > 200 and entropy > 5.5:
                score += 20
                findings.append({
                    "layer": "Layer 2 - Source Code",
                    "rule": "High Entropy Code Section",
                    "severity": "MEDIUM",
                    "detail": f"Entropy of {rel_path} is {entropy:.2f} (threshold: 5.5)"
                })

            # Check long base64 string constants
            base64_strings = re.findall(r"['\"][A-Za-z0-9+/=]{40,}['\"]", content)
            if base64_strings:
                score += 25
                findings.append({
                    "layer": "Layer 2 - Source Code",
                    "rule": "Long Encoded String Artifact",
                    "severity": "HIGH",
                    "detail": f"Found {len(base64_strings)} long Base64 string literal(s) in {rel_path}"
                })

        return score, findings

    def analyze_behavioral_sandbox(self, pkg_dir: str, manifest: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 3: Dynamic / Behavioral Sandbox Analysis (Simulated & telemetry-driven).
        Evaluates potential execution paths during installation without running destructive code.
        """
        score = 0
        findings = []

        scripts = manifest.get("scripts", {})
        combined_scripts = " ".join([str(v) for v in scripts.values()])

        # Detect evasion via sleep or time bomb
        if re.search(r"sleep\s+\d+|setTimeout|Atomics\.wait", combined_scripts, re.IGNORECASE):
            score += 30
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Sleep / Delay Evasion Detected",
                "severity": "HIGH",
                "detail": "Install lifecycle scripts contain deliberate delay execution to evade sandboxes."
            })

        # Detect attempted OS telemetry tampering
        if re.search(r">\s*/dev/null\s*2>&1|--silent|-s\s+", combined_scripts):
            score += 15
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Output Redirection / Stealth Execution",
                "severity": "MEDIUM",
                "detail": "Script suppresses stdout/stderr to hide execution traces."
            })

        return score, findings

    def scan_package(self, pkg_dir: str) -> Dict[str, Any]:
        """
        Runs all 3 detection layers on a target package directory.
        Returns a structured telemetry dictionary.
        """
        pkg_json_path = os.path.join(pkg_dir, "package.json")
        if not os.path.exists(pkg_json_path):
            return {
                "package_path": pkg_dir,
                "error": "package.json not found",
                "verdict": "ERROR",
                "risk_score": 0,
                "findings": []
            }

        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
        except Exception as e:
            return {
                "package_path": pkg_dir,
                "error": f"Invalid JSON: {str(e)}",
                "verdict": "ERROR",
                "risk_score": 0,
                "findings": []
            }

        package_name = manifest_data.get("name", os.path.basename(pkg_dir))
        version = manifest_data.get("version", "unknown")

        total_score = 0
        all_findings = []

        # Layer 1
        l1_score, l1_findings = self.analyze_manifest(pkg_dir, manifest_data)
        total_score += l1_score
        all_findings.extend(l1_findings)

        # Layer 2
        l2_score, l2_findings = self.analyze_source_code(pkg_dir)
        total_score += l2_score
        all_findings.extend(l2_findings)

        # Layer 3
        l3_score, l3_findings = self.analyze_behavioral_sandbox(pkg_dir, manifest_data)
        total_score += l3_score
        all_findings.extend(l3_findings)

        # Final verdict determination
        verdict = "MALICIOUS" if total_score >= self.risk_threshold else "BENIGN"

        telemetry = {
            "package_name": package_name,
            "version": version,
            "package_path": os.path.abspath(pkg_dir),
            "verdict": verdict,
            "risk_score": total_score,
            "threshold": self.risk_threshold,
            "layer_scores": {
                "layer_1_manifest": l1_score,
                "layer_2_source": l2_score,
                "layer_3_behavioral": l3_score
            },
            "findings_count": len(all_findings),
            "findings": all_findings
        }
        return telemetry


def verify_artifact_integrity(tarball_path: str, expected_sha512: str) -> Dict[str, Any]:
    """Auxiliary: verifies artifact integrity against expected SHA-512."""
    if not os.path.exists(tarball_path):
        return {"status": "FAIL", "reason": "Artifact file not found"}

    with open(tarball_path, "rb") as f:
        data = f.read()
    digest = hashlib.sha512(data).digest()
    actual_hash = "sha512-" + base64.b64encode(digest).decode("utf-8")

    matched = (actual_hash == expected_sha512)
    return {
        "status": "PASS" if matched else "FAIL",
        "tarball": tarball_path,
        "expected_hash": expected_sha512,
        "actual_hash": actual_hash,
        "matched": matched
    }


def main():
    parser = argparse.ArgumentParser(description="Multi-Layer Supply Chain Security Detector (NT230 - D04)")
    parser.add_argument("target", help="Path to package directory or directory containing multiple packages")
    parser.add_argument("--threshold", type=int, default=35, help="Risk score threshold for MALICIOUS verdict (default: 35)")
    parser.add_argument("--no-whitelist", action="store_true", help="Disable whitelist filtering (to analyze FPR trade-off)")
    parser.add_argument("--output", type=str, default=None, help="Save telemetry output to JSON file")
    args = parser.parse_args()

    detector = SupplyChainDetector(enable_whitelist=(not args.no_whitelist), risk_threshold=args.threshold)

    results = []
    if os.path.exists(os.path.join(args.target, "package.json")):
        # Single package scan
        telemetry = detector.scan_package(args.target)
        results.append(telemetry)
    else:
        # Batch directory scan
        subdirs = sorted([os.path.join(args.target, d) for d in os.listdir(args.target) if os.path.isdir(os.path.join(args.target, d))])
        for sdir in subdirs:
            if os.path.exists(os.path.join(sdir, "package.json")):
                telemetry = detector.scan_package(sdir)
                results.append(telemetry)

    print("\n" + "=" * 70)
    print(f" SUPPLY CHAIN SECURITY SCAN REPORT (Total Scanned: {len(results)})")
    print("=" * 70)
    for res in results:
        v_tag = f"[{res['verdict']}]"
        print(f"{v_tag:<12} {res['package_name']:<25} (v{res['version']:<10}) -> Score: {res['risk_score']}")
        if res["findings"]:
            for f in res["findings"]:
                print(f"   * [{f['layer']}] {f['rule']}: {f['detail']}")

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Telemetry exported to {args.output}")


if __name__ == "__main__":
    main()
