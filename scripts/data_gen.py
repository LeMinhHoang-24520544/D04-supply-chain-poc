#!/usr/bin/env python3
"""
scripts/data_gen.py
Synthetic Dataset Generator for Supply Chain Security Evaluation.
Course: NT230 - Topic D04: Supply Chain Compromise

Generates a diversified corpus of npm packages (Benign vs Malicious variations):
- Benign packages (with and without whitelisted build tools like node-gyp)
- Lifecycle Hook Injection packages (preinstall, postinstall with mock markers)
- Dependency Confusion packages (anomalous major versions >= 90)
- Evasive Obfuscation packages (Base64, hex encoding, dynamic execution)
- Outputs ground_truth.json for quantitative verification (Precision, Recall, F1, FPR).
"""

import os
import json
import shutil
import random
import string
import base64
import argparse
from typing import Dict, Any, List

# Seed for reproducibility
RANDOM_SEED = 42

SAFE_MOCK_PAYLOADS = [
    "node -e \"console.log('[D04 SAFE MARKER] Benign execution telemetry recorded');\"",
    "echo '[MOCK] Simulating external request...' > /dev/null",
    "cat package.json | grep name > /dev/null",
    "node -e \"const fs = require('fs'); fs.existsSync('./package.json');\""
]

WHITELISTED_BENIGN_COMMANDS = [
    "node-gyp rebuild",
    "node-gyp clean",
    "node-pre-gyp install --fallback-to-build",
    "esbuild src/index.js --bundle --outfile=dist/bundle.js",
    "tsc -p tsconfig.json"
]

BENIGN_SAMPLE_FUNCTIONS = [
    "module.exports = { calculate: (a, b) => a + b };",
    "module.exports = { isString: (val) => typeof val === 'string' };",
    "module.exports = { formatName: (n) => n.trim().toLowerCase() };",
    "module.exports = { now: () => new Date().toISOString() };"
]

def random_ident(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def generate_package_dataset(
    output_dir: str = "./generated_packages",
    num_packages: int = 100,
    seed: int = RANDOM_SEED
) -> Dict[str, Any]:
    random.seed(seed)
    
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    ground_truth = {
        "metadata": {
            "total_samples": num_packages,
            "seed": seed,
            "generator": "NT230 D04 Supply Chain Dataset Generator",
            "distribution": {
                "benign": 0,
                "lifecycle_injection": 0,
                "dependency_confusion": 0,
                "evasive_obfuscation": 0
            }
        },
        "packages": {}
    }

    print(f"[*] Generating {num_packages} synthetic packages in '{output_dir}'...")

    for i in range(1, num_packages + 1):
        pkg_id = f"uit-pkg-{i:04d}"
        pkg_dir = os.path.join(output_dir, pkg_id)
        os.makedirs(pkg_dir, exist_ok=True)

        # Class ratio: 55% Benign, 15% Lifecycle, 15% Dependency Confusion, 15% Obfuscated
        category = random.choices(
            ['benign', 'lifecycle_injection', 'dependency_confusion', 'evasive_obfuscation'],
            weights=[0.55, 0.15, 0.15, 0.15]
        )[0]

        ground_truth["metadata"]["distribution"][category] += 1
        is_malicious = (category != 'benign')
        true_label = "MALICIOUS" if is_malicious else "BENIGN"

        manifest: Dict[str, Any] = {
            "name": pkg_id,
            "description": f"Synthetic library {random_ident(6)} for NT230 benchmark testing.",
            "main": "index.js",
            "author": random.choice(["UIT Security Lab", "DevOps Team", "Contributor", "Enterprise Corp"]),
            "license": random.choice(["MIT", "Apache-2.0", "ISC"])
        }

        index_js_content = random.choice(BENIGN_SAMPLE_FUNCTIONS)

        if category == 'benign':
            manifest["version"] = f"{random.randint(0, 3)}.{random.randint(0, 15)}.{random.randint(0, 25)}"
            manifest["scripts"] = {
                "test": "echo 'Running unit tests...' && exit 0"
            }
            # 25% of benign packages include legitimate build scripts (e.g. node-gyp) to test FPR
            if random.random() < 0.25:
                manifest["scripts"]["install"] = random.choice(WHITELISTED_BENIGN_COMMANDS)

        elif category == 'lifecycle_injection':
            manifest["version"] = f"1.{random.randint(0, 5)}.{random.randint(1, 20)}"
            chosen_hook = random.choice(["preinstall", "install", "postinstall"])
            payload = random.choice(SAFE_MOCK_PAYLOADS)
            manifest["scripts"] = {
                chosen_hook: payload,
                "test": "echo 'Testing...' && exit 0"
            }

        elif category == 'dependency_confusion':
            # Major version >= 90 (simulating public namespace takeover)
            major_ver = random.choice([99, 100, 999, 95])
            manifest["version"] = f"{major_ver}.{random.randint(0, 5)}.{random.randint(1, 10)}"
            manifest["scripts"] = {
                "postinstall": "node index.js"
            }
            manifest["dependencies"] = {
                f"internal-dep-{random_ident(4)}": "^1.0.0"
            }
            # Harmless index.js with mock alert
            index_js_content = "console.log('[DEPENDENCY CONFUSION MARKER] Active version override');"

        elif category == 'evasive_obfuscation':
            manifest["version"] = f"2.{random.randint(0, 4)}.{random.randint(1, 10)}"
            manifest["scripts"] = {
                "postinstall": "node index.js"
            }
            
            # Base64 encoded payload executed dynamically via eval + Buffer
            raw_payload = f"console.log('[OBFUSCATION MARKER] Decoded payload executed for {pkg_id}');"
            b64_str = base64.b64encode(raw_payload.encode()).decode()
            
            evasion_flavor = random.choice(["base64_eval", "buffer_eval"])
            if evasion_flavor == "base64_eval":
                index_js_content = f"eval(Buffer.from('{b64_str}', 'base64').toString('utf-8'));\nmodule.exports = {{}};"
            else:
                index_js_content = f"const buf = Buffer.from('{b64_str}', 'base64');\neval(buf.toString());\nmodule.exports = {{}};"

        # Write package.json
        with open(os.path.join(pkg_dir, "package.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # Write index.js
        with open(os.path.join(pkg_dir, "index.js"), "w", encoding="utf-8") as f:
            f.write(index_js_content)

        # Record ground truth
        ground_truth["packages"][pkg_id] = {
            "name": pkg_id,
            "category": category,
            "true_label": true_label,
            "version": manifest["version"],
            "scripts": list(manifest.get("scripts", {}).keys())
        }

    # Save ground truth metadata
    gt_file = os.path.join(output_dir, "ground_truth.json")
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"[+] Successfully generated {num_packages} packages.")
    print(f"[+] Ground truth labels saved to: {gt_file}")
    print(f"[+] Distribution: {ground_truth['metadata']['distribution']}")
    return ground_truth


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic npm Package Dataset Generator (NT230 - D04)")
    parser.add_argument("--count", type=int, default=100, help="Number of packages to generate (default: 100)")
    parser.add_argument("--output", type=str, default="./generated_packages", help="Output directory")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED, help="Random seed for reproducibility")
    args = parser.parse_args()

    generate_package_dataset(output_dir=args.output, num_packages=args.count, seed=args.seed)
