#!/usr/bin/env python3
"""
Simulate Artifact Hash Tampering (NT230 - Topic D04)
Demonstrates tampering with an npm package tarball (.tgz) after registration
and outputs dist/integrity_manifest.json for automated detector verification.
"""

import os
import json
import tarfile
import hashlib
import base64
import io

def calculate_sha512_integrity(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    digest = hashlib.sha512(data).digest()
    return "sha512-" + base64.b64encode(digest).decode("utf-8")

def build_tampered_artifact(base_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    clean_tarball = os.path.join(output_dir, "uit-marker-tamper-1.0.0.tgz")
    tampered_tarball = os.path.join(output_dir, "uit-marker-tamper-1.0.0-tampered.tgz")
    manifest_record = os.path.join(output_dir, "integrity_manifest.json")

    # 1. Build genuine tarball
    with tarfile.open(clean_tarball, "w:gz") as tar:
        tar.add(os.path.join(base_dir, "package.json"), arcname="package/package.json")
        tar.add(os.path.join(base_dir, "index.js"), arcname="package/index.js")

    clean_hash = calculate_sha512_integrity(clean_tarball)

    # 2. Build tampered tarball (injecting a tampered file post-build)
    tampered_index = (
        b"// Tampered code injected by supply chain adversary\n"
        b"console.log('[TAMPER DETECTED] Unauthorized code injection!');\n"
        b"module.exports = { calculateData: (x) => x * 999 };"
    )

    with tarfile.open(tampered_tarball, "w:gz") as tar:
        tar.add(os.path.join(base_dir, "package.json"), arcname="package/package.json")
        tarinfo = tarfile.TarInfo(name="package/index.js")
        tarinfo.size = len(tampered_index)
        tar.addfile(tarinfo, io.BytesIO(tampered_index))

    tampered_hash = calculate_sha512_integrity(tampered_tarball)

    # 3. Export integrity_manifest.json so detector.py & supply_chain_gate.py can audit automatically
    integrity_data = {
        "package_name": "uit-marker-tamper",
        "version": "1.0.0",
        "expected_integrity": clean_hash,
        "actual_tampered_integrity": tampered_hash,
        "artifact_tarball": "dist/uit-marker-tamper-1.0.0-tampered.tgz",
        "clean_tarball": "dist/uit-marker-tamper-1.0.0.tgz"
    }
    with open(manifest_record, "w", encoding="utf-8") as f:
        json.dump(integrity_data, f, indent=2)

    print("=" * 60)
    print("DEMO: ARTIFACT HASH TAMPERING SIMULATION (D04)")
    print("=" * 60)
    print(f"Genuine Artifact : {clean_tarball}")
    print(f"Genuine Integrity: {clean_hash}")
    print("-" * 60)
    print(f"Tampered Artifact: {tampered_tarball}")
    print(f"Tampered Integrity: {tampered_hash}")
    print(f"Integrity Record : {manifest_record}")
    print("-" * 60)
    if clean_hash != tampered_hash:
        print("[AUDIT SUCCESS] Integrity mismatch successfully demonstrated!")
        print("A secure supply chain detector or package manager will reject this package.")
    print("=" * 60)

    return integrity_data

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(current_dir, "dist")
    build_tampered_artifact(current_dir, dist_dir)
