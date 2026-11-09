#!/usr/bin/env python3
"""
scripts/detector.py
Multi-layer Supply Chain Security Detector for npm Packages.
Course: NT230 - Topic D04: Supply Chain Compromise

Architecture:
- Layer 1: Manifest & Dependency Graph Analysis (package.json metadata, lifecycle hooks,
           version anomalies, whitelist filtering, dependency graph anomalies, artifact hash integrity)
- Layer 2: Context-Aware Static Source Analysis (obfuscation, multi-line encoded eval,
           exfiltration endpoints, recon->exfil dataflows)
- Layer 3: Dynamic Behavioral Analysis (instrumented Node.js sandbox execution, API hooking,
           kill-chain correlation)
- Auxiliary: Artifact Hash & Integrity Verification (SHA-512 tarball validation)
"""

import os
import sys
import json
import re
import math
import hashlib
import base64
import tarfile
import tempfile
import shutil
import subprocess
import argparse
from typing import Dict, Any, List, Optional, Tuple, Set

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

EXTENDED_SANDBOX_HOOKS = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepare",
    "prepack",
    "postpack"
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

# High-risk command patterns inside lifecycle scripts (Layer 1)
SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"(curl|wget|fetch|nc|netcat)\s+", "Remote network egress tool invoked in script"),
    (r"(bash|sh|cmd\.exe|powershell)\s+-c", "External shell interpreter spawned"),
    (r"(base64\s+-d|base64\s+--decode)", "Shell-level Base64 payload decoding"),
    (r"eval\(Buffer\.from\(", "Inline dynamic Node.js Base64 execution"),
    (r">\s*/tmp/|>\s*C:\\Users\\Public\\", "Writing payload marker directly to OS public/temp paths"),
    (r"sleep\s+\d+|timeout\s+/t", "Suspicious sleep/delay evasion technique"),
]

# Standard Node.js core built-in modules (for Phantom Dependency checking)
NODE_BUILTIN_MODULES = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib"
}

# High-confidence dynamic evaluation & obfuscation patterns in JS source code (Layer 2)
SOURCE_CRITICAL_EXEC_PATTERNS = [
    (r"eval\s*\(\s*Buffer\.from\s*\(.*?(?:base64|hex)", "Inline dynamic evaluation of encoded Buffer"),
    (r"eval\s*\(\s*atob\s*\(", "Inline dynamic evaluation of Base64 atob() string"),
    (r"eval\s*\(\s*unescape\s*\(", "Obfuscated unescape dynamic evaluation"),
    (r"Atomics\.wait\s*\(", "Low-level synchronous thread sleep evasion"),
]

# Known malicious OAST / Exfiltration / Webhook endpoints & raw IP URLs (Layer 2)
MALICIOUS_EXFIL_ENDPOINT_REGEX = re.compile(
    r"(?:oastify\.com|burpcollaborator\.net|interact\.sh|interactsh\.com|webhook\.site|"
    r"pipedream\.net|requestbin\.|canarytokens\.com|dnslog\.cn|ceye\.io|ngrok\.io|"
    r"ngrok-free\.app|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|"
    r"transfer\.sh|https?://(?!(?:127\.0\.0\.1|0\.0\.0\.0|localhost)\b)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/)",
    re.IGNORECASE
)

# Dangerous shell commands when passed into child_process calls (Layer 2)
DANGEROUS_SHELL_ARG_REGEX = re.compile(
    r"\b(curl|wget|nc|netcat|ncat|bash|sh\s+-c|cmd(?:\.exe)?\s+/c|powershell|"
    r"whoami|uname|id\b|nslookup|dig\b|ping\s+-[nc]|base64\s+-d|chmod\s+\+x|/dev/tcp/|"
    r"/etc/passwd|/etc/shadow|\.npmrc|\.ssh)\b",
    re.IGNORECASE
)

# Sensitive host filesystem paths targeted directly in JS source code (Layer 2)
SENSITIVE_SOURCE_PATH_REGEX = re.compile(
    r"(['\"`])(?:/etc/(?:passwd|shadow|sudoers|crontab)|~/.ssh|/root/\.ssh|"
    r"[^'\"`\n]*\.npmrc|[^'\"`\n]*\.aws/credentials|/tmp/uit_marker|C:\\\\Users\\\\Public\\\\uit_marker)",
    re.IGNORECASE
)

# Keywords inside decoded Base64 strings that confirm executable/malicious payload vs benign asset
DECODED_PAYLOAD_INDICATORS = re.compile(
    r"\b(eval|Function|require|child_process|exec|execSync|spawn|fork|process\.env|"
    r"Buffer\.from|console\.log|http://|https://|curl|wget|bash|/bin/sh|powershell|"
    r"whoami|hostname|userInfo|/etc/passwd|\.npmrc|/tmp/)\b",
    re.IGNORECASE
)

# Tokens indicating a JS file may interact with runtime APIs or dynamic execution in Layer 3
RUNTIME_CAPABLE_JS_TOKENS = re.compile(
    r"\b(require|import|eval|Function|process|global|globalThis|window|document|self|"
    r"fetch|XMLHttpRequest|WebSocket|Buffer|atob|setTimeout|setInterval|Atomics|"
    r"Reflect|Proxy|constructor)\b|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\[\s*['\"`]"
)

# Threshold for dependency confusion version anomaly
SUSPICIOUS_VERSION_THRESHOLD = 90.0

# Module-level cache for sandbox telemetry to avoid redundant process spawns across passes
_SANDBOX_TELEMETRY_CACHE: Dict[str, List[Dict[str, Any]]] = {}
_NODE_PERMISSION_FLAGS: Optional[List[str]] = None


def _get_node_permission_flags() -> List[str]:
    """Detects once whether the local Node.js runtime supports --experimental-permission."""
    global _NODE_PERMISSION_FLAGS
    if _NODE_PERMISSION_FLAGS is not None:
        return _NODE_PERMISSION_FLAGS
    try:
        res = subprocess.run(
            ["node", "--no-warnings", "--experimental-permission", "--allow-fs-read=*", "-e", ""],
            capture_output=True,
            timeout=3
        )
        if res.returncode == 0:
            _NODE_PERMISSION_FLAGS = ["--no-warnings", "--experimental-permission", "--allow-fs-read=*"]
        else:
            _NODE_PERMISSION_FLAGS = ["--no-warnings"]
    except Exception:
        _NODE_PERMISSION_FLAGS = ["--no-warnings"]
    return _NODE_PERMISSION_FLAGS


def verify_artifact_integrity(tarball_path: str, expected_sha512: str) -> Dict[str, Any]:
    """Auxiliary & automated check: verifies artifact integrity against expected SHA-512."""
    if not os.path.exists(tarball_path):
        return {
            "status": "FAIL",
            "reason": f"Artifact file not found: {tarball_path}",
            "tarball": tarball_path,
            "expected_hash": expected_sha512,
            "actual_hash": None,
            "matched": False
        }

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


class SupplyChainDetector:
    """
    3-Layer Security Detector inspecting npm packages for supply chain threats:
    - Layer 1: Lifecycle Script Injection (T1195.002), Dependency Confusion,
               Dependency Graph Anomaly Analysis, & Artifact Hash Integrity
    - Layer 2: Context-Aware Static Source Analysis (Obfuscation, Exfiltration Sinks, Decoded Payloads)
    - Layer 3: Dynamic Runtime Behavioral Interception (Node.js API-Hooking Sandbox)
    """

    def __init__(self, enable_whitelist: bool = True, risk_threshold: int = 35):
        self.enable_whitelist = enable_whitelist
        self.risk_threshold = risk_threshold
        self.sandbox_runner_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "sandbox_runner.js"
        )

    def _is_whitelisted_command(self, command: str) -> bool:
        if not self.enable_whitelist:
            return False
        for wl_pattern in WHITELISTED_HOOK_COMMANDS:
            if re.search(wl_pattern, command, re.IGNORECASE):
                return True
        return False

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect heavily obfuscated / high-entropy code."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def analyze_manifest(self, pkg_path: str, data: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 1A: Manifest Analysis (package.json).
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
                    whitelisted = self._is_whitelisted_command(command)

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

    def analyze_dependency_graph(
        self, pkg_dir: str, manifest: Dict[str, Any]
    ) -> Tuple[int, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Layer 1B: Dependency Graph & Graph Feature Analysis.
        Extracts direct and transitive dependencies from package.json & package-lock.json,
        constructs graph topology metadata, and detects structural supply chain anomalies:
        1. Unscoped Internal Dependency Risk / Version Pinning Anomaly (+35 HIGH)
        2. Non-Registry / Untrusted Dependency Source (+40 HIGH)
        3. Circular / Self-Dependency Loop (+30 MEDIUM)
        4. Phantom / Undeclared Dependency Usage (+20 MEDIUM)
        """
        score = 0
        findings = []
        pkg_name = str(manifest.get("name", os.path.basename(pkg_dir))).strip()

        dep_fields = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
        direct_deps: Dict[str, str] = {}
        edges: List[Dict[str, str]] = []

        for field in dep_fields:
            field_data = manifest.get(field, {})
            if isinstance(field_data, dict):
                for dep_name, ver_spec in field_data.items():
                    dep_str = str(dep_name).strip()
                    spec_str = str(ver_spec).strip()
                    direct_deps[dep_str] = spec_str
                    edges.append({
                        "from": pkg_name,
                        "to": dep_str,
                        "version_spec": spec_str,
                        "scope": field
                    })

        # Parse package-lock.json if present to extract transitive graph features
        lockfile_path = os.path.join(pkg_dir, "package-lock.json")
        has_lockfile = os.path.isfile(lockfile_path)
        transitive_count = 0
        estimated_depth = 1 if direct_deps else 0
        has_lock_cycle = False

        if has_lockfile:
            try:
                with open(lockfile_path, "r", encoding="utf-8", errors="ignore") as lf:
                    lock_data = json.load(lf)
                lock_pkgs = lock_data.get("packages", {}) or lock_data.get("dependencies", {})
                if isinstance(lock_pkgs, dict):
                    for k, v in lock_pkgs.items():
                        if not k:
                            continue
                        clean_node = k.split("node_modules/")[-1]
                        depth = k.count("node_modules/")
                        if depth > estimated_depth:
                            estimated_depth = depth
                        if clean_node not in direct_deps and clean_node != pkg_name:
                            transitive_count += 1
                        if isinstance(v, dict):
                            sub_deps = v.get("dependencies", {})
                            if isinstance(sub_deps, dict):
                                if pkg_name in sub_deps or clean_node in sub_deps:
                                    has_lock_cycle = True
                                for sub_d, sub_v in list(sub_deps.items())[:20]:
                                    edges.append({
                                        "from": clean_node,
                                        "to": str(sub_d),
                                        "version_spec": str(sub_v),
                                        "scope": "transitive"
                                    })
            except Exception:
                pass

        # Rule 1: Unscoped Internal Dependency Risk / Version Pinning Anomaly (+35 HIGH)
        internal_prefix_re = re.compile(r"^(?:internal-|corp-|private-|uit-|intranet-|company-)", re.IGNORECASE)
        unscoped_anomalies = []
        for dep_name, spec in direct_deps.items():
            is_unscoped_internal = (not dep_name.startswith("@")) and bool(internal_prefix_re.search(dep_name))
            # Extract numeric major version if present in spec (e.g. "^99.0.0" -> 99)
            ver_nums = re.findall(r"\d+", spec)
            high_major = (float(ver_nums[0]) >= SUSPICIOUS_VERSION_THRESHOLD) if ver_nums else False
            wildcard_pin = spec in ("*", "latest", "x", "X")

            if (is_unscoped_internal and (high_major or wildcard_pin)) or high_major:
                unscoped_anomalies.append(f"{dep_name}@{spec}")

        if unscoped_anomalies:
            score += 35
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Unscoped Internal Dependency / Version Pinning Anomaly",
                "severity": "HIGH",
                "detail": f"Suspicious unscoped internal or high-version dependency edge(s): {', '.join(unscoped_anomalies[:3])}"
            })

        # Rule 2: Non-Registry / Untrusted Dependency Source (+40 HIGH)
        untrusted_source_re = re.compile(
            r"^(?:https?://|git\+|git://|ssh://|github:|bitbucket:|gitlab:|file:\.\./)",
            re.IGNORECASE
        )
        untrusted_deps = []
        for dep_name, spec in direct_deps.items():
            if untrusted_source_re.search(spec) or spec.endswith((".tgz", ".tar.gz")):
                untrusted_deps.append(f"{dep_name} -> {spec}")

        if untrusted_deps:
            score += 40
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Non-Registry / Untrusted Dependency Source",
                "severity": "HIGH",
                "detail": f"Dependency resolves from untrusted external URL/path instead of registry semver: {', '.join(untrusted_deps[:3])}"
            })

        # Rule 3: Circular / Self-Dependency Loop (+30 MEDIUM)
        if pkg_name in direct_deps or has_lock_cycle:
            score += 30
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Circular / Self-Dependency Loop",
                "severity": "MEDIUM",
                "detail": f"Package '{pkg_name}' introduces a self-dependency or circular dependency cycle in graph."
            })

        # Rule 4: Phantom / Undeclared Dependency Usage (+20 MEDIUM)
        suspicious_phantom_libs = {
            "axios", "node-fetch", "got", "request", "superagent", "undici", "ws",
            "shelljs", "execa", "cross-spawn", "socket.io-client", "discord.js", "telegraf"
        }
        phantom_found: Set[str] = set()
        for root, _, files in os.walk(pkg_dir):
            if "node_modules" in root or ".git" in root:
                continue
            for file in files:
                if not file.endswith((".js", ".cjs", ".mjs")):
                    continue
                rel_p = os.path.relpath(os.path.join(root, file), pkg_dir).replace("\\", "/")
                if rel_p.startswith(("test/", "tests/", "__tests__/", "spec/", "dist/", "umd/", "build/")):
                    continue
                if rel_p.endswith((".min.js", ".test.js", ".spec.js")):
                    continue
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        js_text = f.read(256 * 1024)
                except Exception:
                    continue
                for req_match in re.finditer(r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", js_text):
                    req_raw = req_match.group(1).strip()
                    if not req_raw or req_raw.startswith((".", "/", "\\", "node:", "http:", "https:")):
                        continue
                    base_pkg = "/".join(req_raw.split("/")[:2]) if req_raw.startswith("@") else req_raw.split("/")[0]
                    if base_pkg in NODE_BUILTIN_MODULES or base_pkg in direct_deps or base_pkg == pkg_name:
                        continue
                    if base_pkg in suspicious_phantom_libs or base_pkg.startswith(("phantom-", "hidden-", "evil-", "unlisted-")):
                        phantom_found.add(base_pkg)

        if phantom_found:
            score += 20
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Phantom / Undeclared Dependency Usage",
                "severity": "MEDIUM",
                "detail": f"Source code imports high-risk external module(s) omitted from package.json: {', '.join(sorted(phantom_found))}"
            })

        graph_metadata = {
            "root_package": pkg_name,
            "direct_dependencies_count": len(direct_deps),
            "transitive_dependencies_count": transitive_count,
            "total_nodes": 1 + len(direct_deps) + transitive_count,
            "estimated_depth": estimated_depth,
            "has_lockfile": has_lockfile,
            "anomalies_detected": len(findings),
            "edges": edges[:30]
        }

        return score, findings, graph_metadata

    def analyze_artifact_integrity(
        self,
        pkg_dir: str,
        manifest: Dict[str, Any],
        tarball_path: Optional[str] = None,
        expected_sha512: Optional[str] = None
    ) -> Tuple[int, List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Layer 1C: Automated Artifact Hash & Integrity Verification.
        Checks package tarball (.tgz) SHA-512 against expected integrity hash from:
        - CLI arguments (--tarball / --expected-hash),
        - dist/integrity_manifest.json (PoC tamper simulation record), or
        - package.json dist.integrity metadata.
        """
        score = 0
        findings = []
        resolved_tarball = tarball_path
        resolved_expected = expected_sha512

        # 1. Check integrity_manifest.json inside pkg_dir or pkg_dir/dist/
        if not resolved_tarball or not resolved_expected:
            candidate_manifests = [
                os.path.join(pkg_dir, "dist", "integrity_manifest.json"),
                os.path.join(pkg_dir, "integrity_manifest.json")
            ]
            for cand in candidate_manifests:
                if os.path.isfile(cand):
                    try:
                        with open(cand, "r", encoding="utf-8") as f:
                            im_data = json.load(f)
                        if not resolved_expected:
                            resolved_expected = im_data.get("expected_integrity")
                        if not resolved_tarball and im_data.get("artifact_tarball"):
                            rel_t = im_data["artifact_tarball"]
                            resolved_tarball = os.path.join(pkg_dir, rel_t) if not os.path.isabs(rel_t) else rel_t
                        break
                    except Exception:
                        pass

        # 2. Check package.json dist.integrity field
        if not resolved_expected:
            dist_obj = manifest.get("dist", {})
            if isinstance(dist_obj, dict) and dist_obj.get("integrity"):
                resolved_expected = str(dist_obj["integrity"]).strip()
                if not resolved_tarball and dist_obj.get("local_tarball"):
                    lt = str(dist_obj["local_tarball"])
                    resolved_tarball = os.path.join(pkg_dir, lt) if not os.path.isabs(lt) else lt

        if not resolved_tarball or not resolved_expected:
            return 0, [], None

        integrity_res = verify_artifact_integrity(resolved_tarball, resolved_expected)
        if not integrity_res.get("matched", False):
            score += 50
            findings.append({
                "layer": "Layer 1 - Integrity",
                "rule": "Artifact Hash Tampering Detected",
                "severity": "CRITICAL",
                "detail": (
                    f"SHA-512 mismatch on '{os.path.basename(resolved_tarball)}': "
                    f"expected {resolved_expected[:28]}..., got {str(integrity_res.get('actual_hash'))[:28]}..."
                )
            })
        else:
            findings.append({
                "layer": "Layer 1 - Integrity",
                "rule": "Artifact Integrity Verified",
                "severity": "INFO",
                "detail": f"Tarball '{os.path.basename(resolved_tarball)}' matches expected SHA-512 hash."
            })

        return score, findings, integrity_res

    def _is_likely_minified_or_dist(self, rel_path: str, content: str) -> bool:
        """
        Determines whether a JS file is a standard minified/bundled distribution asset
        (e.g. dist/*.min.js, Rollup/Webpack/Babel bundle) to avoid false-positive entropy alerts.
        """
        norm_rel = rel_path.replace("\\", "/").lower()
        if norm_rel.endswith((".min.js", ".bundle.js", ".prod.js", ".umd.js")):
            return True
        if norm_rel.startswith(("dist/", "umd/", "bundles/", "cjs/", "esm/", "build/")):
            return True
        if "sourceMappingURL=" in content or "__webpack_require__" in content or "Object.defineProperty(exports," in content:
            return True
        return False

    def _inspect_encoded_strings(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        Inspects Base64 string literals in source code with semantic verification:
        - Filters out harmless SVG/font data URIs, sourcemaps, and URL/module file paths.
        - Flags strings that either decode into executable code/commands/URLs OR are paired
          with Buffer.from(..., 'base64') / atob() decoding in the same file.
        """
        has_explicit_b64_decoder = bool(
            re.search(r"Buffer\.from\s*\([^)]*['\"]base64['\"]|\batob\s*\(", content, re.IGNORECASE)
        )

        for match in re.finditer(r"(['\"])([A-Za-z0-9+/=]{32,})\1", content):
            candidate = match.group(2)
            start_pos = max(0, match.start() - 40)
            prefix = content[start_pos:match.start()].lower()

            # Ignore harmless data URIs (fonts, images, SVGs, sourcemaps)
            if any(tag in prefix for tag in ("data:image/", "data:font/", "data:application/", "sourcemappingurl", " integrity", "sha512-")):
                continue

            # Ignore strings that look like module/file paths (contain '/' without '+' or '=' padding)
            if "/" in candidate and "+" not in candidate and not candidate.endswith("="):
                continue

            # Ignore strings whose length is not a valid multiple of 4 unless explicitly decoded
            if len(candidate) % 4 != 0 and not has_explicit_b64_decoder:
                continue

            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if DECODED_PAYLOAD_INDICATORS.search(decoded_text):
                    preview = re.sub(r"\s+", " ", decoded_text).strip()[:80]
                    return True, f"Decoded Base64 payload contains executable indicator: '{preview}'"
            except Exception:
                pass

            if has_explicit_b64_decoder and len(candidate) >= 40:
                return True, f"Base64 string literal ({len(candidate)} chars) paired with runtime Base64 decoder"

        return False, None

    def analyze_source_code(self, pkg_dir: str) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 2: Context-Aware Static Source Code Analysis.
        Scans JavaScript files for obfuscation, multi-line encoded evaluation, malicious
        exfiltration endpoints, credential/recon-to-network flows, and shell execution.
        Scores are deduplicated at the package level to prevent multi-file FP inflation.
        """
        findings = []
        triggered_rules: Dict[str, Tuple[int, str, str, str]] = {}

        def record_l2(rule_key: str, points: int, rule_name: str, severity: str, detail: str):
            if rule_key not in triggered_rules or points > triggered_rules[rule_key][0]:
                triggered_rules[rule_key] = (points, rule_name, severity, detail)

        js_files = []
        for root, _, files in os.walk(pkg_dir):
            if "node_modules" in root or ".git" in root:
                continue
            for file in files:
                if file.endswith((".js", ".cjs", ".mjs")):
                    rel_f = os.path.relpath(os.path.join(root, file), pkg_dir).replace("\\", "/")
                    # Skip unit test files to avoid false alarms on test mocks
                    if rel_f.startswith(("test/", "tests/", "__tests__/", "spec/")):
                        continue
                    if re.search(r"\.(test|spec)\.(js|cjs|mjs)$", rel_f, re.IGNORECASE):
                        continue
                    js_files.append(os.path.join(root, file))

        for file_path in js_files:
            rel_path = os.path.relpath(file_path, pkg_dir)
            try:
                # Limit static scan to first 1 MB per file to keep scanning fast on huge bundles
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(1024 * 1024)
            except Exception:
                continue

            if not content:
                continue

            is_minified = self._is_likely_minified_or_dist(rel_path, content)

            # 1. Critical inline dynamic evaluation patterns (+45 CRITICAL)
            for pattern, desc in SOURCE_CRITICAL_EXEC_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    record_l2(
                        "inline_encoded_eval",
                        45,
                        "Obfuscation / Dynamic Exec Pattern",
                        "CRITICAL",
                        f"{desc} detected in {rel_path}"
                    )

            # 2. Multi-statement Buffer/Base64/Hex decode combined with eval() or new Function() (+45 CRITICAL)
            has_buffer_decode = bool(
                re.search(r"Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]\s*\)|\batob\s*\(", content, re.IGNORECASE)
            )
            # Exclude benign `new Function("return this")` globalThis polyfill in bundlers
            content_no_polyfill = re.sub(
                r"new\s+Function\s*\(\s*['\"]return\s+this['\"]\s*\)", "", content
            )
            has_dynamic_eval = bool(
                re.search(r"\beval\s*\(|new\s+Function\s*\(", content_no_polyfill)
            )
            if has_buffer_decode and has_dynamic_eval:
                record_l2(
                    "inline_encoded_eval",
                    45,
                    "Obfuscation / Dynamic Exec Pattern",
                    "CRITICAL",
                    f"Decoded Buffer/Base64 payload passed to dynamic eval/Function in {rel_path}"
                )

            # 3. Known Malicious Exfiltration / OAST / Webhook / Raw IP Endpoints (+50 CRITICAL)
            exfil_match = MALICIOUS_EXFIL_ENDPOINT_REGEX.search(content)
            if exfil_match:
                record_l2(
                    "malicious_exfil_endpoint",
                    50,
                    "Suspicious Exfiltration Endpoint",
                    "CRITICAL",
                    f"Hardcoded external exfiltration/OAST endpoint '{exfil_match.group(0)}' in {rel_path}"
                )

            # 4. Static Host/Credential Fingerprinting + Network/DNS Exfiltration in same file (+45 CRITICAL)
            has_host_recon = bool(
                re.search(r"\bos\.(?:userInfo|hostname|networkInterfaces)\s*\(|\bdns\.getServers\s*\(", content)
            )
            has_net_sink = bool(
                re.search(
                    r"\b(?:https?|http2)\.(?:request|get)\s*\(|\bdns\.(?:lookup|resolve\w*)\s*\(|\bfetch\s*\(|\bnet\.(?:connect|createConnection)\s*\(",
                    content
                )
            )
            if has_host_recon and has_net_sink and not is_minified:
                record_l2(
                    "static_recon_exfil_flow",
                    45,
                    "Host Fingerprinting & Exfiltration Flow",
                    "CRITICAL",
                    f"File {rel_path} combines OS host fingerprinting (userInfo/hostname) with outbound network/DNS calls"
                )

            # 5. Context-aware child_process inspection
            has_cp_import = bool(
                re.search(r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)|from\s+['\"](?:node:)?child_process['\"]", content)
            )
            if has_cp_import and re.search(r"\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(", content):
                if DANGEROUS_SHELL_ARG_REGEX.search(content) or has_buffer_decode or has_dynamic_eval:
                    record_l2(
                        "child_process_high",
                        45,
                        "Obfuscation / Dynamic Exec Pattern",
                        "CRITICAL",
                        f"High-risk OS child_process execution with shell/encoded payload in {rel_path}"
                    )
                elif not is_minified and len(js_files) <= 3:
                    # Standalone small package directly invoking child_process
                    record_l2(
                        "child_process_low",
                        20,
                        "Direct Child Process Invocation",
                        "MEDIUM",
                        f"Direct child_process invocation in small package file {rel_path}"
                    )

            # 6. Heavy Obfuscation Signatures (_0x obfuscator arrays, dense hex escapes, fromCharCode chains) (+40 HIGH)
            obf_vars = len(re.findall(r"\b_0x[a-fA-F0-9]{4,}\b", content))
            hex_escapes = bool(re.search(r"(?:\\x[0-9a-fA-F]{2}){10,}", content))
            charcode_chain = bool(re.search(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){8,}", content))
            if obf_vars >= 5 or hex_escapes or charcode_chain:
                record_l2(
                    "heavy_js_obfuscation",
                    40,
                    "Obfuscation / Dynamic Exec Pattern",
                    "HIGH",
                    f"Heavy JS obfuscation signature (_0x/hex-escape/fromCharCode) detected in {rel_path}"
                )

            # 7. Sensitive Host Path / Marker Targeting (+40 HIGH)
            path_match = SENSITIVE_SOURCE_PATH_REGEX.search(content)
            if path_match:
                record_l2(
                    "sensitive_host_path",
                    40,
                    "Sensitive Host Path Targeting",
                    "HIGH",
                    f"Direct reference to sensitive OS path in {rel_path}: {path_match.group(0)}"
                )

            # 8. Semantically Verified Base64 Payload Artifact (+25 HIGH)
            b64_flagged, b64_detail = self._inspect_encoded_strings(content)
            if b64_flagged and b64_detail:
                record_l2(
                    "verified_b64_artifact",
                    25,
                    "Long Encoded String Artifact",
                    "HIGH",
                    f"{b64_detail} in {rel_path}"
                )

            # 9. Context-aware Shannon Entropy (only on non-minified source or extreme >6.15 entropy) (+15 MEDIUM)
            entropy = self.calculate_entropy(content)
            if len(content) > 200:
                if (not is_minified and entropy > 5.65) or entropy > 6.15:
                    record_l2(
                        "high_entropy_source",
                        15,
                        "High Entropy Code Section",
                        "MEDIUM",
                        f"Entropy of {rel_path} is {entropy:.2f} (packed/obfuscated indicator)"
                    )

        total_l2_score = 0
        for pts, rule_name, severity, detail in triggered_rules.values():
            total_l2_score += pts
            findings.append({
                "layer": "Layer 2 - Source Code",
                "rule": rule_name,
                "severity": severity,
                "detail": detail
            })

        return total_l2_score, findings

    def _collect_sandbox_targets(self, pkg_dir: str, manifest: Dict[str, Any]) -> Tuple[Dict[str, str], List[str]]:
        """
        Identifies active lifecycle hooks and entrypoint JS files to execute inside the Layer 3 sandbox.
        """
        active_hooks: Dict[str, str] = {}
        target_files: List[str] = []

        def add_file_if_valid(rel_or_abs: str, from_hook: bool = False):
            clean_rel = rel_or_abs.strip().strip("'\"")
            full_p = os.path.normpath(os.path.join(pkg_dir, clean_rel))
            if not os.path.isfile(full_p):
                return
            # Avoid running unit test suites of benign packages
            rel_norm = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
            if not from_hook:
                if rel_norm.startswith(("test/", "tests/", "__tests__/", "spec/", "example/", "examples/")):
                    return
                if re.search(r"\.(test|spec)\.(js|cjs|mjs)$", rel_norm, re.IGNORECASE):
                    return
                # Skip huge bundled compiler files (> 512 KB) unless explicitly invoked by a lifecycle hook
                try:
                    if os.path.getsize(full_p) > 512 * 1024:
                        return
                except OSError:
                    return
            if rel_norm not in target_files:
                target_files.append(rel_norm)

        scripts = manifest.get("scripts", {})
        if isinstance(scripts, dict):
            for hook in EXTENDED_SANDBOX_HOOKS:
                if hook in scripts:
                    cmd = str(scripts[hook]).strip()
                    if not cmd or self._is_whitelisted_command(cmd):
                        continue
                    active_hooks[hook] = cmd
                    # Extract any .js file invoked via `node <script.js>` inside the lifecycle hook
                    for match in re.finditer(r"\bnode\s+([^\s'\";&|>-]+\.(?:js|cjs|mjs))", cmd):
                        add_file_if_valid(match.group(1), from_hook=True)

        # Check package.json "main" entrypoint
        main_entry = manifest.get("main")
        if isinstance(main_entry, str) and main_entry.strip():
            main_str = main_entry.strip()
            if not main_str.endswith((".js", ".cjs", ".mjs")):
                if os.path.isfile(os.path.join(pkg_dir, main_str + ".js")):
                    main_str += ".js"
                elif os.path.isfile(os.path.join(pkg_dir, main_str, "index.js")):
                    main_str = os.path.join(main_str, "index.js")
            add_file_if_valid(main_str)

        # Always check default root index.js
        add_file_if_valid("index.js")

        # If still no target files found, inspect up to 3 root/non-test JS files
        if not target_files:
            for root, _, files in os.walk(pkg_dir):
                if "node_modules" in root or ".git" in root:
                    continue
                for f in sorted(files):
                    if f.endswith((".js", ".cjs")):
                        add_file_if_valid(os.path.join(root, f))
                        if len(target_files) >= 3:
                            break
                if len(target_files) >= 3:
                    break

        return active_hooks, target_files

    def _should_spawn_sandbox(self, pkg_dir: str, active_hooks: Dict[str, str], target_files: List[str]) -> bool:
        """
        Checks whether the package has active hooks or JS files capable of runtime API calls.
        Avoids spawning a subprocess for trivial pure-math/string leaf files.
        """
        if active_hooks:
            return True
        for rel_file in target_files:
            full_p = os.path.join(pkg_dir, rel_file)
            try:
                with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if RUNTIME_CAPABLE_JS_TOKENS.search(content):
                    return True
            except Exception:
                continue
        return False

    def _run_node_sandbox(self, pkg_dir: str, active_hooks: Dict[str, str], target_files: List[str]) -> List[Dict[str, Any]]:
        """
        Executes scripts/sandbox_runner.js in an isolated Node.js process with permission restrictions.
        """
        cache_key = json.dumps({
            "pkg": os.path.abspath(pkg_dir),
            "hooks": active_hooks,
            "files": target_files
        }, sort_keys=True)

        if cache_key in _SANDBOX_TELEMETRY_CACHE:
            return _SANDBOX_TELEMETRY_CACHE[cache_key]

        if not os.path.exists(self.sandbox_runner_path) or not self._should_spawn_sandbox(pkg_dir, active_hooks, target_files):
            _SANDBOX_TELEMETRY_CACHE[cache_key] = []
            return []

        payload_json = json.dumps({
            "hooks": active_hooks,
            "files": target_files
        })

        cmd = ["node"] + _get_node_permission_flags() + [
            self.sandbox_runner_path,
            os.path.abspath(pkg_dir),
            payload_json
        ]

        events: List[Dict[str, Any]] = []
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=2.0
            )
            stdout_lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
            if stdout_lines:
                last_line = stdout_lines[-1]
                data = json.loads(last_line)
                events = data.get("events", [])
        except subprocess.TimeoutExpired:
            events = [{
                "category": "SANDBOX_EVASION",
                "api": "sandbox.timeout",
                "detail": "Package execution timed out (>2.0s) in behavioral sandbox (infinite loop / stall evasion).",
                "severity": "HIGH"
            }]
        except Exception:
            events = []

        _SANDBOX_TELEMETRY_CACHE[cache_key] = events
        return events

    def analyze_behavioral_sandbox(self, pkg_dir: str, manifest: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 3: Dynamic / Behavioral Sandbox Analysis.
        Executes lifecycle hooks and package entrypoints inside an instrumented Node.js sandbox
        (scripts/sandbox_runner.js) to intercept runtime network egress, DNS exfiltration,
        child process spawning, sensitive filesystem tampering, credential harvesting, and dynamic eval.
        """
        score = 0
        findings = []

        active_hooks, target_files = self._collect_sandbox_targets(pkg_dir, manifest)
        events = self._run_node_sandbox(pkg_dir, active_hooks, target_files)

        if not events:
            return 0, []

        # Group events by behavioral category
        by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            cat = ev.get("category", "UNKNOWN")
            by_cat.setdefault(cat, []).append(ev)

        # 1. Outbound Network Egress / DNS Exfiltration / Raw Socket Connect (+45 CRITICAL)
        net_events = (
            by_cat.get("NETWORK_EGRESS", []) +
            by_cat.get("DNS_EXFILTRATION", []) +
            by_cat.get("RAW_SOCKET_CONNECT", [])
        )
        if net_events:
            score += 45
            sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in net_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Network / DNS Exfiltration",
                "severity": "CRITICAL",
                "detail": f"Intercepted {len(net_events)} outbound network/DNS operation(s) in sandbox ({sample_details})"
            })

        # 2. Child Process / OS Shell Execution (+45 CRITICAL)
        proc_events = by_cat.get("CHILD_PROCESS_SPAWN", [])
        if proc_events:
            score += 45
            sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in proc_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Child Process / Shell Spawn",
                "severity": "CRITICAL",
                "detail": f"Intercepted {len(proc_events)} OS child process spawn(s) in sandbox ({sample_details})"
            })

        # 3. External Filesystem Write / Sensitive File Access (+40 CRITICAL)
        fs_events = by_cat.get("FS_EXTERNAL_WRITE", []) + by_cat.get("FS_SENSITIVE_READ", [])
        if fs_events:
            score += 40
            sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in fs_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Filesystem Boundary Violation",
                "severity": "CRITICAL",
                "detail": f"Intercepted {len(fs_events)} sensitive/external file operation(s) in sandbox ({sample_details})"
            })

        # 4. Runtime Dynamic Code Evaluation (+40 HIGH)
        eval_events = by_cat.get("RUNTIME_DYNAMIC_EVAL", [])
        if eval_events:
            score += 40
            sample_details = "; ".join([e["detail"] for e in eval_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Dynamic Code Evaluation",
                "severity": "HIGH",
                "detail": f"Intercepted runtime dynamic code execution ({sample_details})"
            })

        # 5. Credential / Environment Variable Harvesting (+35 HIGH)
        env_events = by_cat.get("ENV_HARVESTING", [])
        if env_events:
            score += 35
            sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in env_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Credential / Environment Harvesting",
                "severity": "HIGH",
                "detail": f"Package harvested sensitive environment variables in sandbox ({sample_details})"
            })

        # 6. Host Identity Fingerprinting (os.userInfo, networkInterfaces, hostname, homedir)
        os_events = by_cat.get("OS_FINGERPRINTING", [])
        if os_events:
            high_risk_os = any(
                e.get("api") in ("os.userInfo", "os.networkInterfaces", "dns.getServers") or
                str(e.get("api", "")).startswith("shell:")
                for e in os_events
            )
            distinct_os_apis = {e.get("api") for e in os_events}
            if high_risk_os or len(distinct_os_apis) >= 2:
                score += 25
                apis_str = ", ".join(sorted(distinct_os_apis))
                findings.append({
                    "layer": "Layer 3 - Behavioral Sandbox",
                    "rule": "Runtime Host Identity Fingerprinting",
                    "severity": "HIGH",
                    "detail": f"Package collected host identity telemetry via [{apis_str}]"
                })
            else:
                score += 10
                apis_str = ", ".join(sorted(distinct_os_apis))
                findings.append({
                    "layer": "Layer 3 - Behavioral Sandbox",
                    "rule": "Runtime Host Recon Query",
                    "severity": "LOW",
                    "detail": f"Package queried host property via [{apis_str}]"
                })

        # 7. Sandbox Evasion / Delay / Time-Bomb (+35 HIGH)
        evasion_events = by_cat.get("SANDBOX_EVASION", [])
        if evasion_events:
            score += 35
            sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in evasion_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Sleep / Delay / Sandbox Evasion Detected",
                "severity": "HIGH",
                "detail": f"Intercepted sandbox evasion behavior ({sample_details})"
            })

        # 8. Stealth Output Suppression (+15 MEDIUM)
        stealth_events = by_cat.get("STEALTH_EXECUTION", [])
        if stealth_events:
            score += 15
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Output Redirection / Stealth Execution",
                "severity": "MEDIUM",
                "detail": stealth_events[0]["detail"]
            })

        # 9. Multi-Stage Behavioral Kill-Chain Correlation (Recon/Harvest -> Exfil/Exec) (+30 CRITICAL)
        has_recon = bool(os_events or env_events or by_cat.get("FS_SENSITIVE_READ"))
        has_exfil = bool(net_events or proc_events or by_cat.get("FS_EXTERNAL_WRITE"))
        if has_recon and has_exfil:
            score += 30
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Behavioral Exfiltration Kill-Chain",
                "severity": "CRITICAL",
                "detail": "Correlated multi-stage behavior: Host/Credential Reconnaissance followed by External Exfiltration/Execution."
            })

        return score, findings

    def scan_package(
        self,
        pkg_dir: str,
        tarball_path: Optional[str] = None,
        expected_sha512: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs all detection layers (Manifest, Dependency Graph, Integrity, Static Source, Behavioral Sandbox)
        on a target package directory or tarball (.tgz). Returns a structured telemetry dictionary.
        """
        temp_extract_dir = None
        actual_pkg_dir = pkg_dir

        # Allow passing a .tgz tarball directly to scan_package
        if os.path.isfile(pkg_dir) and pkg_dir.endswith((".tgz", ".tar.gz")):
            if not tarball_path:
                tarball_path = pkg_dir
            temp_extract_dir = tempfile.mkdtemp(prefix="d04_scan_")
            try:
                with tarfile.open(pkg_dir, "r:gz") as tar:
                    safe_members = [
                        m for m in tar.getmembers()
                        if (m.isfile() or m.isdir()) and not m.name.startswith("/") and ".." not in m.name.split("/")
                    ]
                    tar.extractall(temp_extract_dir, members=safe_members)
                extracted_sub = os.path.join(temp_extract_dir, "package")
                actual_pkg_dir = extracted_sub if os.path.isdir(extracted_sub) else temp_extract_dir
            except Exception as e:
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
                return {
                    "package_path": pkg_dir,
                    "error": f"Failed to extract tarball: {str(e)}",
                    "verdict": "ERROR",
                    "risk_score": 0,
                    "findings": []
                }

        try:
            pkg_json_path = os.path.join(actual_pkg_dir, "package.json")
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

            package_name = manifest_data.get("name", os.path.basename(actual_pkg_dir))
            version = manifest_data.get("version", "unknown")

            total_score = 0
            all_findings = []

            # Layer 1A: Manifest Analysis
            l1_manifest_score, l1_findings = self.analyze_manifest(actual_pkg_dir, manifest_data)
            all_findings.extend(l1_findings)

            # Layer 1B: Dependency Graph Analysis
            l1_graph_score, graph_findings, graph_metadata = self.analyze_dependency_graph(actual_pkg_dir, manifest_data)
            all_findings.extend(graph_findings)

            # Layer 1C: Artifact Hash & Integrity Verification
            l1_integrity_score, integrity_findings, integrity_report = self.analyze_artifact_integrity(
                actual_pkg_dir, manifest_data, tarball_path=tarball_path, expected_sha512=expected_sha512
            )
            all_findings.extend(integrity_findings)

            l1_total_score = l1_manifest_score + l1_graph_score + l1_integrity_score
            total_score += l1_total_score

            # Layer 2: Context-Aware Static Source Analysis
            l2_score, l2_findings = self.analyze_source_code(actual_pkg_dir)
            total_score += l2_score
            all_findings.extend(l2_findings)

            # Layer 3: Dynamic Behavioral Sandbox Analysis
            l3_score, l3_findings = self.analyze_behavioral_sandbox(actual_pkg_dir, manifest_data)
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
                    "layer_1_manifest": l1_total_score,
                    "layer_1_dependency_graph": l1_graph_score,
                    "layer_1_integrity": l1_integrity_score,
                    "layer_2_source": l2_score,
                    "layer_3_behavioral": l3_score
                },
                "dependency_graph": graph_metadata,
                "integrity_check": integrity_report,
                "findings_count": len(all_findings),
                "findings": all_findings
            }
            return telemetry
        finally:
            if temp_extract_dir and os.path.exists(temp_extract_dir):
                shutil.rmtree(temp_extract_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Multi-Layer Supply Chain Security Detector (NT230 - D04)")
    parser.add_argument("target", help="Path to package directory, .tgz tarball, or parent directory of packages")
    parser.add_argument("--threshold", type=int, default=35, help="Risk score threshold for MALICIOUS verdict (default: 35)")
    parser.add_argument("--no-whitelist", action="store_true", help="Disable whitelist filtering (to analyze FPR trade-off)")
    parser.add_argument("--tarball", type=str, default=None, help="Optional path to .tgz artifact for SHA-512 integrity check")
    parser.add_argument("--expected-hash", type=str, default=None, help="Expected sha512-... integrity string for artifact verification")
    parser.add_argument("--output", type=str, default=None, help="Save telemetry output to JSON file")
    args = parser.parse_args()

    detector = SupplyChainDetector(enable_whitelist=(not args.no_whitelist), risk_threshold=args.threshold)

    results = []
    if os.path.isfile(args.target) and args.target.endswith((".tgz", ".tar.gz")):
        telemetry = detector.scan_package(args.target, tarball_path=args.tarball or args.target, expected_sha512=args.expected_hash)
        results.append(telemetry)
    elif os.path.exists(os.path.join(args.target, "package.json")):
        # Single package scan
        telemetry = detector.scan_package(args.target, tarball_path=args.tarball, expected_sha512=args.expected_hash)
        results.append(telemetry)
    else:
        # Batch directory scan
        subdirs = sorted([os.path.join(args.target, d) for d in os.listdir(args.target) if os.path.isdir(os.path.join(args.target, d))])
        for sdir in subdirs:
            if os.path.exists(os.path.join(sdir, "package.json")):
                telemetry = detector.scan_package(sdir)
                results.append(telemetry)

    print("\n" + "=" * 75)
    print(f" SUPPLY CHAIN SECURITY SCAN REPORT (Total Scanned: {len(results)})")
    print("=" * 75)
    for res in results:
        v_tag = f"[{res['verdict']}]"
        g_info = res.get("dependency_graph", {})
        nodes_cnt = g_info.get("total_nodes", 1)
        print(f"{v_tag:<12} {res['package_name']:<25} (v{res['version']:<8} | Graph Nodes: {nodes_cnt:<2}) -> Score: {res['risk_score']}")
        if res["findings"]:
            for f in res["findings"]:
                print(f"   * [{f['layer']}] ({f['severity']}) {f['rule']}: {f['detail']}")

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Telemetry exported to {args.output}")


if __name__ == "__main__":
    main()
