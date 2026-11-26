#!/usr/bin/env python3
"""
scripts/detector.py
Multi-layer Supply Chain Security Detector for npm Packages (Facade over `detector_core`).
Course: NT230 - Topic D04: Supply Chain Compromise

Architecture:
- Layer 1: Neutral 3-Tier Manifest, Dependency Graph & Integrity Analysis
  - Tier 1 (Hard Evidence): Malicious binding.gyp, concrete malicious hook/aux patterns,
    Binary Shadowing, Dependency Confusion, Untrusted/Poisoned deps, SRI/Tarball exploits.
  - Tier 2 (Capability): Install hooks & local scripts capped once (+20 max), never self-convicting;
    hands off install-reachable entry files & inline JS snippets to Layer 2.
  - Tier 3 (Weak Anomalies): Typosquatting & missing description.
- Layer 2: Context-Aware Static Source Analysis + Install-Context Contract & Cross-Layer Gating.
- Layer 3: Dynamic Behavioral Analysis (instrumented Node.js sandbox execution).
"""

import argparse
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure scripts/ is on sys.path whether invoked as `python scripts/detector.py` or imported from `scripts`
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from detector_core.constants import (  # noqa: E402
    AUTHOR_PUBLISH_HOOKS,
    COMMON_ENGLISH_PACKAGE_WORDS,
    DANGEROUS_SHELL_ARG_REGEX,
    DANGEROUS_WHITELIST_FLAGS_RE,
    DECODED_PAYLOAD_INDICATORS,
    EXTENDED_SANDBOX_HOOKS,
    MALICIOUS_EXFIL_ENDPOINT_REGEX,
    POPULAR_NPM_PACKAGES,
    RUNTIME_CAPABLE_JS_TOKENS,
    SENSITIVE_ENV_KEY_NAMES,
    SENSITIVE_SOURCE_PATH_REGEX,
    SHADOWED_CORE_BINARIES,
    SOURCE_CRITICAL_EXEC_PATTERNS,
    SUSPICIOUS_LIFECYCLE_HOOKS,
    SUSPICIOUS_SCRIPT_PATTERNS,
    SUSPICIOUS_VERSION_THRESHOLD,
    TELEMETRY_PREFIX,
    TRUSTED_DEPENDENCY_HOSTS,
    TRUSTED_OFFICIAL_SCOPES,
    WHITELISTED_HOOK_COMMANDS,
)
from detector_core.layer1_graph_integrity import (  # noqa: E402
    analyze_artifact_integrity as _l1c_analyze_artifact_integrity,
    analyze_dependency_graph as _l1b_analyze_dependency_graph,
    extract_github_owner_repo,
    inspect_bundled_node_modules as _l1b_inspect_bundled_nm,
    inspect_tarball_structure,
    is_suspicious_npm_alias,
    is_traversal_file_spec,
    is_untrusted_dependency_url,
    verify_artifact_integrity,
)
from detector_core.layer1_manifest import (  # noqa: E402
    analyze_manifest_structured as _l1a_analyze_manifest_structured,
    damerau_levenshtein_distance,
    scan_auxiliary_scripts as _l1a_scan_aux_scripts,
)
from detector_core.layer2_source import (  # noqa: E402
    analyze_source_code_detailed as _l2_analyze_source_code_detailed,
    calculate_entropy as _l2_calculate_entropy,
    detect_heavy_obfuscation,
    extract_declared_entrypoints,
    normalize_js_for_static_scan,
    resolve_pkg_script_candidate,
    strip_js_comments_safely,
)
from detector_core.layer3_sandbox import (  # noqa: E402
    analyze_behavioral_sandbox as _l3_analyze_behavioral_sandbox,
    collect_sandbox_targets as _l3_collect_sandbox_targets,
    run_node_sandbox as _l3_run_node_sandbox,
    should_spawn_sandbox as _l3_should_spawn_sandbox,
    summarize_sandbox_events as _l3_summarize_sandbox_events,
)
from detector_core.models import Layer1ManifestResult  # noqa: E402
from detector_core.shell_analyzer import (  # noqa: E402
    deobfuscate_shell_cmd,
    extract_gyp_command_expansions,
    extract_node_targets_from_cmd,
    inspect_binding_gyp,
    is_benign_local_node_script,
    is_official_github_release_download,
    is_whitelisted_command,
    match_suspicious_hook_patterns,
    resolve_script_chain,
    tokenize_shell_tokens,
)
from detector_core.version_diff import analyze_version_diff  # noqa: E402

_HIGH_CONFIDENCE_STANDALONE_L2_RULES = {
    "inline_encoded_eval",
    "malicious_exfil_endpoint",
    "static_recon_exfil_flow",
    "install_identity_exfil",
    "install_post_or_dns_exfil",
    "child_process_high",
    "verified_b64_artifact",
    "nm_bundled_script_exec",
    "obfuscated_builtin_require",
    "toplevel_unsafe_cp_exec",
    "delayed_exec_timer",
    "trojan_source_unicode",
}


class SupplyChainDetector:
    """
    3-Layer Security Detector inspecting npm packages for supply chain threats:
    - Layer 1: Neutral Manifest, Dependency Graph, & Artifact Hash Integrity
    - Layer 2: Context-Aware Static Source Analysis + Install-Context Contract & Gating
    - Layer 3: Dynamic Runtime Behavioral Interception (Node.js API-Hooking Sandbox)
    """

    def __init__(self, enable_whitelist: bool = True, risk_threshold: int = 35, always_scan_l2: bool = False):
        self.enable_whitelist = enable_whitelist
        self.risk_threshold = risk_threshold
        self.always_scan_l2 = always_scan_l2
        self.sandbox_runner_path = os.path.join(_SCRIPTS_DIR, "sandbox_runner.js")
        self._nm_inspect_cache: Dict[Tuple[str, bool, int], Dict[str, Any]] = {}
        self._last_l2_obf_corroborated = False
        self._last_sandbox_events: List[Dict[str, Any]] = []

    # --- Backward-compatible utility wrappers ---
    def _deobfuscate_shell_cmd(self, cmd: str) -> str:
        return deobfuscate_shell_cmd(cmd)

    def _resolve_script_chain(self, command: str, scripts: Dict[str, Any], max_depth: int = 5) -> List[Tuple[str, str]]:
        return resolve_script_chain(command, scripts, max_depth=max_depth)

    def _extract_gyp_command_expansions(self, gyp_content: str) -> List[str]:
        return extract_gyp_command_expansions(gyp_content)

    def _inspect_binding_gyp(self, pkg_dir: str) -> List[str]:
        return inspect_binding_gyp(pkg_dir)

    def _is_whitelisted_command(
        self,
        command: str,
        scripts: Optional[Dict[str, Any]] = None,
        pkg_dir: Optional[str] = None,
        _visited: Optional[Set[str]] = None,
    ) -> bool:
        return is_whitelisted_command(
            command,
            scripts=scripts,
            pkg_dir=pkg_dir,
            enable_whitelist=self.enable_whitelist,
            _visited=_visited,
        )

    def _is_benign_local_node_script(self, hook_name: str, command: str, pkg_dir: str) -> bool:
        return is_benign_local_node_script(
            hook_name, command, pkg_dir, SENSITIVE_ENV_KEY_NAMES, detect_heavy_obfuscation
        )

    def _is_official_github_release_download(self, command: str, manifest: Dict[str, Any]) -> bool:
        return is_official_github_release_download(command, manifest)

    def _scan_auxiliary_scripts(
        self,
        pkg_dir: str,
        hook_commands: List[str],
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
    ) -> List[Tuple[str, str, bool, bool]]:
        return _l1a_scan_aux_scripts(
            pkg_dir, hook_commands, manifest=manifest, is_tarball=is_tarball, nm_cache=self._nm_inspect_cache
        )

    def _damerau_levenshtein_distance(self, s1: str, s2: str) -> int:
        return damerau_levenshtein_distance(s1, s2)

    def calculate_entropy(self, text: str) -> float:
        return _l2_calculate_entropy(text)

    def _match_suspicious_hook_patterns(self, raw_cmd: str, deobf_cmd: str, is_author_hook: bool = False) -> List[str]:
        return match_suspicious_hook_patterns(raw_cmd, deobf_cmd, is_author_hook=is_author_hook)

    def _extract_github_owner_repo(self, manifest: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
        return extract_github_owner_repo(manifest)

    def _is_untrusted_dependency_url(
        self, spec: str, manifest: Optional[Dict[str, Any]] = None, allow_raw_own_repo: bool = True
    ) -> bool:
        return is_untrusted_dependency_url(spec, manifest=manifest, allow_raw_own_repo=allow_raw_own_repo)

    def _is_traversal_file_spec(self, pkg_dir: str, spec: str) -> bool:
        return is_traversal_file_spec(pkg_dir, spec)

    def _is_suspicious_npm_alias(
        self,
        alias_key: str,
        spec: str,
        manifest: Optional[Dict[str, Any]] = None,
        pkg_dir: Optional[str] = None,
    ) -> Tuple[bool, str]:
        return is_suspicious_npm_alias(alias_key, spec, manifest=manifest, pkg_dir=pkg_dir)

    def _inspect_bundled_node_modules(
        self,
        pkg_dir: str,
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
        budget: int = 50,
    ) -> Dict[str, Any]:
        return _l1b_inspect_bundled_nm(
            pkg_dir, manifest=manifest, is_tarball=is_tarball, budget=budget, cache=self._nm_inspect_cache
        )

    def _inspect_tarball_structure(self, tarball_path: str) -> List[str]:
        return inspect_tarball_structure(tarball_path)

    def _strip_js_comments_safely(self, content: str) -> str:
        return strip_js_comments_safely(content)

    def _normalize_js_for_static_scan(self, content: str) -> str:
        return normalize_js_for_static_scan(content)

    def _tokenize_shell_tokens(self, cmd: str) -> List[str]:
        return tokenize_shell_tokens(cmd)

    def _resolve_pkg_script_candidate(
        self, pkg_dir: str, raw_path: str, base_dir: Optional[str] = None
    ) -> Optional[str]:
        return resolve_pkg_script_candidate(pkg_dir, raw_path, base_dir=base_dir)

    def _extract_node_targets_from_cmd(self, cmd_str: str) -> List[str]:
        return extract_node_targets_from_cmd(cmd_str)

    def _extract_declared_entrypoints(self, pkg_dir: str, manifest: Dict[str, Any]) -> Set[str]:
        return extract_declared_entrypoints(pkg_dir, manifest)

    # --- Layer 1A / 1B / 1C ---
    def _analyze_manifest_structured(
        self, pkg_path: str, data: Dict[str, Any], is_tarball: bool = False
    ) -> Layer1ManifestResult:
        return _l1a_analyze_manifest_structured(
            pkg_path,
            data,
            enable_whitelist=self.enable_whitelist,
            is_tarball=is_tarball,
            detect_heavy_obf_fn=detect_heavy_obfuscation,
            resolve_script_fn=resolve_pkg_script_candidate,
            nm_cache=self._nm_inspect_cache,
        )

    def analyze_manifest(
        self, pkg_path: str, data: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[int, List[Dict[str, Any]]]:
        res = self._analyze_manifest_structured(pkg_path, data, is_tarball=is_tarball)
        return res.score, res.findings

    def analyze_dependency_graph(
        self, pkg_dir: str, manifest: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[int, List[Dict[str, Any]], Dict[str, Any]]:
        return _l1b_analyze_dependency_graph(
            pkg_dir, manifest, is_tarball=is_tarball, nm_cache=self._nm_inspect_cache
        )

    def analyze_artifact_integrity(
        self,
        pkg_dir: str,
        manifest: Dict[str, Any],
        tarball_path: Optional[str] = None,
        expected_sha512: Optional[str] = None,
    ) -> Tuple[int, List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        return _l1c_analyze_artifact_integrity(
            pkg_dir, manifest, tarball_path=tarball_path, expected_sha512=expected_sha512
        )

    # --- Layer 2 ---
    def _analyze_source_code_detailed(
        self,
        pkg_dir: str,
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
        install_entry_files: Optional[Set[str]] = None,
        inline_js_snippets: Optional[List[Tuple[str, str]]] = None,
        has_hard_l1_evidence: bool = False,
        has_install_capability: bool = False,
    ) -> Tuple[int, List[Dict[str, Any]], Dict[str, Tuple[int, str, str, str]]]:
        total_l2_score, findings, triggered_rules, obf_corr, self._last_install_ctx_rules = _l2_analyze_source_code_detailed(
            pkg_dir,
            manifest=manifest,
            is_tarball=is_tarball,
            install_entry_files=install_entry_files,
            inline_js_snippets=inline_js_snippets,
            has_hard_l1_evidence=has_hard_l1_evidence,
            has_install_capability=has_install_capability,
            nm_cache=self._nm_inspect_cache,
        )
        self._last_l2_obf_corroborated = obf_corr
        return total_l2_score, findings, triggered_rules

    def analyze_source_code(
        self,
        pkg_dir: str,
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        total_l2_score, findings, _ = self._analyze_source_code_detailed(
            pkg_dir, manifest=manifest, is_tarball=is_tarball
        )
        return total_l2_score, findings

    # --- Layer 3 (keeps _run_node_sandbox and module-level subprocess monkeypatchable) ---
    def _collect_sandbox_targets(
        self, pkg_dir: str, manifest: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[Dict[str, str], List[str]]:
        return _l3_collect_sandbox_targets(
            pkg_dir,
            manifest,
            is_tarball=is_tarball,
            enable_whitelist=self.enable_whitelist,
            nm_cache=self._nm_inspect_cache,
        )

    def _should_spawn_sandbox(self, pkg_dir: str, active_hooks: Dict[str, str], target_files: List[str]) -> bool:
        return _l3_should_spawn_sandbox(pkg_dir, active_hooks, target_files)

    def _run_node_sandbox(self, pkg_dir: str, active_hooks: Dict[str, str], target_files: List[str]) -> List[Dict[str, Any]]:
        return _l3_run_node_sandbox(
            self.sandbox_runner_path,
            pkg_dir,
            active_hooks,
            target_files,
            subprocess_mod=subprocess,
        )

    def analyze_behavioral_sandbox(
        self, pkg_dir: str, manifest: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[int, List[Dict[str, Any]]]:
        return _l3_analyze_behavioral_sandbox(
            self.sandbox_runner_path,
            pkg_dir,
            manifest,
            is_tarball=is_tarball,
            enable_whitelist=self.enable_whitelist,
            nm_cache=self._nm_inspect_cache,
            run_sandbox_fn=self._run_node_sandbox,
            subprocess_mod=subprocess,
            events_out=self._last_sandbox_events,
        )

    # --- Full Scan Pipeline ---
    def scan_package(
        self,
        pkg_dir: str,
        tarball_path: Optional[str] = None,
        expected_sha512: Optional[str] = None,
        baseline_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Runs all detection layers on a package directory or tarball (.tgz).
        Returns structured telemetry with verdict, layer scores, findings, risk_tier, and signal_summary.
        """
        temp_extract_dir = None
        actual_pkg_dir = pkg_dir
        self._nm_inspect_cache.clear()
        self._last_install_ctx_rules: Set[str] = set()
        self._last_l2_obf_corroborated = False
        self._last_sandbox_events = []
        is_tarball_input = os.path.isfile(pkg_dir) and pkg_dir.lower().endswith((".tgz", ".tar.gz", ".tar"))

        if is_tarball_input:
            if not tarball_path:
                tarball_path = pkg_dir
            temp_extract_dir = tempfile.mkdtemp(prefix="d04_scan_")
            abs_extract_dir = os.path.abspath(temp_extract_dir)
            try:
                with tarfile.open(pkg_dir, "r:*") as tar:
                    safe_members = []
                    seen_extract_files: Set[str] = set()
                    for m in tar.getmembers():
                        if not (m.isfile() or m.isdir()):
                            continue
                        norm_m = (m.name or "").replace("\\", "/")
                        parts = [p for p in norm_m.split("/") if p]
                        if norm_m.startswith("/") or bool(re.match(r"^[A-Za-z]:", norm_m)) or ".." in parts:
                            continue
                        canon_m = posixpath.normpath(norm_m)
                        if canon_m == ".":
                            continue
                        dest_path = os.path.abspath(os.path.join(abs_extract_dir, canon_m))
                        try:
                            if os.path.commonpath([abs_extract_dir, dest_path]) != abs_extract_dir:
                                continue
                        except ValueError:
                            continue
                        if not m.isdir():
                            clean_rel = canon_m.lower()
                            if clean_rel in seen_extract_files:
                                continue
                            seen_extract_files.add(clean_rel)
                        safe_members.append(m)
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
                    "findings": [],
                }

        try:
            pkg_json_path = os.path.join(actual_pkg_dir, "package.json")
            if not os.path.exists(pkg_json_path):
                if tarball_path and os.path.isfile(tarball_path):
                    struct_anomalies = self._inspect_tarball_structure(tarball_path)
                    if struct_anomalies:
                        tb_name = os.path.basename(tarball_path)
                        finding = {
                            "layer": "Layer 1 - Integrity",
                            "rule": "Tarball Structural / Path Traversal Attack",
                            "severity": "CRITICAL",
                            "detail": f"Structural exploit detected in '{tb_name}': {'; '.join(struct_anomalies[:3])}",
                        }
                        verdict = "MALICIOUS" if 50 >= self.risk_threshold else "BENIGN"
                        return {
                            "package_name": tb_name,
                            "version": "unknown",
                            "package_path": os.path.abspath(pkg_dir),
                            "verdict": verdict,
                            "risk_tier": verdict,
                            "risk_score": 50,
                            "threshold": self.risk_threshold,
                            "layer_scores": {
                                "layer_1_manifest": 50,
                                "layer_1_dependency_graph": 0,
                                "layer_1_integrity": 50,
                                "layer_2_source": 0,
                                "layer_3_behavioral": 0,
                            },
                            "dependency_graph": {
                                "root_package": tb_name,
                                "direct_dependencies_count": 0,
                                "transitive_dependencies_count": 0,
                                "total_nodes": 1,
                                "estimated_depth": 0,
                                "has_lockfile": False,
                                "anomalies_detected": 1,
                                "edges": [],
                            },
                            "integrity_check": {
                                "status": "FAIL",
                                "tarball": tarball_path,
                                "expected_hash": expected_sha512,
                                "actual_hash": None,
                                "matched": False,
                                "structural_anomalies": struct_anomalies,
                            },
                            "findings_count": 1,
                            "findings": [finding],
                        }
                return {
                    "package_path": pkg_dir,
                    "error": "package.json not found",
                    "verdict": "ERROR",
                    "risk_score": 0,
                    "findings": [],
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
                    "findings": [],
                }

            if not isinstance(manifest_data, dict):
                return {
                    "package_path": pkg_dir,
                    "error": "package.json is not a JSON object",
                    "verdict": "ERROR",
                    "risk_score": 0,
                    "findings": [],
                }

            package_name = manifest_data.get("name", os.path.basename(actual_pkg_dir))
            version = manifest_data.get("version", "unknown")

            all_findings: List[Dict[str, Any]] = []

            # Layer 1A: Neutral 3-Tier Manifest Analysis
            l1_res = self._analyze_manifest_structured(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
            all_findings.extend(l1_res.findings)

            # Layer 1B: Dependency Graph Analysis
            l1_graph_score, graph_findings, graph_metadata = self.analyze_dependency_graph(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
            all_findings.extend(graph_findings)

            # Layer 1C: Artifact Hash & Integrity Verification
            l1_integrity_score, integrity_findings, integrity_report = self.analyze_artifact_integrity(
                actual_pkg_dir, manifest_data, tarball_path=tarball_path, expected_sha512=expected_sha512
            )
            all_findings.extend(integrity_findings)

            l1_total_score = l1_res.score + l1_graph_score + l1_integrity_score
            total_score = l1_total_score

            # Layer 2: Context-Aware Static Source Analysis + Install-Context Contract & Gating
            nm_info = self._inspect_bundled_node_modules(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
            has_hard_l1_evidence = (
                l1_res.has_hard_evidence
                or l1_integrity_score > 0
                or l1_graph_score >= 20
                or bool(nm_info.get("needs_l2_scan"))
            )
            raw_l2_score, raw_l2_findings, triggered_l2_rules = self._analyze_source_code_detailed(
                actual_pkg_dir,
                manifest_data,
                is_tarball=is_tarball_input,
                install_entry_files=l1_res.install_entry_files,
                inline_js_snippets=l1_res.inline_js_snippets,
                has_hard_l1_evidence=has_hard_l1_evidence,
                has_install_capability=l1_res.has_install_capability,
            )

            if self.always_scan_l2 or has_hard_l1_evidence:
                l2_score, l2_findings = raw_l2_score, raw_l2_findings
            else:
                has_obf_and_sensitive = (
                    "heavy_js_obfuscation" in triggered_l2_rules
                    and "sensitive_host_path" in triggered_l2_rules
                )
                other_strong_l2 = [
                    k for k in triggered_l2_rules
                    if k not in ("heavy_js_obfuscation", "high_entropy_source", "sensitive_host_path_cfg")
                ]
                has_corroborated_obf = "heavy_js_obfuscation" in triggered_l2_rules and bool(other_strong_l2)
                keep_rules = set(_HIGH_CONFIDENCE_STANDALONE_L2_RULES)
                if has_corroborated_obf or has_obf_and_sensitive:
                    keep_rules.add("heavy_js_obfuscation")
                if has_obf_and_sensitive:
                    keep_rules.add("sensitive_host_path")
                if "whitespace_cloaking" in triggered_l2_rules and "heavy_js_obfuscation" in triggered_l2_rules:
                    keep_rules.add("whitespace_cloaking")
                # When L1 saw install execution capability, also promote rules observed directly
                # inside install-reachable files (e.g. direct child_process shell spawn or cloaking),
                # while keeping low-confidence runtime heuristics out to prevent false positives.
                if l1_res.has_install_capability:
                    for r_k in self._last_install_ctx_rules:
                        if r_k not in ("sensitive_host_path_cfg", "high_entropy_source"):
                            keep_rules.add(r_k)

                l2_score = 0
                l2_findings = []
                for r_key, (pts, rule_name, severity, detail) in triggered_l2_rules.items():
                    if r_key in keep_rules:
                        l2_score += pts
                        l2_findings.append({
                            "layer": "Layer 2 - Source Code",
                            "rule": rule_name,
                            "severity": severity,
                            "detail": detail,
                        })

            total_score += l2_score
            all_findings.extend(l2_findings)

            # Optional Offline Version Diff Analysis
            diff_score = 0
            diff_report: Optional[Dict[str, Any]] = None
            if baseline_path:
                diff_target = (
                    tarball_path
                    if (is_tarball_input and tarball_path and os.path.isfile(tarball_path))
                    else actual_pkg_dir
                )
                diff_score, diff_findings, diff_report = analyze_version_diff(baseline_path, diff_target)
                total_score += diff_score
                all_findings.extend(diff_findings)

            # Layer 3: Dynamic Behavioral Sandbox Analysis
            l3_score, l3_findings = self.analyze_behavioral_sandbox(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
            total_score += l3_score
            all_findings.extend(l3_findings)
            behavioral_summary = _l3_summarize_sandbox_events(self._last_sandbox_events)

            verdict = "MALICIOUS" if total_score >= self.risk_threshold else "BENIGN"
            risk_tier = (
                "MALICIOUS"
                if verdict == "MALICIOUS"
                else ("REVIEW" if (l1_res.has_install_capability or total_score >= 20) else "BENIGN")
            )

            result_obj: Dict[str, Any] = {
                "package_name": package_name,
                "version": version,
                "package_path": os.path.abspath(pkg_dir),
                "verdict": verdict,
                "risk_tier": risk_tier,
                "risk_score": total_score,
                "threshold": self.risk_threshold,
                "layer_scores": {
                    "layer_1_manifest": l1_total_score,
                    "layer_1_dependency_graph": l1_graph_score,
                    "layer_1_integrity": l1_integrity_score,
                    "layer_1_version_diff": diff_score,
                    "layer_2_source": l2_score,
                    "layer_3_behavioral": l3_score,
                },
                "signal_summary": {
                    "hard_evidence_score": l1_res.hard_score + l1_graph_score + l1_integrity_score + diff_score,
                    "capability_score": l1_res.capability_score,
                    "weak_anomaly_score": l1_res.weak_score,
                    "has_install_capability": l1_res.has_install_capability,
                    "install_entry_files": sorted(l1_res.install_entry_files),
                },
                "dependency_graph": graph_metadata,
                "integrity_check": integrity_report,
                "behavioral_summary": behavioral_summary,
                "findings_count": len(all_findings),
                "findings": all_findings,
            }
            if diff_report is not None:
                result_obj["version_diff"] = diff_report
            return result_obj
        finally:
            self._nm_inspect_cache.clear()
            if temp_extract_dir and os.path.exists(temp_extract_dir):
                shutil.rmtree(temp_extract_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Multi-Layer Supply Chain Security Detector (NT230 - D04)")
    parser.add_argument("target", help="Path to package directory, .tgz tarball, or parent directory of packages")
    parser.add_argument("--threshold", type=int, default=35, help="Risk score threshold for MALICIOUS verdict (default: 35)")
    parser.add_argument("--no-whitelist", action="store_true", help="Disable whitelist filtering (to analyze FPR trade-off)")
    parser.add_argument("--always-scan-l2", action="store_true", help="Always run Layer 2 static analysis even without hard Layer 1 evidence")
    parser.add_argument("--tarball", type=str, default=None, help="Optional path to .tgz artifact for SHA-512 integrity check")
    parser.add_argument("--expected-hash", type=str, default=None, help="Expected sha512-... integrity string for artifact verification")
    parser.add_argument("--diff-base", type=str, default=None, help="Optional baseline version dir/.tgz for offline differential analysis")
    parser.add_argument("--output", type=str, default=None, help="Save telemetry output to JSON file")
    args = parser.parse_args()

    detector = SupplyChainDetector(
        enable_whitelist=(not args.no_whitelist),
        risk_threshold=args.threshold,
        always_scan_l2=args.always_scan_l2,
    )

    results = []
    if os.path.isfile(args.target) and args.target.endswith((".tgz", ".tar.gz")):
        telemetry = detector.scan_package(
            args.target,
            tarball_path=args.tarball or args.target,
            expected_sha512=args.expected_hash,
            baseline_path=args.diff_base,
        )
        results.append(telemetry)
    elif os.path.exists(os.path.join(args.target, "package.json")):
        telemetry = detector.scan_package(
            args.target,
            tarball_path=args.tarball,
            expected_sha512=args.expected_hash,
            baseline_path=args.diff_base,
        )
        results.append(telemetry)
    else:
        subdirs = sorted([os.path.join(args.target, d) for d in os.listdir(args.target) if os.path.isdir(os.path.join(args.target, d))])
        for sdir in subdirs:
            if os.path.exists(os.path.join(sdir, "package.json")):
                telemetry = detector.scan_package(sdir, baseline_path=args.diff_base)
                results.append(telemetry)

    print("\n" + "=" * 75)
    print(f" SUPPLY CHAIN SECURITY SCAN REPORT (Total Scanned: {len(results)})")
    print("=" * 75)
    for res in results:
        v_tag = f"[{res['verdict']}]"
        g_info = res.get("dependency_graph", {})
        nodes_cnt = g_info.get("total_nodes", 1)
        print(f"{v_tag:<12} {res['package_name']:<25} (v{res['version']:<8} | Graph Nodes: {nodes_cnt:<2}) -> Score: {res['risk_score']}")
        if res.get("version_diff") and isinstance(res["version_diff"], dict) and "baseline_version" in res["version_diff"]:
            vd = res["version_diff"]
            print(
                f"   [Version Diff] v{vd['baseline_version']} -> v{vd['target_version']} | "
                f"Added: {len(vd.get('added_files', []))}, Modified: {len(vd.get('modified_files', []))}, Removed: {len(vd.get('removed_files', []))}"
            )
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
