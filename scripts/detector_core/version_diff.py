"""
scripts/detector_core/version_diff.py
Offline version-to-version differential analyzer comparing baseline vs target package
directory/tarball (inspired by Chainguard malcontent, Elastic supply-chain-monitor, and GuardDog).
"""

import hashlib
import json
import os
import posixpath
import re
import shutil
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import SENSITIVE_ENV_KEY_NAMES, SHADOWED_CORE_BINARIES, SUSPICIOUS_LIFECYCLE_HOOKS
from .layer1_graph_integrity import (
    is_suspicious_npm_alias,
    is_traversal_file_spec,
    is_untrusted_dependency_url,
)
from .layer2_source import strip_js_comments_safely

_CAPABILITY_PROBES: List[Tuple[str, re.Pattern]] = [
    (
        "child_process",
        re.compile(
            r"require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)|"
            r"\b(?:execSync|spawnSync|execFile|execFileSync)\s*\("
        ),
    ),
    (
        "dynamic_eval",
        re.compile(
            r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn(?:New|This)?Context\s*\("
        ),
    ),
    (
        "network",
        re.compile(
            r"\b(?:https?|http2)\.(?:request|get|post)\s*\(|\bfetch\s*\(|"
            r"\b(?:net|tls)\.connect\s*\(|\bnew\s+WebSocket\s*\(|\b(?:curl|wget)\s+https?://"
        ),
    ),
    (
        "encoded_decode",
        re.compile(
            r"\bBuffer\.from\s*\([^;\)]{0,200},\s*['\"`](?:base64|base64url|hex)['\"`]\s*\)|"
            r"\batob\s*\(|\bString\.from(?:CharCode|CodePoint)\s*\("
        ),
    ),
    (
        "env_secrets",
        re.compile(
            rf"\bprocess\.env(?:\s*\.\s*|\s*\[\s*['\"`])(?:{SENSITIVE_ENV_KEY_NAMES})\b|"
            r"\bJSON\.stringify\s*\(\s*process\.env\b"
        ),
    ),
    (
        "sensitive_path",
        re.compile(
            r"(?:/etc/(?:passwd|shadow|sudoers)|\.ssh[/\\]+(?:id_rsa|id_ed25519|authorized_keys)|"
            r"\.npmrc|\.aws[/\\]+credentials|\.claude\.json)"
        ),
    ),
    (
        "obfuscation",
        re.compile(
            r"\b[A-Za-z0-9_$]*_0x[a-fA-F0-9]{4,}\b|"
            r"(?:\\x[0-9a-fA-F]{2}){8,}"
        ),
    ),
]

_CAPABILITY_HIGH_RISK = frozenset({"child_process", "dynamic_eval", "sensitive_path", "env_secrets"})
_CODE_DIFF_EXTS = (".js", ".cjs", ".mjs", ".ts", ".sh", ".bash", ".ps1", ".py")
_IGNORED_DIFF_SEGS = ("test/", "tests/", "__tests__/", "docs/", "example/", "examples/")


def _safe_extract_pkg(path: str, cleanup_dirs: List[str]) -> Optional[str]:
    """Resolves a package root dir from either a directory or safe-extracted tarball (`alignRoots`)."""
    if not path or not os.path.exists(path):
        return None
    if os.path.isdir(path):
        if os.path.isfile(os.path.join(path, "package.json")):
            return path
        pkg_sub = os.path.join(path, "package")
        return pkg_sub if os.path.isfile(os.path.join(pkg_sub, "package.json")) else path

    if os.path.isfile(path) and path.lower().endswith((".tgz", ".tar.gz", ".tar")):
        tmp_dir = tempfile.mkdtemp(prefix="d04_diff_")
        cleanup_dirs.append(tmp_dir)
        abs_tmp = os.path.abspath(tmp_dir)
        try:
            with tarfile.open(path, "r:*") as tar:
                safe_members = []
                for m in tar.getmembers():
                    if not (m.isfile() or m.isdir()):
                        continue
                    norm_m = (m.name or "").replace("\\", "/")
                    parts = [p for p in norm_m.split("/") if p]
                    if norm_m.startswith("/") or re.match(r"^[A-Za-z]:", norm_m) or ".." in parts:
                        continue
                    canon = posixpath.normpath(norm_m)
                    if canon == ".":
                        continue
                    dest_p = os.path.abspath(os.path.join(abs_tmp, canon))
                    try:
                        if os.path.commonpath([abs_tmp, dest_p]) != abs_tmp:
                            continue
                    except ValueError:
                        continue
                    safe_members.append(m)
                tar.extractall(tmp_dir, members=safe_members)
        except Exception:
            return None

        # alignRoots: prefer `package/` or unique top-level directory containing package.json
        pkg_sub = os.path.join(tmp_dir, "package")
        if os.path.isfile(os.path.join(pkg_sub, "package.json")):
            return pkg_sub
        if os.path.isfile(os.path.join(tmp_dir, "package.json")):
            return tmp_dir
        try:
            top_dirs = [d for d in os.listdir(tmp_dir) if os.path.isdir(os.path.join(tmp_dir, d))]
            if len(top_dirs) == 1:
                cand = os.path.join(tmp_dir, top_dirs[0])
                if os.path.isfile(os.path.join(cand, "package.json")):
                    return cand
        except OSError:
            pass
        return tmp_dir

    return None


def _read_manifest(root_dir: str) -> Optional[Dict[str, Any]]:
    pkg_json = os.path.join(root_dir, "package.json")
    if not os.path.isfile(pkg_json):
        return None
    try:
        with open(pkg_json, "r", encoding="utf-8", errors="ignore") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _parse_semver_tuple(ver: str) -> Optional[Tuple[int, int, int]]:
    core = re.split(r"[-+]", str(ver or "").strip(), maxsplit=1)[0]
    parts = core.split(".")
    if len(parts) < 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def _collect_bin_names(manifest: Dict[str, Any]) -> Set[str]:
    bin_field = manifest.get("bin")
    names: Set[str] = set()
    if isinstance(bin_field, dict):
        names.update(str(k).strip().lower() for k in bin_field.keys() if str(k).strip())
    elif isinstance(bin_field, str) and bin_field.strip():
        pkg_name = str(manifest.get("name", "")).strip().lower()
        unscoped = pkg_name.split("/")[-1] if "/" in pkg_name else pkg_name
        if unscoped:
            names.add(unscoped)
    return names


def _hash_package_files(root_dir: str) -> Dict[str, Tuple[str, str]]:
    """Returns `{rel_posix_path: (sha256_hex, abs_path)}` skipping `.git` and `node_modules`."""
    file_map: Dict[str, Tuple[str, str]] = {}
    for cur_root, dirs, files in os.walk(root_dir):
        dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules"))
        for fname in sorted(files):
            full_p = os.path.join(cur_root, fname)
            rel_p = os.path.relpath(full_p, root_dir).replace("\\", "/")
            try:
                if os.path.getsize(full_p) > 2 * 1024 * 1024:
                    continue
                with open(full_p, "rb") as f:
                    digest = hashlib.sha256(f.read()).hexdigest()
                file_map[rel_p] = (digest, full_p)
            except OSError:
                continue
    return file_map


def _extract_static_capabilities(full_path: str) -> Set[str]:
    """Extracts coarse behavioral capability tags from a JS/script file."""
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read(256 * 1024)
    except OSError:
        return set()
    clean = strip_js_comments_safely(raw) if full_path.lower().endswith((".js", ".cjs", ".mjs", ".ts")) else raw
    caps: Set[str] = set()
    for name, pat in _CAPABILITY_PROBES:
        if pat.search(clean):
            caps.add(name)
    return caps


def analyze_version_diff(
    baseline_path: str,
    target_path: str,
) -> Tuple[int, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Performs offline differential supply-chain inspection comparing `baseline_path`
    against `target_path` (`dir` or `.tgz`).
    """
    cleanup_dirs: List[str] = []
    try:
        base_root = _safe_extract_pkg(baseline_path, cleanup_dirs)
        targ_root = _safe_extract_pkg(target_path, cleanup_dirs)
        if not base_root or not targ_root:
            return 0, [], {"error": "Unable to resolve baseline or target package directory"}

        base_m = _read_manifest(base_root)
        targ_m = _read_manifest(targ_root)
        if base_m is None or targ_m is None:
            return 0, [], {"error": "package.json missing or invalid in baseline or target"}

        score = 0
        findings: List[Dict[str, Any]] = []

        base_ver = str(base_m.get("version", "unknown"))
        targ_ver = str(targ_m.get("version", "unknown"))

        # 1. Lifecycle Hook introduction / modification
        base_scripts = base_m.get("scripts") if isinstance(base_m.get("scripts"), dict) else {}
        targ_scripts = targ_m.get("scripts") if isinstance(targ_m.get("scripts"), dict) else {}
        new_hooks: Dict[str, str] = {}
        modified_hooks: List[str] = []

        for hook in SUSPICIOUS_LIFECYCLE_HOOKS:
            t_cmd = str(targ_scripts.get(hook, "")).strip() if hook in targ_scripts else ""
            b_cmd = str(base_scripts.get(hook, "")).strip() if hook in base_scripts else ""
            if t_cmd and not b_cmd:
                new_hooks[hook] = t_cmd
            elif t_cmd and b_cmd and t_cmd != b_cmd:
                modified_hooks.append(f"{hook}: '{b_cmd}' -> '{t_cmd}'")

        if new_hooks:
            score += 35
            sample_h = ", ".join(f"{k}='{v[:60]}'" for k, v in list(new_hooks.items())[:2])
            findings.append({
                "layer": "Layer 1 - Version Diff",
                "rule": "Version Diff: New Lifecycle Hook Introduced",
                "severity": "HIGH",
                "detail": f"v{base_ver} -> v{targ_ver} introduces lifecycle hook(s): {sample_h}",
            })
        elif modified_hooks:
            score += 30
            findings.append({
                "layer": "Layer 1 - Version Diff",
                "rule": "Version Diff: Lifecycle Hook Modified",
                "severity": "HIGH",
                "detail": f"v{base_ver} -> v{targ_ver} modifies lifecycle hook: {modified_hooks[0][:120]}",
            })

        # 2. Provenance Attestation Regression (GuardDog provenance_regression)
        base_att = bool((base_m.get("dist") or {}).get("attestations")) if isinstance(base_m.get("dist"), dict) else False
        targ_att = bool((targ_m.get("dist") or {}).get("attestations")) if isinstance(targ_m.get("dist"), dict) else False
        if base_att and not targ_att:
            score += 30
            findings.append({
                "layer": "Layer 1 - Version Diff",
                "rule": "Version Diff: Provenance Attestation Dropped",
                "severity": "HIGH",
                "detail": f"SLSA dist.attestations present in v{base_ver} is absent in v{targ_ver}",
            })

        # 3. Abrupt Semver Inflation (npm-scan tier1-metadata-spoof)
        b_sem = _parse_semver_tuple(base_ver)
        t_sem = _parse_semver_tuple(targ_ver)
        if b_sem and t_sem:
            d_maj = t_sem[0] - b_sem[0]
            d_min = t_sem[1] - b_sem[1]
            d_pat = t_sem[2] - b_sem[2]
            if d_maj > 10 or (d_maj == 0 and d_min > 20) or (d_maj == 0 and d_min == 0 and d_pat > 50):
                score += 25
                findings.append({
                    "layer": "Layer 1 - Version Diff",
                    "rule": "Version Diff: Abrupt Semver Jump",
                    "severity": "MEDIUM",
                    "detail": f"Abnormal semver jump v{base_ver} -> v{targ_ver} (+{d_maj}.{d_min}.{d_pat})",
                })

        # 4. Risky New Dependency (GuardDog risky_new_dependency)
        risky_new_deps: List[str] = []
        for field in ("dependencies", "optionalDependencies"):
            b_deps = base_m.get(field) if isinstance(base_m.get(field), dict) else {}
            t_deps = targ_m.get(field) if isinstance(targ_m.get(field), dict) else {}
            for dk, dv in t_deps.items():
                dk_s = str(dk).strip()
                dv_s = str(dv).strip()
                if dk_s in b_deps and str(b_deps[dk_s]).strip() == dv_s:
                    continue
                if is_untrusted_dependency_url(dv_s, targ_m) or is_traversal_file_spec(targ_root, dv_s):
                    risky_new_deps.append(f"{dk_s} -> {dv_s}")
                else:
                    bad_al, reason = is_suspicious_npm_alias(dk_s, dv_s, targ_m, targ_root)
                    if bad_al:
                        risky_new_deps.append(reason)
        if risky_new_deps:
            score += 40
            findings.append({
                "layer": "Layer 1 - Version Diff",
                "rule": "Version Diff: Risky New Dependency",
                "severity": "HIGH",
                "detail": f"Suspicious dependency introduced in v{targ_ver}: {', '.join(risky_new_deps[:2])}",
            })

        # 5. New Core-Shadowing bin Entry
        pkg_unscoped = str(targ_m.get("name", "")).strip().lower().split("/")[-1]
        new_shadow_bins = [
            b for b in (_collect_bin_names(targ_m) - _collect_bin_names(base_m))
            if b in SHADOWED_CORE_BINARIES and b != pkg_unscoped
        ]
        if new_shadow_bins:
            score += 35
            findings.append({
                "layer": "Layer 1 - Version Diff",
                "rule": "Version Diff: New Core-Shadowing Binary",
                "severity": "HIGH",
                "detail": f"v{targ_ver} introduces core command bin shadow(s): {', '.join(sorted(new_shadow_bins))}",
            })

        # 6. File-Level SHA-256 Skip-Unchanged & Capability Delta (supply-chain-monitor + malcontent)
        base_files = _hash_package_files(base_root)
        targ_files = _hash_package_files(targ_root)
        added_files = sorted(k for k in targ_files if k not in base_files)
        removed_files = sorted(k for k in base_files if k not in targ_files)
        modified_files = sorted(
            k for k in targ_files if k in base_files and targ_files[k][0] != base_files[k][0]
        )

        new_capabilities: Dict[str, List[str]] = {}
        for rel in modified_files:
            if not rel.lower().endswith(_CODE_DIFF_EXTS):
                continue
            delta = _extract_static_capabilities(targ_files[rel][1]) - _extract_static_capabilities(base_files[rel][1])
            if len(delta) >= 2:
                new_capabilities[rel] = sorted(delta)

        for rel in added_files:
            rel_l = rel.lower()
            if not rel_l.endswith(_CODE_DIFF_EXTS) or rel_l.startswith(_IGNORED_DIFF_SEGS):
                continue
            caps = _extract_static_capabilities(targ_files[rel][1])
            if len(caps) >= 2 and bool(caps & _CAPABILITY_HIGH_RISK):
                new_capabilities[rel] = sorted(caps)

        if new_capabilities:
            score += 35
            sample_c = "; ".join(f"{rp} (+{', '.join(cs)})" for rp, cs in list(new_capabilities.items())[:2])
            findings.append({
                "layer": "Layer 1 - Version Diff",
                "rule": "Version Diff: Escalated Code Capabilities",
                "severity": "HIGH",
                "detail": f"New high-risk behavioral capabilities added in v{targ_ver}: {sample_c}",
            })

        diff_report = {
            "baseline_version": base_ver,
            "target_version": targ_ver,
            "added_files": added_files[:50],
            "removed_files": removed_files[:50],
            "modified_files": modified_files[:50],
            "new_hooks": list(new_hooks.keys()),
            "modified_hooks": modified_hooks[:10],
            "new_capabilities": new_capabilities,
        }
        return score, findings, diff_report
    finally:
        for d in cleanup_dirs:
            shutil.rmtree(d, ignore_errors=True)
