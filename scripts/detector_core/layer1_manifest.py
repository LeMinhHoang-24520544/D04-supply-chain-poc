"""
scripts/detector_core/layer1_manifest.py
Neutral 3-Tier Layer 1A Manifest Analyzer:
  - Tier 1 (Hard Evidence): Malicious binding.gyp, concrete malicious hook/aux commands,
    Binary Shadowing, Dependency Confusion.
  - Tier 2 (Execution Capability): Install hooks & local scripts capped ONCE per package (+20 max),
    never self-convicting at thr=35 when enable_whitelist=True; delegates targets to Layer 2.
  - Tier 3 (Weak Anomalies): Typosquatting (+30 with install capability, +20 small footprint),
    Empty Description (+5).
"""

import ipaddress
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .constants import (
    AUTHOR_PUBLISH_HOOKS,
    COMMON_ENGLISH_PACKAGE_WORDS,
    HIGH_CONF_AUX_MALWARE_RE,
    MALICIOUS_EXFIL_ENDPOINT_REGEX,
    POPULAR_NPM_PACKAGES,
    SENSITIVE_ENV_KEY_NAMES,
    SHADOWED_CORE_BINARIES,
    SUSPICIOUS_LIFECYCLE_HOOKS,
    SUSPICIOUS_VERSION_THRESHOLD,
    TRUSTED_OFFICIAL_SCOPES,
)
from .layer1_graph_integrity import inspect_bundled_node_modules, is_untrusted_dependency_url
from .models import Layer1ManifestResult
from .shell_analyzer import (
    classify_hook_command,
    deobfuscate_shell_cmd,
    inspect_binding_gyp,
    inspect_build_files,
    match_suspicious_hook_patterns,
)

_DEP_CONF_SENTINEL_FAMILY = frozenset({"9.9.9", "9.9.10", "10.10.10", "11.11.11"})
_NATIVE_BINARY_EXTS = (
    ".node", ".exe", ".dll", ".so", ".dylib", ".wasm", ".bin",
    ".a", ".lib", ".o", ".obj", ".pyc", ".zip", ".tgz", ".gz", ".tar", ".pdf", ".br",
)
_DISGUISED_CHECK_EXTS = (".js", ".cjs", ".mjs", ".json", ".txt", ".md", ".png", ".jpg", ".svg", ".dat", ".css")
_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
_INTERNAL_META_HOST_RE = re.compile(r"\.(?:internal|corp|intra|priv|lan)$", re.IGNORECASE)


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes optimal string alignment (Damerau-Levenshtein) distance."""
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > 2:
        return max(len1, len2)
    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len1][len2]


def scan_auxiliary_scripts(
    pkg_dir: str,
    hook_commands: List[str],
    manifest: Optional[Dict[str, Any]] = None,
    is_tarball: bool = False,
    nm_cache: Optional[Dict[Tuple[str, bool, int], Dict[str, Any]]] = None,
) -> List[Tuple[str, str, bool, bool]]:
    """
    Scans .sh, .bash, .ps1, .bat, .cmd, .py files referenced by hooks or bundled in the package.
    Returns `[(rel_path, pattern_desc, is_referenced_in_hook, is_high_confidence), ...]`.
    """
    script_exts = (".sh", ".bash", ".ps1", ".bat", ".cmd", ".py")
    shell_exts = (".sh", ".bash", ".ps1", ".bat", ".cmd")
    test_doc_prefixes = (
        "test/", "tests/", "__tests__/", "spec/", "example/", "examples/",
        "docs/", "doc/", "benchmark/", "benchmarks/",
        "integration/", "e2e/", "fixtures/", "__mocks__/",
    )

    referenced_files: Set[str] = set()
    joined_hooks = "\n".join(hook_commands)
    for m in re.finditer(r"([A-Za-z0-9_./\\-]+\.(?:sh|bash|ps1|bat|cmd|py))\b", joined_hooks, re.IGNORECASE):
        referenced_files.add(m.group(1).replace("\\", "/").lstrip("./"))

    candidate_paths: List[Tuple[str, str, bool]] = []
    seen_rel: Set[str] = set()
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for fname in files:
            if fname.lower().endswith(script_exts):
                full_p = os.path.join(root, fname)
                rel_p = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
                if rel_p not in seen_rel:
                    seen_rel.add(rel_p)
                    is_ref = rel_p in referenced_files or os.path.basename(rel_p) in referenced_files
                    candidate_paths.append((full_p, rel_p, is_ref))

    nm_info = inspect_bundled_node_modules(pkg_dir, manifest=manifest, is_tarball=is_tarball, cache=nm_cache)
    if nm_info.get("should_scan"):
        for full_p in nm_info.get("budget_code_files", []):
            if full_p.lower().endswith(script_exts):
                rel_p = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
                if rel_p not in seen_rel:
                    seen_rel.add(rel_p)
                    is_ref = rel_p in referenced_files or os.path.basename(rel_p) in referenced_files
                    candidate_paths.append((full_p, rel_p, is_ref))

    for ref_rel in referenced_files:
        if ".." in ref_rel.split("/"):
            continue
        full_p = os.path.normpath(os.path.join(pkg_dir, ref_rel))
        if os.path.isfile(full_p):
            rel_p = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
            if not rel_p.startswith("../") and rel_p not in seen_rel:
                seen_rel.add(rel_p)
                candidate_paths.append((full_p, rel_p, True))

    hits: List[Tuple[str, str, bool, bool]] = []
    for full_p, rel_p, is_ref in candidate_paths:
        rel_lower = rel_p.lower()
        if not is_ref:
            if rel_lower.endswith(".py") or rel_lower.startswith(test_doc_prefixes):
                continue
            if not rel_lower.endswith(shell_exts):
                continue
        try:
            with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read(256 * 1024)
        except Exception:
            continue
        filtered_lines = [
            line for line in raw.splitlines()
            if not re.match(r"^\s*(?:#|REM\b|::)", line, re.IGNORECASE)
        ]
        cleaned = "\n".join(filtered_lines)
        deobf = deobfuscate_shell_cmd(cleaned)

        exfil_m = MALICIOUS_EXFIL_ENDPOINT_REGEX.search(cleaned) or MALICIOUS_EXFIL_ENDPOINT_REGEX.search(deobf)
        high_conf_m = HIGH_CONF_AUX_MALWARE_RE.search(cleaned) or HIGH_CONF_AUX_MALWARE_RE.search(deobf)
        is_high_conf = bool(exfil_m or high_conf_m)

        if is_ref:
            matched_descs = match_suspicious_hook_patterns(cleaned, deobf, is_author_hook=False)
            if exfil_m and "Suspicious exfiltration endpoint" not in matched_descs:
                matched_descs.insert(0, f"Exfiltration endpoint '{exfil_m.group(0)}'")
            for desc in dict.fromkeys(matched_descs):
                hits.append((rel_p, desc, True, True))
        elif is_high_conf:
            desc = (
                f"High-confidence exfiltration endpoint '{exfil_m.group(0)}'"
                if exfil_m
                else "High-confidence malicious shell construct (pipe-to-shell/reverse-shell/credential-exfil)"
            )
            hits.append((rel_p, desc, False, True))

    return hits


def _inspect_install_config_files(pkg_dir: str) -> List[Tuple[str, str, int]]:
    """
    Detects dangerous package-manager install configuration files (`npm-scan` install-config-abuse):
    - `.pnpmfile.cjs` / `.pnpmfile.mjs` / `pnpmfile.js` defining `hooks.readPackage`
    - `.yarnrc.yml` referencing remote `http(s)://` plugins
    - `bunfig.toml` configuring `preload` or untrusted custom `registry` URL
    Returns `[(kind, detail, points), ...]` where kind is 'hard' or 'cap'.
    """
    hits: List[Tuple[str, str, int]] = []
    if not pkg_dir:
        return hits

    for pnpm_name in (".pnpmfile.cjs", ".pnpmfile.mjs", "pnpmfile.js"):
        pnpm_path = os.path.join(pkg_dir, pnpm_name)
        if not os.path.isfile(pnpm_path):
            continue
        try:
            with open(pnpm_path, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read(128 * 1024)
        except OSError:
            continue
        if re.search(r"\b(?:hooks|readPackage)\b", src):
            is_risky = bool(
                re.search(
                    r"\.(?:scripts|dependencies|optionalDependencies)\b|"
                    r"\b(?:child_process|execSync|spawn|eval|Function|fetch|require\s*\(\s*['\"](?:https?|net|fs))\b",
                    src,
                )
            )
            if is_risky:
                hits.append(("hard", f"{pnpm_name} defines lifecycle/dependency mutation hook (`readPackage`)", 40))
            else:
                hits.append(("cap", f"{pnpm_name} defines pnpm package hook configuration", 20))
        break

    yarnrc_path = os.path.join(pkg_dir, ".yarnrc.yml")
    if os.path.isfile(yarnrc_path):
        try:
            with open(yarnrc_path, "r", encoding="utf-8", errors="ignore") as f:
                ysrc = f.read(64 * 1024)
            if re.search(r"(?m)^\s*plugins\s*:", ysrc) and re.search(
                r"(?:path|spec)\s*:\s*['\"]?https?://", ysrc, re.IGNORECASE
            ):
                hits.append(("hard", ".yarnrc.yml loads remote HTTP/HTTPS Yarn plugin", 40))
        except OSError:
            pass

    bunfig_path = os.path.join(pkg_dir, "bunfig.toml")
    if os.path.isfile(bunfig_path):
        try:
            with open(bunfig_path, "r", encoding="utf-8", errors="ignore") as f:
                bsrc = f.read(64 * 1024)
            if re.search(r"(?m)^\s*preload\s*=", bsrc):
                hits.append(("hard", "bunfig.toml configures automatic `preload` script execution", 35))
            else:
                reg_m = re.search(r"(?m)^\s*registry\s*=\s*['\"]([^'\"]+)['\"]", bsrc)
                if reg_m:
                    rurl = reg_m.group(1).strip()
                    host = (urlparse(rurl).hostname or "").lower()
                    if host and host not in ("registry.npmjs.org", "registry.yarnpkg.com", "localhost", "127.0.0.1"):
                        hits.append(("hard", f"bunfig.toml points registry to untrusted URL '{rurl}'", 35))
        except OSError:
            pass

    return hits


def _detect_disguised_native_binary(pkg_dir: str, max_files: int = 500) -> Optional[str]:
    """
    Detects compiled ELF / verified PE / Mach-O executables disguised with non-native
    extensions (`.js`, `.txt`, `.png`, `.json`, etc.), adapted from GuardDog `bundled_binary.py`.
    """
    if not pkg_dir:
        return None
    checked = 0
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules"))
        for fname in sorted(files):
            fname_l = fname.lower()
            if fname_l.endswith(_NATIVE_BINARY_EXTS) or not fname_l.endswith(_DISGUISED_CHECK_EXTS):
                continue
            checked += 1
            if checked > max_files:
                return None
            full_p = os.path.join(root, fname)
            try:
                fsize = os.path.getsize(full_p)
                if fsize < 64:
                    continue
                with open(full_p, "rb") as bf:
                    head4 = bf.read(4)
                    magic = ""
                    if head4.startswith(b"\x7fELF"):
                        magic = "ELF"
                    elif head4 in _MACHO_MAGICS:
                        magic = "Mach-O"
                    elif head4.startswith(b"MZ"):
                        rest60 = bf.read(60)
                        head = head4 + rest60
                        if len(head) >= 64:
                            e_lfanew = int.from_bytes(head[60:64], "little")
                            if 64 <= e_lfanew <= min(65536, fsize - 4):
                                bf.seek(e_lfanew)
                                pe_sig = bf.read(4)
                                if pe_sig == b"PE\x00\x00":
                                    magic = "PE/COFF"
                    if magic:
                        rel_p = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
                        return f"{magic} executable disguised as '{rel_p}'"
            except OSError:
                continue
    return None


def _find_internal_metadata_urls(data: Dict[str, Any]) -> List[str]:
    """Extracts internal corporate domains or RFC1918 IPs in `repository`/`homepage`/`bugs`."""
    candidates: List[Tuple[str, str]] = []
    repo = data.get("repository")
    if isinstance(repo, str):
        candidates.append(("repository", repo))
    elif isinstance(repo, dict) and isinstance(repo.get("url"), str):
        candidates.append(("repository.url", repo["url"]))
    if isinstance(data.get("homepage"), str):
        candidates.append(("homepage", data["homepage"]))
    bugs = data.get("bugs")
    if isinstance(bugs, str):
        candidates.append(("bugs", bugs))
    elif isinstance(bugs, dict) and isinstance(bugs.get("url"), str):
        candidates.append(("bugs.url", bugs["url"]))

    suspicious: List[str] = []
    for field, raw_url in candidates:
        u = raw_url.strip()
        if not u:
            continue
        norm = re.sub(r"^git\+", "", u, flags=re.IGNORECASE)
        host = ""
        if "://" in norm:
            try:
                host = (urlparse(norm).hostname or "").lower().rstrip(".")
            except ValueError:
                host = ""
        else:
            scp = re.match(r"^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):", norm)
            if scp:
                host = scp.group(1).lower().rstrip(".")
        if not host or host in ("localhost", "127.0.0.1", "::1") or "verdaccio" in host:
            continue
        if _INTERNAL_META_HOST_RE.search(host):
            suspicious.append(f"{field}={u}")
            continue
        try:
            ip_obj = ipaddress.ip_address(host)
            if ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                suspicious.append(f"{field}={u}")
        except ValueError:
            pass
    return suspicious


def analyze_manifest_structured(
    pkg_path: str,
    data: Dict[str, Any],
    enable_whitelist: bool = True,
    is_tarball: bool = False,
    detect_heavy_obf_fn=None,
    resolve_script_fn=None,
    nm_cache: Optional[Dict[Tuple[str, bool, int], Dict[str, Any]]] = None,
) -> Layer1ManifestResult:
    """
    Neutral 3-Tier Layer 1A Manifest Analysis.
    Returns `Layer1ManifestResult` separating Hard Evidence, Install Capability, and Weak Anomalies.
    """
    hard_score = 0
    capability_score = 0
    weak_score = 0
    findings: List[Dict[str, Any]] = []
    install_entry_files: Set[str] = set()
    inline_js_snippets: List[Tuple[str, str]] = []
    all_hook_commands: List[str] = []

    has_hard_evidence = False
    has_install_capability = False
    has_suspicious_install_hook = False

    # 0. Cross-check binding.gyp for genuine malicious command execution / undeclared gyp / bad flags
    gyp_issues = inspect_binding_gyp(pkg_path, manifest=data)
    gyp_malicious = bool(gyp_issues)
    for g_issue in gyp_issues:
        hard_score += 50
        has_hard_evidence = True
        findings.append({
            "layer": "Layer 1 - Manifest",
            "rule": "Malicious binding.gyp Command Injection",
            "severity": "CRITICAL",
            "detail": g_issue,
        })

    # 1. Inspect consumer lifecycle hooks & author hooks
    scripts = data.get("scripts", {})
    capability_points_assigned = 0  # Cap bare install capability per package!

    if isinstance(scripts, dict):
        for hook in SUSPICIOUS_LIFECYCLE_HOOKS:
            if hook not in scripts:
                continue
            command = str(scripts[hook]).strip()
            if not command:
                continue
            all_hook_commands.append(command)

            # Resolve subcommands for aux scanning
            from .shell_analyzer import resolve_script_chain
            for _, sub_cmd in resolve_script_chain(command, scripts):
                all_hook_commands.append(sub_cmd)

            cls = classify_hook_command(
                hook_name=hook,
                command=command,
                manifest=data,
                scripts=scripts,
                pkg_dir=pkg_path,
                enable_whitelist=enable_whitelist,
                gyp_malicious=gyp_malicious,
                sensitive_env_key_names=SENSITIVE_ENV_KEY_NAMES,
                detect_heavy_obf_fn=detect_heavy_obf_fn,
                resolve_script_fn=resolve_script_fn,
            )

            install_entry_files.update(cls.local_js_targets)
            inline_js_snippets.extend(cls.inline_js_snippets)

            if cls.kind == "whitelisted_build":
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": f"Whitelisted Hook: {hook}",
                    "severity": "INFO",
                    "detail": cls.detail,
                })
            elif cls.kind == "github_release_download":
                has_install_capability = True
                pts = max(0, 10 - capability_points_assigned)
                capability_points_assigned += pts
                capability_score += pts
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": f"Suspicious Lifecycle Hook: {hook}",
                    "severity": "MEDIUM",
                    "detail": cls.detail,
                })
            elif cls.kind == "benign_banner":
                has_install_capability = True
                pts = max(0, 5 - capability_points_assigned)
                capability_points_assigned += pts
                capability_score += pts
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": f"Suspicious Lifecycle Hook: {hook}",
                    "severity": "LOW",
                    "detail": cls.detail,
                })
            elif cls.kind == "malicious_inline":
                has_hard_evidence = True
                has_install_capability = True
                has_suspicious_install_hook = True
                hard_score += 40
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": f"Suspicious Lifecycle Hook: {hook}",
                    "severity": "HIGH",
                    "detail": f"Detected active '{hook}' hook with malicious command: {command}",
                })
                for desc in cls.hard_patterns:
                    hard_score += 25
                    if " in bridged script " in desc:
                        detail_msg = desc
                    else:
                        detail_msg = f"{desc} in '{hook}': {command}"
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": "Suspicious Hook Command Pattern",
                        "severity": "CRITICAL",
                        "detail": detail_msg,
                    })
            else:
                # local_script or capability_other
                has_install_capability = True
                has_suspicious_install_hook = True
                if not enable_whitelist:
                    # Raw trade-off mode (used by evaluate.py / --no-whitelist)
                    hard_score += 40
                    has_hard_evidence = True
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": f"Suspicious Lifecycle Hook: {hook}",
                        "severity": "HIGH",
                        "detail": cls.detail,
                    })
                else:
                    # Neutral Tier 2 Capability: capped at +20 ONCE per package across all hooks
                    pts = max(0, 20 - capability_points_assigned)
                    capability_points_assigned += pts
                    capability_score += pts
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": f"Suspicious Lifecycle Hook: {hook}",
                        "severity": "MEDIUM",
                        "detail": cls.detail,
                    })

        for hook in AUTHOR_PUBLISH_HOOKS:
            if hook not in scripts:
                continue
            command = str(scripts[hook]).strip()
            if not command:
                continue
            all_hook_commands.append(command)
            from .shell_analyzer import resolve_script_chain
            for _, sub_cmd in resolve_script_chain(command, scripts):
                all_hook_commands.append(sub_cmd)

            cls = classify_hook_command(
                hook_name=hook,
                command=command,
                manifest=data,
                scripts=scripts,
                pkg_dir=pkg_path,
                enable_whitelist=enable_whitelist,
                gyp_malicious=gyp_malicious,
                sensitive_env_key_names=SENSITIVE_ENV_KEY_NAMES,
                detect_heavy_obf_fn=detect_heavy_obf_fn,
                resolve_script_fn=resolve_script_fn,
            )
            inline_js_snippets.extend(cls.inline_js_snippets)
            if cls.hard_patterns:
                has_hard_evidence = True
                has_suspicious_install_hook = True
                install_entry_files.update(cls.local_js_targets)
                hard_score += 40
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": f"Suspicious Lifecycle Hook: {hook}",
                    "severity": "HIGH",
                    "detail": f"Detected suspicious '{hook}' hook with command: {command}",
                })
                for desc in cls.hard_patterns:
                    hard_score += 25
                    detail_msg = desc if " in bridged script " in desc else f"{desc} in '{hook}': {command}"
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": "Suspicious Hook Command Pattern",
                        "severity": "CRITICAL",
                        "detail": detail_msg,
                    })

    # 1a-bis. Install-config abuse (.pnpmfile.cjs, .yarnrc.yml, bunfig.toml) & build files (Makefile/CMakeLists.txt)
    for cfg_kind, cfg_detail, cfg_pts in _inspect_install_config_files(pkg_path):
        if cfg_kind == "hard":
            hard_score += cfg_pts
            has_hard_evidence = True
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Suspicious Package Manager Hook Config",
                "severity": "HIGH",
                "detail": cfg_detail,
            })
        else:
            has_install_capability = True
            pts = max(0, 20 - capability_points_assigned)
            capability_points_assigned += pts
            capability_score += pts
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Suspicious Package Manager Hook Config",
                "severity": "MEDIUM",
                "detail": cfg_detail,
            })

    for b_issue in inspect_build_files(pkg_path, all_hook_commands):
        hard_score += 45
        has_hard_evidence = True
        findings.append({
            "layer": "Layer 1 - Manifest",
            "rule": "Malicious Build Config Injection",
            "severity": "CRITICAL",
            "detail": b_issue,
        })

    # 1a-ter. Disguised compiled executable binaries inside source/asset files
    disguised_bin = _detect_disguised_native_binary(pkg_path)
    if disguised_bin:
        hard_score += 45
        has_hard_evidence = True
        findings.append({
            "layer": "Layer 1 - Manifest",
            "rule": "Disguised Native Executable Binary",
            "severity": "CRITICAL",
            "detail": f"Detected {disguised_bin}",
        })

    # 1b. Scan auxiliary shell/script files
    aux_hits = scan_auxiliary_scripts(
        pkg_path, all_hook_commands, manifest=data, is_tarball=is_tarball, nm_cache=nm_cache
    )
    unref_aux_scored = False
    for rel_p, desc, is_ref, _is_high_conf in aux_hits:
        if is_ref:
            hard_score += 35
            has_hard_evidence = True
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Suspicious Hook Command Pattern",
                "severity": "CRITICAL",
                "detail": f"{desc} in auxiliary script '{rel_p}'",
            })
        elif not unref_aux_scored:
            unref_aux_scored = True
            weak_score += 20
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Suspicious Auxiliary Script Pattern",
                "severity": "MEDIUM",
                "detail": f"{desc} in unreferenced auxiliary script '{rel_p}'",
            })

    # 2. Version anomalies (Dependency Confusion)
    def _is_yyyymmdd_calver(val: int) -> bool:
        if not (20150101 <= val <= 20351231):
            return False
        mm = (val // 100) % 100
        dd = val % 100
        return 1 <= mm <= 12 and 1 <= dd <= 31

    version_str = str(data.get("version", "1.0.0")).strip()
    ver_core = re.split(r"[-+]", version_str, maxsplit=1)[0]
    ver_parts = ver_core.split(".")
    try:
        major_version = int(ver_parts[0])
        minor_version = int(ver_parts[1]) if len(ver_parts) > 1 and ver_parts[1].isdigit() else 0
        patch_version = int(ver_parts[2]) if len(ver_parts) > 2 and ver_parts[2].isdigit() else 0

        is_calver = (
            (2015 <= major_version <= 2035 and 1 <= minor_version <= 12 and patch_version < 999)
            or (major_version < 90 and _is_yyyymmdd_calver(minor_version) and patch_version < 999)
        )
        is_high_ver = (
            (major_version >= SUSPICIOUS_VERSION_THRESHOLD and not is_calver)
            or (minor_version >= 999 and not is_calver)
            or patch_version >= 999
        )
        pkg_name_l = str(data.get("name", "")).strip().lower()
        has_scope_tmp = "/" in pkg_name_l
        unscoped_tmp = pkg_name_l.split("/")[-1] if has_scope_tmp else pkg_name_l
        is_reputable_tmp = (
            unscoped_tmp in POPULAR_NPM_PACKAGES
            or any(pkg_name_l.startswith(sc) for sc in TRUSTED_OFFICIAL_SCOPES)
        )
        js_count = 0
        if is_high_ver or (ver_core in _DEP_CONF_SENTINEL_FAMILY):
            for root, dirs, files in os.walk(pkg_path):
                dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
                js_count += sum(1 for fn in files if fn.endswith((".js", ".cjs", ".mjs")))

        has_repo = bool(data.get("repository"))
        has_internal_name = bool(re.search(r"(?:^|[-_/])(?:internal|corp|private|staging)(?:[-_/]|$)", pkg_name_l))
        if is_high_ver:
            has_untrusted_dep = False
            for dep_f in ("dependencies", "optionalDependencies"):
                dep_obj = data.get(dep_f, {})
                if isinstance(dep_obj, dict):
                    for sp in dep_obj.values():
                        if is_untrusted_dependency_url(str(sp), data):
                            has_untrusted_dep = True
                            break

            if (
                js_count > 10
                and has_repo
                and not has_suspicious_install_hook
                and not has_untrusted_dep
                and not has_internal_name
                and minor_version < 999
            ):
                weak_score += 15
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": "Dependency Confusion Indicator",
                    "severity": "LOW",
                    "detail": f"High version '{version_str}' in established multi-file repository package (Chromium/date/database-style versioning)",
                })
            else:
                hard_score += 50
                has_hard_evidence = True
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": "Dependency Confusion Indicator",
                    "severity": "CRITICAL",
                    "detail": f"Abnormally high version '{version_str}' (major >= {SUSPICIOUS_VERSION_THRESHOLD} or minor/patch >= 999)",
                })
        elif (
            ver_core in _DEP_CONF_SENTINEL_FAMILY
            and not is_reputable_tmp
            and (has_suspicious_install_hook or has_internal_name or js_count <= 3)
        ):
            weak_score += 35
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Dependency Confusion Indicator",
                "severity": "HIGH",
                "detail": f"Sentinel version '{version_str}' paired with install/internal/minimal-footprint indicator",
            })
    except (ValueError, IndexError):
        pass

    internal_meta_urls = _find_internal_metadata_urls(data)
    if internal_meta_urls:
        weak_score += 15
        findings.append({
            "layer": "Layer 1 - Manifest",
            "rule": "Spoofed Internal Metadata URL",
            "severity": "MEDIUM",
            "detail": f"Package metadata references internal/private host URL: {', '.join(internal_meta_urls[:2])}",
        })

    # 3. Typosquatting / Brandjacking Indicator (Tier 3 Weak Anomaly, escalates with install capability)
    pkg_name_raw = str(data.get("name", "")).strip().lower()
    has_scope = "/" in pkg_name_raw
    unscoped_name = pkg_name_raw.split("/")[-1] if has_scope else pkg_name_raw
    is_official_scope = any(pkg_name_raw.startswith(sc) for sc in TRUSTED_OFFICIAL_SCOPES)
    if unscoped_name and len(unscoped_name) >= 4 and not is_official_scope and unscoped_name not in POPULAR_NPM_PACKAGES:
        if not (unscoped_name in COMMON_ENGLISH_PACKAGE_WORDS and not has_suspicious_install_hook):
            typo_target = None
            for pop in POPULAR_NPM_PACKAGES:
                if len(pop) < 4:
                    continue
                if has_scope and len(pop) <= 5:
                    continue
                if ("-" in pop and unscoped_name == pop.replace("-", "")) or damerau_levenshtein_distance(unscoped_name, pop) == 1:
                    typo_target = pop
                    break
            if typo_target:
                code_files_count = 0
                for root, dirs, files in os.walk(pkg_path):
                    dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
                    code_files_count += sum(
                        1 for fn in files if fn.endswith((".js", ".cjs", ".mjs", ".ts", ".sh", ".ps1", ".bat", ".py"))
                    )
                if has_suspicious_install_hook:
                    weak_score += 30
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": "Typosquatting / Brandjacking Indicator",
                        "severity": "HIGH",
                        "detail": f"Package name '{pkg_name_raw}' closely resembles popular package '{typo_target}' with suspicious install hook",
                    })
                elif code_files_count <= 3:
                    weak_score += 20
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": "Typosquatting / Brandjacking Indicator",
                        "severity": "MEDIUM",
                        "detail": f"Package name '{pkg_name_raw}' closely resembles popular package '{typo_target}' with minimal file footprint",
                    })

    # 4. Binary / Command Shadowing (Tier 1 Hard Evidence)
    bin_field = data.get("bin")
    declared_bins: List[str] = []
    if isinstance(bin_field, dict):
        declared_bins = [str(k).strip().lower() for k in bin_field.keys() if str(k).strip()]
    elif isinstance(bin_field, str) and bin_field.strip() and unscoped_name:
        declared_bins = [unscoped_name]

    shadowed_cmds = []
    for cmd_name in declared_bins:
        if cmd_name not in SHADOWED_CORE_BINARIES:
            continue
        if cmd_name == unscoped_name:
            continue
        if unscoped_name == "typescript" and cmd_name == "tsc":
            continue
        if unscoped_name == "npm" and cmd_name in ("npm", "npx"):
            continue
        shadowed_cmds.append(cmd_name)

    if shadowed_cmds:
        hard_score += 45
        has_hard_evidence = True
        findings.append({
            "layer": "Layer 1 - Manifest",
            "rule": "Binary / Command Shadowing",
            "severity": "CRITICAL",
            "detail": f"Package 'bin' overrides core system/toolchain command(s): {', '.join(shadowed_cmds)}",
        })

    # 5. Missing metadata description (Tier 3 Weak Anomaly)
    if not data.get("description") or len(str(data.get("description")).strip()) == 0:
        weak_score += 5
        findings.append({
            "layer": "Layer 1 - Manifest",
            "rule": "Empty Description",
            "severity": "LOW",
            "detail": "Package lacks metadata description.",
        })

    total_score = hard_score + capability_score + weak_score
    return Layer1ManifestResult(
        score=total_score,
        hard_score=hard_score,
        capability_score=capability_score,
        weak_score=weak_score,
        findings=findings,
        has_hard_evidence=has_hard_evidence,
        has_install_capability=has_install_capability,
        has_suspicious_install_hook=has_suspicious_install_hook,
        install_entry_files=install_entry_files,
        inline_js_snippets=inline_js_snippets,
        all_hook_commands=all_hook_commands,
        gyp_malicious=gyp_malicious,
    )
