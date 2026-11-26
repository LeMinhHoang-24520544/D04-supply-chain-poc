"""
scripts/detector_core/layer3_sandbox.py
Layer 3: Dynamic Behavioral Sandbox Analysis via Node.js API Hooking (`scripts/sandbox_runner.js`).
"""

import json
import os
import re
import subprocess as _std_subproc
from typing import Any, Callable, Dict, List, Optional, Tuple

from .constants import (
    AUTHOR_PUBLISH_HOOKS,
    DANGEROUS_SHELL_ARG_REGEX,
    IGNORED_TEST_DOC_SEG_RE,
    RUNTIME_CAPABLE_JS_TOKENS,
    SENSITIVE_ENV_KEY_NAMES,
    SUSPICIOUS_LIFECYCLE_HOOKS,
    TELEMETRY_PREFIX,
)
from .layer1_graph_integrity import inspect_bundled_node_modules
from .layer2_source import detect_heavy_obfuscation, resolve_pkg_script_candidate
from .shell_analyzer import (
    deobfuscate_shell_cmd,
    extract_node_targets_from_cmd,
    is_benign_local_node_script,
    is_whitelisted_command,
    match_suspicious_hook_patterns,
    resolve_script_chain,
)

SANDBOX_TELEMETRY_CACHE: Dict[str, List[Dict[str, Any]]] = {}
_NODE_PERMISSION_FLAGS: Optional[List[str]] = None


def _normalize_perm_paths(raw_paths: List[str]) -> List[str]:
    """Normalizes and deduplicates paths (with uppercase Windows drive letters for Node --permission)."""
    seen: set = set()
    out: List[str] = []
    for rp in raw_paths:
        if not rp:
            continue
        for cand in (os.path.abspath(rp), os.path.realpath(rp)):
            norm_v = os.path.normpath(cand)
            if len(norm_v) >= 2 and norm_v[1] == ":" and norm_v[0].isalpha():
                norm_v = norm_v[0].upper() + norm_v[1:]
            if norm_v not in seen:
                seen.add(norm_v)
                out.append(norm_v)
    return out


def get_node_permission_flags(
    subprocess_mod,
    allowed_read_paths: Optional[List[str]] = None,
) -> List[str]:
    """Detects once whether Node.js supports `--permission` (22+) or `--experimental-permission` (20/21)."""
    global _NODE_PERMISSION_FLAGS
    if _NODE_PERMISSION_FLAGS is None:
        detected = ["--no-warnings"]
        for flag in ("--permission", "--experimental-permission"):
            try:
                res = subprocess_mod.run(
                    ["node", "--no-warnings", flag, "--allow-fs-read=*", "-e", ""],
                    capture_output=True,
                    timeout=3,
                )
                if res.returncode == 0:
                    detected = ["--no-warnings", flag, "--allow-fs-read=*"]
                    break
            except Exception:
                continue
        _NODE_PERMISSION_FLAGS = detected

    if allowed_read_paths and len(_NODE_PERMISSION_FLAGS) >= 2 and _NODE_PERMISSION_FLAGS[1] in (
        "--permission",
        "--experimental-permission",
    ):
        scoped = _normalize_perm_paths(allowed_read_paths)
        if scoped:
            return [_NODE_PERMISSION_FLAGS[0], _NODE_PERMISSION_FLAGS[1]] + [
                f"--allow-fs-read={p}" for p in scoped
            ]
    return list(_NODE_PERMISSION_FLAGS)


def collect_sandbox_targets(
    pkg_dir: str,
    manifest: Dict[str, Any],
    is_tarball: bool = False,
    enable_whitelist: bool = True,
    nm_cache: Optional[Dict[Tuple[str, bool, int], Dict[str, Any]]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Identifies active lifecycle hooks and entrypoint JS files for Layer 3 sandbox execution."""
    active_hooks: Dict[str, str] = {}
    target_files: List[str] = []

    def add_file_if_valid(rel_or_abs: str, from_hook: bool = False):
        if not from_hook and len(target_files) >= 5:
            return
        clean_rel = rel_or_abs.strip().strip("'\"")
        if not clean_rel:
            return
        full_p = os.path.normpath(os.path.join(pkg_dir, clean_rel))
        rel_norm: Optional[str] = None
        if os.path.isfile(full_p):
            rel_norm = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
        elif from_hook:
            rel_norm = resolve_pkg_script_candidate(pkg_dir, clean_rel)
            if rel_norm:
                full_p = os.path.normpath(os.path.join(pkg_dir, rel_norm))
        if not rel_norm or not os.path.isfile(full_p):
            return
        if not from_hook:
            if IGNORED_TEST_DOC_SEG_RE.search(rel_norm):
                return
            if re.search(r"\.(test|spec|mock)\.(js|cjs|mjs)$", rel_norm, re.IGNORECASE):
                return
            try:
                if os.path.getsize(full_p) > 256 * 1024:
                    return
            except OSError:
                return
        if rel_norm not in target_files:
            target_files.append(rel_norm)

    scripts = manifest.get("scripts", {})
    if isinstance(scripts, dict):
        for hook in SUSPICIOUS_LIFECYCLE_HOOKS:
            if hook not in scripts:
                continue
            cmd = str(scripts[hook]).strip()
            if not cmd:
                continue
            bridged_bad = False
            for sub_name, sub_cmd in resolve_script_chain(cmd, scripts):
                deobf_sub = deobfuscate_shell_cmd(sub_cmd)
                if match_suspicious_hook_patterns(sub_cmd, deobf_sub, is_author_hook=False):
                    bridged_bad = True
                    active_hooks[f"{hook}->{sub_name}"] = sub_cmd
                    for tgt in extract_node_targets_from_cmd(sub_cmd) + extract_node_targets_from_cmd(deobf_sub):
                        add_file_if_valid(tgt, from_hook=True)
            if not bridged_bad and (
                is_whitelisted_command(cmd, scripts=scripts, pkg_dir=pkg_dir, enable_whitelist=enable_whitelist)
                or is_benign_local_node_script(hook, cmd, pkg_dir, SENSITIVE_ENV_KEY_NAMES, detect_heavy_obfuscation)
            ):
                continue
            active_hooks[hook] = cmd
            deobf_cmd = deobfuscate_shell_cmd(cmd)
            for tgt in extract_node_targets_from_cmd(cmd) + extract_node_targets_from_cmd(deobf_cmd):
                add_file_if_valid(tgt, from_hook=True)

        for hook in AUTHOR_PUBLISH_HOOKS:
            if hook not in scripts:
                continue
            cmd = str(scripts[hook]).strip()
            if not cmd:
                continue
            deobf_cmd = deobfuscate_shell_cmd(cmd)
            bridged_bad = False
            for sub_name, sub_cmd in resolve_script_chain(cmd, scripts):
                deobf_sub = deobfuscate_shell_cmd(sub_cmd)
                if match_suspicious_hook_patterns(sub_cmd, deobf_sub, is_author_hook=True):
                    bridged_bad = True
                    active_hooks[f"{hook}->{sub_name}"] = sub_cmd
                    for tgt in extract_node_targets_from_cmd(sub_cmd) + extract_node_targets_from_cmd(deobf_sub):
                        add_file_if_valid(tgt, from_hook=True)
            if bridged_bad or match_suspicious_hook_patterns(cmd, deobf_cmd, is_author_hook=True):
                active_hooks[hook] = cmd
                for tgt in extract_node_targets_from_cmd(cmd) + extract_node_targets_from_cmd(deobf_cmd):
                    add_file_if_valid(tgt, from_hook=True)

    main_entry = manifest.get("main")
    if isinstance(main_entry, str) and main_entry.strip():
        resolved_main = resolve_pkg_script_candidate(pkg_dir, main_entry)
        if resolved_main:
            add_file_if_valid(resolved_main)

    add_file_if_valid("index.js")
    add_file_if_valid("index.cjs")
    add_file_if_valid("index.mjs")

    bin_field = manifest.get("bin")
    if isinstance(bin_field, str) and bin_field.strip():
        resolved_bin = resolve_pkg_script_candidate(pkg_dir, bin_field)
        if resolved_bin:
            add_file_if_valid(resolved_bin)
    elif isinstance(bin_field, dict):
        added_bins = 0
        for v in bin_field.values():
            if added_bins >= 2 or len(target_files) >= 5:
                break
            if isinstance(v, str) and v.strip():
                resolved_bin = resolve_pkg_script_candidate(pkg_dir, v)
                if resolved_bin:
                    add_file_if_valid(resolved_bin)
                    added_bins += 1

    if not target_files:
        for root, dirs, files in os.walk(pkg_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            rel_parts = os.path.relpath(root, pkg_dir).replace("\\", "/").split("/")
            if ".git" in rel_parts or "node_modules" in rel_parts:
                continue
            for f in sorted(files):
                if f.endswith((".js", ".cjs", ".mjs")):
                    add_file_if_valid(os.path.join(root, f))
                    if len(target_files) >= 3:
                        break
            if len(target_files) >= 3:
                break

    nm_info = inspect_bundled_node_modules(pkg_dir, manifest=manifest, is_tarball=is_tarball, cache=nm_cache)
    if nm_info.get("needs_l2_scan"):
        added_nm = 0
        for full_p in nm_info.get("budget_code_files", []):
            if added_nm >= 3 or len(target_files) >= 5:
                break
            if full_p.lower().endswith((".js", ".cjs", ".mjs")):
                rel_nm = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
                add_file_if_valid(rel_nm)
                added_nm += 1

    return active_hooks, target_files


def should_spawn_sandbox(pkg_dir: str, active_hooks: Dict[str, str], target_files: List[str]) -> bool:
    """Checks whether the package has active hooks or JS files capable of runtime API calls."""
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


def run_node_sandbox(
    sandbox_runner_path: str,
    pkg_dir: str,
    active_hooks: Dict[str, str],
    target_files: List[str],
    subprocess_mod,
) -> List[Dict[str, Any]]:
    """Executes `scripts/sandbox_runner.js` in an isolated Node.js process."""
    cache_key = json.dumps(
        {
            "pkg": os.path.abspath(pkg_dir),
            "hooks": active_hooks,
            "files": target_files,
        },
        sort_keys=True,
    )

    if cache_key in SANDBOX_TELEMETRY_CACHE:
        return SANDBOX_TELEMETRY_CACHE[cache_key]

    if not os.path.exists(sandbox_runner_path) or not should_spawn_sandbox(pkg_dir, active_hooks, target_files):
        SANDBOX_TELEMETRY_CACHE[cache_key] = []
        return []

    runner_abs = _normalize_perm_paths([sandbox_runner_path])[0]
    pkg_abs = _normalize_perm_paths([pkg_dir])[0]
    payload_json = json.dumps({"hooks": active_hooks, "files": target_files})
    perm_flags = get_node_permission_flags(
        subprocess_mod,
        allowed_read_paths=[os.path.dirname(runner_abs), pkg_abs],
    )
    cmd = ["node"] + perm_flags + [
        runner_abs,
        pkg_abs,
        payload_json,
    ]

    events: List[Dict[str, Any]] = []
    try:
        run_kwargs: Dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "ignore",
            "timeout": 2.0,
        }
        if os.path.isdir(pkg_abs):
            run_kwargs["cwd"] = pkg_abs
        proc = subprocess_mod.run(cmd, **run_kwargs)
        stdout_lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
        telemetry_line = None
        for line in reversed(stdout_lines):
            if line.startswith(TELEMETRY_PREFIX):
                telemetry_line = line[len(TELEMETRY_PREFIX):]
                break
        if telemetry_line is None and stdout_lines:
            telemetry_line = stdout_lines[-1]
        if telemetry_line:
            data = json.loads(telemetry_line)
            events = data.get("events", [])
    except getattr(subprocess_mod, "TimeoutExpired", _std_subproc.TimeoutExpired):
        is_small_target = False
        if target_files and len(target_files) <= 2:
            try:
                is_small_target = all(
                    os.path.getsize(os.path.join(pkg_dir, rf)) < 64 * 1024
                    for rf in target_files
                )
            except OSError:
                is_small_target = False
        if active_hooks or is_small_target:
            events = [{
                "category": "SANDBOX_EVASION",
                "api": "sandbox.timeout",
                "detail": "Package execution timed out (>2.0s) in behavioral sandbox (infinite loop / stall evasion).",
                "severity": "HIGH",
            }]
    except Exception:
        events = []

    SANDBOX_TELEMETRY_CACHE[cache_key] = events
    return events


def score_sandbox_events(events: List[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]]]:
    """Correlates sandbox telemetry events into risk score and findings."""
    if not events:
        return 0, []

    score = 0
    findings: List[Dict[str, Any]] = []
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        cat = ev.get("category", "UNKNOWN")
        by_cat.setdefault(cat, []).append(ev)

    net_events = (
        by_cat.get("NETWORK_EGRESS", [])
        + by_cat.get("DNS_EXFILTRATION", [])
        + by_cat.get("RAW_SOCKET_CONNECT", [])
    )
    if net_events:
        score += 45
        sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in net_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Runtime Network / DNS Exfiltration",
            "severity": "CRITICAL",
            "detail": f"Intercepted {len(net_events)} outbound network/DNS operation(s) in sandbox ({sample_details})",
        })

    has_recon_ctx = bool(
        by_cat.get("ENV_HARVESTING")
        or by_cat.get("ENV_ENUMERATION")
        or by_cat.get("FS_SENSITIVE_READ")
        or by_cat.get("OS_FINGERPRINTING")
    )
    proc_events = [
        e for e in by_cat.get("CHILD_PROCESS_SPAWN", [])
        if e.get("phase") != "export_fuzz"
        or has_recon_ctx
        or DANGEROUS_SHELL_ARG_REGEX.search(str(e.get("detail", "")))
    ]
    if proc_events:
        score += 45
        sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in proc_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Runtime Child Process / Shell Spawn",
            "severity": "CRITICAL",
            "detail": f"Intercepted {len(proc_events)} OS child process spawn(s) in sandbox ({sample_details})",
        })

    fs_events = by_cat.get("FS_EXTERNAL_WRITE", []) + by_cat.get("FS_SENSITIVE_READ", [])
    if fs_events:
        score += 40
        sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in fs_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Runtime Filesystem Boundary Violation",
            "severity": "CRITICAL",
            "detail": f"Intercepted {len(fs_events)} sensitive/external file operation(s) in sandbox ({sample_details})",
        })

    internal_write_events = by_cat.get("FS_INTERNAL_WRITE", [])
    eval_events = by_cat.get("RUNTIME_DYNAMIC_EVAL", [])
    if internal_write_events and (eval_events or proc_events):
        score += 35
        sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in internal_write_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Runtime Dropper Payload Creation",
            "severity": "CRITICAL",
            "detail": f"Intercepted internal file write dropped alongside dynamic eval or process spawn ({sample_details})",
        })

    if eval_events:
        score += 40
        sample_details = "; ".join([e["detail"] for e in eval_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Runtime Dynamic Code Evaluation",
            "severity": "HIGH",
            "detail": f"Intercepted runtime dynamic code execution ({sample_details})",
        })

    env_events = by_cat.get("ENV_HARVESTING", [])
    if env_events:
        score += 35
        sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in env_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Runtime Credential / Environment Harvesting",
            "severity": "HIGH",
            "detail": f"Package harvested sensitive environment variables in sandbox ({sample_details})",
        })

    env_enum_events = by_cat.get("ENV_ENUMERATION", [])
    if env_enum_events:
        score += 15
        sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in env_enum_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Runtime Environment Enumeration",
            "severity": "MEDIUM",
            "detail": f"Package enumerated environment keys in sandbox ({sample_details})",
        })

    os_events = by_cat.get("OS_FINGERPRINTING", [])
    if os_events:
        high_risk_os = any(
            e.get("api") in ("os.userInfo", "os.networkInterfaces", "dns.getServers")
            or str(e.get("api", "")).startswith("shell:")
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
                "detail": f"Package collected host identity telemetry via [{apis_str}]",
            })
        else:
            score += 10
            apis_str = ", ".join(sorted(distinct_os_apis))
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Host Recon Query",
                "severity": "LOW",
                "detail": f"Package queried host property via [{apis_str}]",
            })

    evasion_events = by_cat.get("SANDBOX_EVASION", [])
    if evasion_events:
        score += 35
        sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in evasion_events[:2]])
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Sleep / Delay / Sandbox Evasion Detected",
            "severity": "HIGH",
            "detail": f"Intercepted sandbox evasion behavior ({sample_details})",
        })

    stealth_events = by_cat.get("STEALTH_EXECUTION", [])
    if stealth_events:
        score += 15
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Output Redirection / Stealth Execution",
            "severity": "MEDIUM",
            "detail": stealth_events[0]["detail"],
        })

    has_recon = bool(os_events or env_events or env_enum_events or by_cat.get("FS_SENSITIVE_READ"))
    has_exfil = bool(net_events or proc_events or by_cat.get("FS_EXTERNAL_WRITE"))
    if has_recon and has_exfil:
        score += 30
        findings.append({
            "layer": "Layer 3 - Behavioral Sandbox",
            "rule": "Behavioral Exfiltration Kill-Chain",
            "severity": "CRITICAL",
            "detail": "Correlated multi-stage behavior: Host/Credential Reconnaissance followed by External Exfiltration/Execution.",
        })

    return score, findings


def summarize_sandbox_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Builds a structured OSSF-style 4-axis summary (`commands`, `files`, `network`, `env`) plus phase counts."""
    phases = {"install": 0, "import": 0, "export_fuzz": 0}
    axes: Dict[str, Any] = {
        "commands": [],
        "files": {"read": [], "write": [], "sensitive": []},
        "network": [],
        "env": [],
    }

    def _push(target_list: List[str], val: str) -> None:
        if len(target_list) < 50 and val not in target_list:
            target_list.append(val)

    for ev in events or []:
        raw_ph = str(ev.get("phase") or "")
        ph = raw_ph if raw_ph in phases else ("export_fuzz" if raw_ph == "export_fuzz" else "import")
        phases[ph] += 1
        cat = ev.get("category", "")
        entry = f"{ev.get('api', '')}: {ev.get('detail', '')}"
        if cat == "CHILD_PROCESS_SPAWN":
            _push(axes["commands"], entry)
        elif cat == "FS_SENSITIVE_READ":
            _push(axes["files"]["sensitive"], entry)
            _push(axes["files"]["read"], entry)
        elif cat in ("FS_EXTERNAL_WRITE", "FS_INTERNAL_WRITE"):
            _push(axes["files"]["write"], entry)
        elif cat in ("NETWORK_EGRESS", "DNS_EXFILTRATION", "RAW_SOCKET_CONNECT"):
            _push(axes["network"], entry)
        elif cat in ("ENV_HARVESTING", "ENV_ENUMERATION"):
            _push(axes["env"], entry)

    return {
        "events_count": len(events or []),
        "phases": phases,
        "axes": axes,
    }


def analyze_behavioral_sandbox(
    sandbox_runner_path: str,
    pkg_dir: str,
    manifest: Dict[str, Any],
    is_tarball: bool = False,
    enable_whitelist: bool = True,
    nm_cache: Optional[Dict[Tuple[str, bool, int], Dict[str, Any]]] = None,
    run_sandbox_fn: Optional[Callable[[str, Dict[str, str], List[str]], List[Dict[str, Any]]]] = None,
    subprocess_mod=None,
    events_out: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Layer 3 orchestration calling `run_sandbox_fn` (preserves `_run_node_sandbox` monkeypatching)."""
    active_hooks, target_files = collect_sandbox_targets(
        pkg_dir,
        manifest,
        is_tarball=is_tarball,
        enable_whitelist=enable_whitelist,
        nm_cache=nm_cache,
    )
    if run_sandbox_fn is not None:
        events = run_sandbox_fn(pkg_dir, active_hooks, target_files)
    else:
        import subprocess as _std_subproc
        events = run_node_sandbox(
            sandbox_runner_path,
            pkg_dir,
            active_hooks,
            target_files,
            subprocess_mod or _std_subproc,
        )
    if events_out is not None and events:
        events_out.extend(events)
    return score_sandbox_events(events)
