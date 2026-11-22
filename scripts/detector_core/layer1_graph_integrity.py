"""
scripts/detector_core/layer1_graph_integrity.py
Layer 1B (Dependency Graph & Bundled node_modules) and Layer 1C (Artifact SRI Integrity & Tarball Structure).
"""

import base64
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import tarfile
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from .constants import (
    MALICIOUS_EXFIL_ENDPOINT_REGEX,
    POPULAR_NPM_PACKAGES,
    TRUSTED_DEPENDENCY_HOSTS,
    TRUSTED_OFFICIAL_SCOPES,
)


def extract_github_owner_repo(manifest: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
    """Extracts lowercased `(owner, repo)` if manifest declares a GitHub repository."""
    if not isinstance(manifest, dict):
        return None
    repo = manifest.get("repository")
    if isinstance(repo, dict):
        repo_url = str(repo.get("url", "")).strip()
    elif isinstance(repo, str):
        repo_url = repo.strip()
    else:
        return None
    if not repo_url:
        return None

    m_gh = re.search(r"(?:^github:|github\.com[:/])([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", repo_url, re.IGNORECASE)
    if m_gh:
        owner = m_gh.group(1).lower()
        repo_name = m_gh.group(2).lower()
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        return (owner, repo_name)

    if "://" not in repo_url and ":" not in repo_url:
        m_short = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", repo_url)
        if m_short:
            return (m_short.group(1).lower(), m_short.group(2).lower())
    return None


def is_untrusted_dependency_url(
    spec: str,
    manifest: Optional[Dict[str, Any]] = None,
    allow_raw_own_repo: bool = True,
) -> bool:
    """
    Returns True when a dependency spec is an explicit URL or SCP-style Git URL pointing
    outside trusted hosts, uses raw IP addresses, references mutable Gists, or points to
    `raw.githubusercontent.com` outside the root package's own repo.
    """
    cleaned = spec.strip()
    if cleaned.lower().startswith("npm:"):
        npm_target = cleaned[4:].strip()
        at_idx = npm_target.find("@", 1) if npm_target.startswith("@") else npm_target.find("@")
        if at_idx == -1:
            return False
        cleaned = npm_target[at_idx + 1:].strip()

    if re.match(r"^gist:", cleaned, re.IGNORECASE):
        return True

    host = ""
    url_path = ""
    if re.match(r"^(?:git\+)?(?:https?|ssh|git)://", cleaned, re.IGNORECASE):
        normalized_url = re.sub(r"^git\+", "", cleaned, count=1, flags=re.IGNORECASE)
        try:
            parsed = urlparse(normalized_url)
            host = (parsed.hostname or "").lower().rstrip(".")
            url_path = parsed.path or ""
        except ValueError:
            return True
    else:
        m_scp = re.fullmatch(
            r"(?:git\+)?([A-Za-z0-9._-]+)@(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):([^\s]+)",
            cleaned,
            re.IGNORECASE,
        )
        if not m_scp:
            return False
        host = m_scp.group(2).lower().rstrip(".")
        url_path = m_scp.group(3)

    if not host:
        return True

    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    if re.fullmatch(r"(?:\d+|0x[0-9a-f]+)", host, re.IGNORECASE):
        return True

    if host in ("gist.github.com", "gist.githubusercontent.com"):
        return True

    if host == "raw.githubusercontent.com":
        if not allow_raw_own_repo:
            return True
        declared = extract_github_owner_repo(manifest)
        path_parts = [p for p in url_path.split("/") if p]
        if not declared or len(path_parts) < 2:
            return True
        url_owner, url_repo = path_parts[0].lower(), path_parts[1].lower()
        if url_repo.endswith(".git"):
            url_repo = url_repo[:-4]
        return (url_owner, url_repo) != declared

    is_trusted = any(
        host == trusted or host.endswith("." + trusted)
        for trusted in TRUSTED_DEPENDENCY_HOSTS
    )
    return not is_trusted


def is_traversal_file_spec(pkg_dir: str, spec: str) -> bool:
    """Detects `file:` / `link:` specs that escape the package root via traversal or absolute paths."""
    cleaned = unquote(spec.strip())
    if not re.match(r"^(?:file|link):", cleaned, re.IGNORECASE):
        return False
    target = re.sub(r"^(?:file|link):", "", cleaned, count=1, flags=re.IGNORECASE).strip()
    if not target:
        return False
    norm_target = target.replace("\\", "/")
    if norm_target.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", norm_target):
        return True
    resolved_posix = posixpath.normpath(norm_target)
    if resolved_posix == ".." or resolved_posix.startswith("../"):
        return True
    abs_pkg = os.path.abspath(pkg_dir)
    abs_target = os.path.abspath(os.path.join(abs_pkg, target))
    try:
        return os.path.commonpath([abs_pkg, abs_target]) != abs_pkg
    except ValueError:
        return True


def extract_package_key_name(raw_key: str) -> str:
    """Normalizes dependency / override / resolution keys like `**/@babel/parser` or `foo>bar@^1.0`."""
    part = raw_key.strip().split(">")[-1].strip()
    if "/" in part:
        segs = [s for s in part.split("/") if s]
        if len(segs) >= 2 and segs[-2].startswith("@"):
            part = f"{segs[-2]}/{segs[-1]}".strip()
        elif segs:
            part = segs[-1].strip()
    if part.startswith("@"):
        at_idx = part.find("@", 1)
        if at_idx != -1:
            part = part[:at_idx]
    else:
        at_idx = part.find("@")
        if at_idx != -1:
            part = part[:at_idx]
    return part.strip().lower()


def is_suspicious_npm_alias(
    alias_key: str,
    spec: str,
    manifest: Optional[Dict[str, Any]] = None,
    pkg_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """Detects `npm:` protocol alias hijacking while permitting standard compat aliases."""
    cleaned = spec.strip()
    if not cleaned.lower().startswith("npm:"):
        return False, ""
    body = cleaned[4:].strip()
    if not body:
        return False, ""

    at_idx = body.find("@", 1) if body.startswith("@") else body.find("@")
    if at_idx != -1:
        target_pkg = body[:at_idx].strip().lower()
        ver_part = body[at_idx + 1:].strip()
    else:
        target_pkg = body.strip().lower()
        ver_part = ""

    if ver_part:
        if is_untrusted_dependency_url(ver_part, manifest):
            return True, f"{alias_key} -> {spec} (untrusted tarball URL)"
        if pkg_dir and is_traversal_file_spec(pkg_dir, ver_part):
            return True, f"{alias_key} -> {spec} (path traversal target)"

    root_name = str(manifest.get("name", "")).strip().lower() if isinstance(manifest, dict) else ""
    root_scope = (root_name.split("/")[0] + "/") if "/" in root_name else ""
    key_base = extract_package_key_name(alias_key)
    if not key_base or key_base == "*" or target_pkg == key_base:
        return False, ""

    key_unscoped = key_base.split("/")[-1] if "/" in key_base else key_base
    target_unscoped = target_pkg.split("/")[-1] if "/" in target_pkg else target_pkg

    if target_pkg in POPULAR_NPM_PACKAGES or target_unscoped in POPULAR_NPM_PACKAGES:
        return False, ""
    if root_scope and target_pkg.startswith(root_scope):
        return False, ""
    if any(target_pkg.startswith(sc) for sc in TRUSTED_OFFICIAL_SCOPES):
        return False, ""
    if key_unscoped == target_unscoped:
        return False, ""
    if min(len(key_unscoped), len(target_unscoped)) >= 3 and (
        key_unscoped in target_unscoped or target_unscoped in key_unscoped
    ):
        return False, ""

    suffix_re = r"(?:[-_.]?(?:cjs|esm|compat|legacy|v?\d+(?:[_.-]\d+)*))+$"
    if re.sub(suffix_re, "", key_unscoped) == re.sub(suffix_re, "", target_unscoped):
        return False, ""

    return True, f"{alias_key} -> {spec} (redirects to unrelated package '{target_pkg}')"


def inspect_bundled_node_modules_impl(
    pkg_dir: str,
    manifest: Optional[Dict[str, Any]] = None,
    is_tarball: bool = False,
    budget: int = 50,
) -> Dict[str, Any]:
    """
    Inspects `node_modules/` to distinguish legitimate dev npm installs from undeclared/bundled payloads,
    and prioritizes real code files up to `budget`.
    """
    nm_dir = os.path.join(pkg_dir, "node_modules")
    empty_res = {
        "exists": False,
        "has_valid_nm_lock": False,
        "is_valid_dev_lock": False,
        "should_scan": False,
        "needs_l2_scan": False,
        "total_files": 0,
        "undeclared_code_files": [],
        "bundled_code_files": [],
        "budget_code_files": [],
    }
    if not os.path.isdir(nm_dir):
        return empty_res

    bundled_only: Set[str] = set()
    all_declared: Set[str] = set()
    if isinstance(manifest, dict):
        for key in ("bundledDependencies", "bundleDependencies"):
            val = manifest.get(key)
            if isinstance(val, list):
                for item in val:
                    name_l = str(item).strip().lower()
                    if name_l:
                        bundled_only.add(name_l)
                        all_declared.add(name_l)
        for key in ("dependencies", "optionalDependencies", "devDependencies"):
            val = manifest.get(key)
            if isinstance(val, dict):
                for dep_k in val.keys():
                    name_l = str(dep_k).strip().lower()
                    if name_l:
                        all_declared.add(name_l)

    nm_lock_path = os.path.join(nm_dir, ".package-lock.json")
    has_valid_nm_lock = False
    nm_lock_declared_pkgs: Set[str] = set()
    if not is_tarball and os.path.isfile(nm_lock_path):
        try:
            with open(nm_lock_path, "r", encoding="utf-8", errors="ignore") as f:
                nm_lock_obj = json.load(f)
            if (
                isinstance(nm_lock_obj, dict)
                and nm_lock_obj.get("lockfileVersion") in (2, 3)
                and isinstance(nm_lock_obj.get("packages"), dict)
                and len(nm_lock_obj["packages"]) > 0
            ):
                lock_pkgs_map = nm_lock_obj["packages"]
                lock_valid = True
                valid_entries = 0
                for lk_key, lk_val in lock_pkgs_map.items():
                    lk_str = str(lk_key).strip()
                    if not lk_str:
                        continue
                    if not lk_str.startswith("node_modules/") or not isinstance(lk_val, dict):
                        lock_valid = False
                        break
                    ver_s = lk_val.get("version")
                    res_s = lk_val.get("resolved")
                    if not ver_s and not res_s:
                        lock_valid = False
                        break
                    if isinstance(res_s, str) and res_s.strip():
                        r_clean = res_s.strip()
                        if is_untrusted_dependency_url(r_clean, manifest=None, allow_raw_own_repo=False) or is_traversal_file_spec(pkg_dir, r_clean):
                            lock_valid = False
                            break
                        if lk_val.get("link") is True and is_traversal_file_spec(pkg_dir, f"file:{r_clean}"):
                            lock_valid = False
                            break
                    if isinstance(ver_s, str) and ver_s.strip():
                        v_clean = ver_s.strip()
                        if is_untrusted_dependency_url(v_clean, manifest=None, allow_raw_own_repo=False) or is_traversal_file_spec(pkg_dir, v_clean):
                            lock_valid = False
                            break
                    valid_entries += 1
                    rest = lk_str[len("node_modules/"):]
                    if "/node_modules/" not in rest:
                        nm_lock_declared_pkgs.add(rest.lower())
                if lock_valid and valid_entries > 0:
                    has_valid_nm_lock = True
        except Exception:
            has_valid_nm_lock = False

    code_exts = (".js", ".cjs", ".mjs", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".py")
    all_code_check_exts = code_exts + (".node",)

    top_pkgs: Set[str] = set()
    has_stray_root_code = False
    has_hidden_code_dir = False
    standard_dev_dot_dirs = {".bin", ".cache", ".vite", ".pnpm", ".modules.yaml"}
    try:
        top_entries = sorted(os.listdir(nm_dir))
    except OSError:
        top_entries = []

    for entry in top_entries:
        entry_path = os.path.join(nm_dir, entry)
        entry_l = entry.lower()
        if entry == ".package-lock.json":
            continue
        if os.path.isfile(entry_path):
            if entry_l.endswith(all_code_check_exts):
                has_stray_root_code = True
            continue
        if not os.path.isdir(entry_path):
            continue
        if entry.startswith("@"):
            try:
                for sub in sorted(os.listdir(entry_path)):
                    if os.path.isdir(os.path.join(entry_path, sub)):
                        top_pkgs.add(f"{entry}/{sub}".lower())
            except OSError:
                pass
        elif entry.startswith("."):
            if not (has_valid_nm_lock and entry_l in standard_dev_dot_dirs):
                has_hidden_code_dir = True
        else:
            top_pkgs.add(entry_l)

    dev_allowed_pkgs = all_declared | (nm_lock_declared_pkgs if has_valid_nm_lock else set())
    undeclared_dev_pkgs = {p for p in top_pkgs if p not in dev_allowed_pkgs}
    is_valid_dev_lock = (
        has_valid_nm_lock
        and (not is_tarball)
        and (not has_stray_root_code)
        and (not has_hidden_code_dir)
        and len(undeclared_dev_pkgs) == 0
    )

    if is_valid_dev_lock and len(bundled_only) == 0:
        return {
            **empty_res,
            "exists": True,
            "has_valid_nm_lock": True,
            "is_valid_dev_lock": True,
        }

    suspicious_peek_re = re.compile(
        r"eval\s*\(|new\s+Function|Buffer\.from|\batob\s*\(|child_process|"
        r"\[\s*['\"][^'\"]{1,8}['\"]\s*\+\s*['\"][^'\"]{1,8}['\"]\s*\]|"
        r"(?:globalThis|global|window|this)\s*\[\s*['\"](?:eval|Function|require)['\"]\s*\]|"
        r"\[['\"](?:eval|constructor|require)['\"]\]|"
        r"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|https?\.(?:request|get)|http2\.connect)\s*\(|"
        r"\b(?:fetch|axios|request|curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,120}https?://|"
        r"require\s*\(\s*['\"](?:node:)?(?:fs|os|net|dns|http|https|child_process|vm|dgram|tls)['\"]|"
        r"_0x[a-f0-9]{4,}|(?:\\x[0-9a-f]{2}){6,}|(?:\\u[0-9a-f]{4}){5,}|"
        r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}|/dev/(?:tcp|udp)/|"
        r"\b(?:curl|wget|powershell|pwsh|base64|subprocess|urllib)\b",
        re.IGNORECASE,
    )

    total_walked = 0
    total_code_files = 0
    non_code_per_pkg: Dict[str, int] = {}
    max_non_code_per_pkg = 200
    max_code_files = 2000
    max_total_walk = 50000

    undeclared_code_files: List[str] = []
    bundled_code_files: List[str] = []
    candidates: List[Tuple[Tuple[int, int, int, str], str]] = []

    for root, dirs, files in os.walk(nm_dir):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        files = sorted(files)

        rel_dir = os.path.relpath(root, nm_dir).replace("\\", "/")
        parts = [p for p in rel_dir.split("/") if p and p != "."]
        top_pkg = ""
        if parts:
            if parts[0].startswith("@") and len(parts) >= 2:
                top_pkg = f"{parts[0]}/{parts[1]}".lower()
            else:
                top_pkg = parts[0].lower()

        pkg_bucket_key = top_pkg or "__root__"
        is_bundled = bool(top_pkg and top_pkg in bundled_only)
        is_undeclared_against_bundle = not is_bundled
        is_undeclared_all = (not top_pkg) or (top_pkg not in all_declared)

        for fname in files:
            fname_l = fname.lower()
            is_code_any = fname_l.endswith(all_code_check_exts)
            if not is_code_any:
                cnt = non_code_per_pkg.get(pkg_bucket_key, 0)
                if cnt >= max_non_code_per_pkg:
                    continue
                non_code_per_pkg[pkg_bucket_key] = cnt + 1
                total_walked += 1
                if total_walked >= max_total_walk:
                    break
                continue

            total_walked += 1
            total_code_files += 1
            full_p = os.path.join(root, fname)
            rel_file = f"{rel_dir}/{fname}" if parts else fname

            if not is_valid_dev_lock and is_undeclared_against_bundle:
                if len(undeclared_code_files) < 15:
                    undeclared_code_files.append(rel_file)
            if is_bundled and len(bundled_code_files) < 15:
                bundled_code_files.append(rel_file)

            if fname_l.endswith(code_exts) and not fname_l.endswith(".d.ts"):
                try:
                    fsize = os.path.getsize(full_p)
                except OSError:
                    fsize = 0
                has_sig = False
                if fsize > 10:
                    try:
                        with open(full_p, "rb") as cf:
                            if fsize < 256 * 1024:
                                peek_text = cf.read().decode("utf-8", errors="ignore")
                            else:
                                head = cf.read(65536).decode("utf-8", errors="ignore")
                                mid_pos = max(0, (fsize // 2) - 32768)
                                cf.seek(mid_pos)
                                mid = cf.read(65536).decode("utf-8", errors="ignore")
                                cf.seek(max(0, fsize - 65536))
                                tail = cf.read(65536).decode("utf-8", errors="ignore")
                                peek_text = f"{head}\n{mid}\n{tail}"
                        code_lines = [
                            ln for ln in peek_text.splitlines()
                            if not re.match(r"^\s*(?://|/\*|\*|#(?!!))", ln)
                        ]
                        filtered_peek = "\n".join(code_lines)
                        has_sig = bool(
                            suspicious_peek_re.search(filtered_peek)
                            or MALICIOUS_EXFIL_ENDPOINT_REGEX.search(filtered_peek)
                        )
                    except Exception:
                        has_sig = False

                tier_pkg = 0 if is_undeclared_all else (1 if is_bundled else 2)
                tier_sig = 0 if has_sig else (1 if fsize >= 40 else 2)
                tier_entry = 0 if fname_l in ("index.js", "main.js", "install.js", "postinstall.js", "preinstall.js") else 1
                candidates.append(((tier_pkg, tier_sig, tier_entry, rel_file), full_p))

            if total_code_files >= max_code_files or total_walked >= max_total_walk:
                break
        if total_code_files >= max_code_files or total_walked >= max_total_walk:
            break

    candidates.sort(key=lambda item: item[0])
    budget_code_files = [fp for _, fp in candidates[:budget]]

    should_scan = bool(budget_code_files) and (
        not is_valid_dev_lock or is_tarball or bool(bundled_only) or bool(undeclared_dev_pkgs)
    )
    needs_l2_scan = should_scan and (
        bool(undeclared_code_files) or bool(bundled_code_files) or not is_valid_dev_lock or is_tarball
    )

    return {
        "exists": total_walked > 0 or bool(top_entries),
        "has_valid_nm_lock": has_valid_nm_lock,
        "is_valid_dev_lock": is_valid_dev_lock,
        "should_scan": should_scan,
        "needs_l2_scan": needs_l2_scan,
        "total_files": total_walked,
        "undeclared_code_files": undeclared_code_files,
        "bundled_code_files": bundled_code_files,
        "budget_code_files": budget_code_files,
    }


def inspect_bundled_node_modules(
    pkg_dir: str,
    manifest: Optional[Dict[str, Any]] = None,
    is_tarball: bool = False,
    budget: int = 50,
    cache: Optional[Dict[Tuple[str, bool, int], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Cached wrapper around `inspect_bundled_node_modules_impl`."""
    if cache is None:
        return inspect_bundled_node_modules_impl(pkg_dir, manifest=manifest, is_tarball=is_tarball, budget=budget)
    cache_key = (os.path.abspath(pkg_dir), bool(is_tarball), int(budget))
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
    res = inspect_bundled_node_modules_impl(pkg_dir, manifest=manifest, is_tarball=is_tarball, budget=budget)
    if len(cache) >= 8:
        cache.clear()
    cache[cache_key] = res
    return res


def analyze_dependency_graph(
    pkg_dir: str,
    manifest: Dict[str, Any],
    is_tarball: bool = False,
    nm_cache: Optional[Dict[Tuple[str, bool, int], Dict[str, Any]]] = None,
) -> Tuple[int, List[Dict[str, Any]], Dict[str, Any]]:
    """Layer 1B: Dependency Graph & Graph Feature Analysis."""
    score = 0
    findings: List[Dict[str, Any]] = []
    manifest_name = str(manifest.get("name", "")).strip()
    pkg_name = manifest_name or os.path.basename(pkg_dir)

    dep_fields = ["dependencies", "optionalDependencies"]
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
                    "scope": field,
                })

    lockfile_candidates = [
        os.path.join(pkg_dir, "package-lock.json"),
        os.path.join(pkg_dir, "npm-shrinkwrap.json"),
    ]
    has_lockfile = False
    transitive_count = 0
    estimated_depth = 1 if direct_deps else 0
    lockfile_poisoned: List[str] = []

    def _lock_url_reason(raw_spec: str) -> Optional[str]:
        if is_untrusted_dependency_url(raw_spec, manifest=None, allow_raw_own_repo=False):
            if "raw.githubusercontent.com" in raw_spec.lower():
                return "mutable raw branch URL in lockfile"
            return "untrusted host URL"
        if is_traversal_file_spec(pkg_dir, raw_spec):
            return "path traversal target"
        return None

    def _check_lock_entry(entry_name: str, entry_obj: Dict[str, Any], lf_name: str) -> None:
        resolved_val = entry_obj.get("resolved")
        if isinstance(resolved_val, str) and resolved_val.strip():
            r_str = resolved_val.strip()
            url_reason = _lock_url_reason(r_str)
            if url_reason:
                lockfile_poisoned.append(f"{lf_name}:{entry_name} -> {r_str} ({url_reason})")
            elif entry_obj.get("link") is True and is_traversal_file_spec(pkg_dir, f"file:{r_str}"):
                lockfile_poisoned.append(f"{lf_name}:{entry_name} -> {r_str} (symlink escape)")
        ver_val = entry_obj.get("version")
        if isinstance(ver_val, str) and ver_val.strip():
            v_str = ver_val.strip()
            ver_reason = _lock_url_reason(v_str)
            if ver_reason:
                lockfile_poisoned.append(f"{lf_name}:{entry_name} -> {v_str} ({ver_reason})")
            else:
                bad_alias, reason = is_suspicious_npm_alias(entry_name, v_str, manifest=None, pkg_dir=pkg_dir)
                if bad_alias:
                    lockfile_poisoned.append(f"{lf_name}:{reason}")

    def _walk_v1_deps(deps_dict: Any, depth: int, lf_name: str) -> None:
        nonlocal estimated_depth, transitive_count
        if not isinstance(deps_dict, dict) or depth > 50:
            return
        if depth > estimated_depth and deps_dict:
            estimated_depth = depth
        for dep_k, dep_v in deps_dict.items():
            if not isinstance(dep_v, dict):
                continue
            if dep_k not in direct_deps and dep_k != pkg_name and depth > 1:
                transitive_count += 1
            _check_lock_entry(str(dep_k), dep_v, lf_name)
            nested_requires = dep_v.get("requires", {})
            if isinstance(nested_requires, dict):
                for req_k, req_v in list(nested_requires.items())[:20]:
                    edges.append({
                        "from": str(dep_k),
                        "to": str(req_k),
                        "version_spec": str(req_v),
                        "scope": "transitive",
                    })
            nested_deps = dep_v.get("dependencies")
            if isinstance(nested_deps, dict):
                _walk_v1_deps(nested_deps, depth + 1, lf_name)

    for lf_path in lockfile_candidates:
        if not os.path.isfile(lf_path):
            continue
        has_lockfile = True
        lf_name = os.path.basename(lf_path)
        try:
            with open(lf_path, "r", encoding="utf-8", errors="ignore") as lf:
                lock_data = json.load(lf)
            if not isinstance(lock_data, dict):
                continue

            lock_pkgs = lock_data.get("packages", {})
            if isinstance(lock_pkgs, dict):
                for k, v in lock_pkgs.items():
                    if not isinstance(v, dict):
                        continue
                    clean_node = k.split("node_modules/")[-1] if k else pkg_name
                    if k:
                        depth = k.count("node_modules/")
                        if depth > estimated_depth:
                            estimated_depth = depth
                        if clean_node not in direct_deps and clean_node != pkg_name:
                            transitive_count += 1
                    _check_lock_entry(clean_node, v, lf_name)
                    sub_deps = v.get("dependencies", {})
                    if isinstance(sub_deps, dict):
                        for sub_d, sub_v in list(sub_deps.items())[:20]:
                            edges.append({
                                "from": clean_node,
                                "to": str(sub_d),
                                "version_spec": str(sub_v),
                                "scope": "transitive",
                            })

            v1_deps = lock_data.get("dependencies", {})
            if isinstance(v1_deps, dict) and v1_deps:
                _walk_v1_deps(v1_deps, 1, lf_name)
        except Exception:
            pass

    all_manifest_deps: Dict[str, str] = dict(direct_deps)
    for extra_field in ("devDependencies", "peerDependencies"):
        extra_obj = manifest.get(extra_field, {})
        if isinstance(extra_obj, dict):
            for dk, dv in extra_obj.items():
                all_manifest_deps.setdefault(str(dk).strip(), str(dv).strip())

    untrusted_deps = []
    for dep_name, spec in direct_deps.items():
        if is_untrusted_dependency_url(spec, manifest):
            untrusted_deps.append(f"{dep_name} -> {spec}")

    if untrusted_deps:
        score += 40
        findings.append({
            "layer": "Layer 1 - Dependency Graph",
            "rule": "Non-Registry / Untrusted Dependency Source",
            "severity": "HIGH",
            "detail": f"Dependency resolves from untrusted external host URL: {', '.join(untrusted_deps[:3])}",
        })

    if manifest_name and manifest_name in direct_deps:
        score += 20
        findings.append({
            "layer": "Layer 1 - Dependency Graph",
            "rule": "Runtime Self-Dependency",
            "severity": "MEDIUM",
            "detail": f"Package '{manifest_name}' declares itself in runtime dependencies.",
        })

    traversal_deps = []
    for dep_name, spec in all_manifest_deps.items():
        if is_traversal_file_spec(pkg_dir, spec):
            traversal_deps.append(f"{dep_name} -> {spec}")
    if traversal_deps:
        score += 40
        findings.append({
            "layer": "Layer 1 - Dependency Graph",
            "rule": "File / Link Dependency Path Traversal",
            "severity": "HIGH",
            "detail": f"Local file:/link: dependency escapes package root: {', '.join(traversal_deps[:3])}",
        })

    alias_hijacks = []
    for dep_name, spec in direct_deps.items():
        is_bad_alias, alias_reason = is_suspicious_npm_alias(dep_name, spec, manifest, pkg_dir)
        if is_bad_alias:
            alias_hijacks.append(alias_reason)
    if alias_hijacks:
        score += 40
        findings.append({
            "layer": "Layer 1 - Dependency Graph",
            "rule": "Protocol Alias Hijacking",
            "severity": "HIGH",
            "detail": f"Suspicious npm: alias redirect detected: {', '.join(alias_hijacks[:3])}",
        })

    override_hijacks: List[str] = []

    def _walk_overrides(obj: Any, parent_key: str, origin: str, depth: int = 0) -> None:
        if depth > 20:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k).strip()
                eff_key = parent_key if k_str == "." and parent_key else k_str
                _walk_overrides(v, eff_key, origin, depth + 1)
        elif isinstance(obj, str) and parent_key:
            val_str = obj.strip()
            if is_untrusted_dependency_url(val_str, manifest):
                override_hijacks.append(f"{origin}[{parent_key}] -> {val_str} (untrusted URL)")
            elif is_traversal_file_spec(pkg_dir, val_str):
                override_hijacks.append(f"{origin}[{parent_key}] -> {val_str} (path traversal)")
            else:
                bad_alias, reason = is_suspicious_npm_alias(parent_key, val_str, manifest, pkg_dir)
                if bad_alias:
                    override_hijacks.append(f"{origin}:{reason}")

    if isinstance(manifest.get("overrides"), dict):
        _walk_overrides(manifest["overrides"], "", "overrides")
    if isinstance(manifest.get("resolutions"), dict):
        _walk_overrides(manifest["resolutions"], "", "resolutions")
    pnpm_cfg = manifest.get("pnpm")
    if isinstance(pnpm_cfg, dict) and isinstance(pnpm_cfg.get("overrides"), dict):
        _walk_overrides(pnpm_cfg["overrides"], "", "pnpm.overrides")

    if override_hijacks:
        score += 40
        findings.append({
            "layer": "Layer 1 - Dependency Graph",
            "rule": "Overrides / Resolutions Hijacking",
            "severity": "HIGH",
            "detail": f"Malicious dependency override/resolution target detected: {', '.join(override_hijacks[:3])}",
        })

    if lockfile_poisoned:
        score += 45
        findings.append({
            "layer": "Layer 1 - Dependency Graph",
            "rule": "Lockfile Resolved URL Poisoning",
            "severity": "CRITICAL",
            "detail": f"Lockfile resolves dependency from poisoned or untrusted location: {', '.join(lockfile_poisoned[:3])}",
        })

    nm_info = inspect_bundled_node_modules(pkg_dir, manifest, is_tarball=is_tarball, cache=nm_cache)
    if not nm_info.get("is_valid_dev_lock") and nm_info.get("undeclared_code_files"):
        score += 20
        findings.append({
            "layer": "Layer 1 - Dependency Graph",
            "rule": "Pre-bundled node_modules Detected",
            "severity": "MEDIUM",
            "detail": (
                f"Undeclared pre-bundled code inside node_modules/ ({nm_info['total_files']} scanned files): "
                f"{', '.join(nm_info['undeclared_code_files'][:3])}"
            ),
        })

    graph_metadata = {
        "root_package": pkg_name,
        "direct_dependencies_count": len(direct_deps),
        "transitive_dependencies_count": transitive_count,
        "total_nodes": 1 + len(direct_deps) + transitive_count,
        "estimated_depth": estimated_depth,
        "has_lockfile": has_lockfile,
        "anomalies_detected": len(findings),
        "edges": edges[:30],
    }

    return score, findings, graph_metadata


def inspect_tarball_structure(tarball_path: str) -> List[str]:
    """Inspects a tarball for Tar Slip, symlink/hardlink escape, and Tar Clobbering."""
    anomalies: List[str] = []
    if not tarball_path or not os.path.isfile(tarball_path):
        return anomalies

    seen_files: Dict[str, int] = {}
    manifest_paths: List[str] = []

    try:
        with tarfile.open(tarball_path, "r:*") as tar:
            for m in tar.getmembers():
                raw_name = m.name or ""
                norm_name = raw_name.replace("\\", "/")
                parts = [p for p in norm_name.split("/") if p]

                if norm_name.startswith("/") or bool(re.match(r"^[A-Za-z]:", norm_name)) or ".." in parts:
                    anomalies.append(f"Tar Slip path traversal member: '{raw_name}'")
                    continue

                canon_rel = posixpath.normpath(norm_name)
                if canon_rel == ".":
                    canon_rel = ""

                if m.issym() or m.islnk():
                    linkname = (m.linkname or "").replace("\\", "/").strip()
                    link_parts = [p for p in linkname.split("/") if p]
                    if (
                        not linkname
                        or linkname.startswith("/")
                        or bool(re.match(r"^[A-Za-z]:", linkname))
                        or ".." in (link_parts if m.islnk() else [])
                    ):
                        anomalies.append(f"Unsafe link member '{raw_name}' -> '{linkname}'")
                        continue

                    if m.issym():
                        parent_dir = posixpath.dirname(canon_rel)
                        resolved = posixpath.normpath(posixpath.join(parent_dir, linkname))
                        in_package_dir = canon_rel == "package" or canon_rel.startswith("package/")
                        escapes_top = resolved == ".." or resolved.startswith("../") or resolved.startswith("/")
                        escapes_pkg = in_package_dir and not (resolved == "package" or resolved.startswith("package/"))
                        if escapes_top or escapes_pkg:
                            anomalies.append(f"Symlink escape '{raw_name}' -> '{linkname}'")
                            continue
                    elif m.islnk():
                        resolved = posixpath.normpath(linkname)
                        in_package_dir = canon_rel == "package" or canon_rel.startswith("package/")
                        escapes_top = resolved == ".." or resolved.startswith("../") or resolved.startswith("/")
                        escapes_pkg = in_package_dir and not (resolved == "package" or resolved.startswith("package/"))
                        if escapes_top or escapes_pkg:
                            anomalies.append(f"Hardlink escape '{raw_name}' -> '{linkname}'")
                            continue

                if not m.isdir() and canon_rel:
                    norm_key = canon_rel.lower()
                    seen_files[norm_key] = seen_files.get(norm_key, 0) + 1
                    if norm_key in ("package/package.json", "package.json"):
                        manifest_paths.append(canon_rel)
                    if seen_files[norm_key] > 1:
                        if norm_key in ("package/package.json", "package.json"):
                            anomalies.append(f"Duplicate manifest entry (Tar Clobbering): '{raw_name}'")
                        else:
                            anomalies.append(f"Duplicate file entry (Tar Clobbering): '{raw_name}'")

        if "package/package.json" in [p.lower() for p in manifest_paths] and "package.json" in [p.lower() for p in manifest_paths]:
            anomalies.append("Conflicting root package.json and package/package.json entries (Manifest Confusion)")
    except Exception as e:
        anomalies.append(f"Unreadable or malformed tarball structure: {e}")

    return anomalies


def verify_artifact_integrity(tarball_path: str, expected_sha512: str) -> Dict[str, Any]:
    """Verifies artifact integrity against SRI hashes (`sha512`/`sha384`/`sha256`/`sha1`)."""
    if not os.path.exists(tarball_path):
        return {
            "status": "FAIL",
            "reason": f"Artifact file not found: {tarball_path}",
            "tarball": tarball_path,
            "expected_hash": expected_sha512,
            "actual_hash": None,
            "matched": False,
        }

    with open(tarball_path, "rb") as f:
        data = f.read()

    algo_map = {
        "sha512": hashlib.sha512,
        "sha384": hashlib.sha384,
        "sha256": hashlib.sha256,
        "sha1": hashlib.sha1,
    }

    expected_str = (expected_sha512 or "").strip()
    tokens = expected_str.split()

    recognized_checks: List[Tuple[str, bool]] = []
    computed_parts: List[str] = []
    digest_cache: Dict[str, str] = {}

    for token in tokens:
        m = re.match(r"^(sha512|sha384|sha256|sha1)-(.+)$", token, re.IGNORECASE)
        if not m:
            continue
        algo = m.group(1).lower()
        if algo not in digest_cache:
            digest = algo_map[algo](data).digest()
            digest_cache[algo] = f"{algo}-" + base64.b64encode(digest).decode("utf-8")
        actual_token = digest_cache[algo]
        expected_normalized = f"{algo}-{m.group(2)}"
        computed_parts.append(actual_token)
        recognized_checks.append((algo, actual_token == expected_normalized))

    if recognized_checks:
        actual_hash = " ".join(computed_parts)
        matched = all(is_ok for _, is_ok in recognized_checks)
    else:
        digest = hashlib.sha512(data).digest()
        actual_hash = "sha512-" + base64.b64encode(digest).decode("utf-8")
        matched = bool(expected_str) and (actual_hash == expected_str)

    return {
        "status": "PASS" if matched else "FAIL",
        "tarball": tarball_path,
        "expected_hash": expected_sha512,
        "actual_hash": actual_hash,
        "matched": matched,
    }


def analyze_artifact_integrity(
    pkg_dir: str,
    manifest: Dict[str, Any],
    tarball_path: Optional[str] = None,
    expected_sha512: Optional[str] = None,
) -> Tuple[int, List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Layer 1C: Automated Artifact Hash & Structural Integrity Verification."""
    score = 0
    findings: List[Dict[str, Any]] = []
    resolved_tarball = tarball_path
    resolved_expected = expected_sha512

    if not resolved_tarball or not resolved_expected:
        candidate_manifests = [
            os.path.join(pkg_dir, "dist", "integrity_manifest.json"),
            os.path.join(pkg_dir, "integrity_manifest.json"),
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

    if not resolved_expected:
        dist_obj = manifest.get("dist", {})
        if isinstance(dist_obj, dict) and dist_obj.get("integrity"):
            resolved_expected = str(dist_obj["integrity"]).strip()
            if not resolved_tarball and dist_obj.get("local_tarball"):
                lt = str(dist_obj["local_tarball"])
                resolved_tarball = os.path.join(pkg_dir, lt) if not os.path.isabs(lt) else lt

    if not resolved_tarball:
        return 0, [], None

    struct_anomalies = inspect_tarball_structure(resolved_tarball) if os.path.isfile(resolved_tarball) else []
    integrity_res: Optional[Dict[str, Any]] = None

    if resolved_expected:
        integrity_res = verify_artifact_integrity(resolved_tarball, resolved_expected)
        if not integrity_res.get("matched", False):
            score += 50
            findings.append({
                "layer": "Layer 1 - Integrity",
                "rule": "Artifact Hash Tampering Detected",
                "severity": "CRITICAL",
                "detail": (
                    f"SRI hash mismatch on '{os.path.basename(resolved_tarball)}': "
                    f"expected {resolved_expected[:28]}..., got {str(integrity_res.get('actual_hash'))[:28]}..."
                ),
            })
        elif not struct_anomalies:
            findings.append({
                "layer": "Layer 1 - Integrity",
                "rule": "Artifact Integrity Verified",
                "severity": "INFO",
                "detail": f"Tarball '{os.path.basename(resolved_tarball)}' matches expected SRI integrity hash.",
            })

    if struct_anomalies:
        score += 50
        findings.append({
            "layer": "Layer 1 - Integrity",
            "rule": "Tarball Structural / Path Traversal Attack",
            "severity": "CRITICAL",
            "detail": f"Structural exploit detected in '{os.path.basename(resolved_tarball)}': {'; '.join(struct_anomalies[:3])}",
        })
        if integrity_res is None:
            integrity_res = {
                "status": "FAIL",
                "tarball": resolved_tarball,
                "expected_hash": None,
                "actual_hash": None,
                "matched": False,
                "structural_anomalies": struct_anomalies,
            }
        else:
            integrity_res["status"] = "FAIL"
            integrity_res["structural_anomalies"] = struct_anomalies

    if integrity_res is None:
        return 0, [], None

    return score, findings, integrity_res
