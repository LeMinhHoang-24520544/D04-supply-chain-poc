"""
scripts/detector_core/layer2_source.py
Layer 2: Context-Aware Static Source Analysis + L1->L2 Install-Context Contract.
"""

import base64
import ipaddress
import math
import os
import posixpath
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import (
    CP_FUNC_NAMES,
    DANGEROUS_SHELL_ARG_REGEX,
    DECODED_PAYLOAD_INDICATORS,
    DOC_AND_CGNAT_NETS,
    EXFIL_SENSITIVE_ENV_KEY_NAMES,
    EXTENDED_SANDBOX_HOOKS,
    HARMLESS_XML_NS_RE,
    IGNORED_TEST_DOC_SEG_RE,
    INSTALL_IDENTITY_OS_RECON_FUNCS,
    MALICIOUS_EXFIL_ENDPOINT_REGEX,
    PUBLIC_DNS_IPS,
    SAFE_NON_SHELL_TOOLS,
    SENSITIVE_OS_RECON_FUNCS,
    SENSITIVE_SOURCE_PATH_REGEX,
    SOURCE_CRITICAL_EXEC_PATTERNS,
    STATIC_NON_CODE_EXTENSIONS,
    SUSPICIOUS_SCRIPT_PATTERNS,
)
from .layer1_graph_integrity import extract_github_owner_repo, inspect_bundled_node_modules
from .shell_analyzer import (
    deobfuscate_shell_cmd,
    extract_node_targets_from_cmd,
    resolve_script_chain,
    split_safe_shell_chain,
)

_JS_COMMENT_AND_LITERAL_RE = re.compile(
    r'("(?:\\[\s\S]|[^"\\\n])*"|\'(?:\\[\s\S]|[^\'\\\n])*\'|`(?:\\[\s\S]|[^`\\])*`|'
    r'(?:(?<=[=(,:!&|?~;{\[\n])|\b(?:return|case|throw|typeof|void|delete|yield|await|else|do)\b)[ \t]*/(?![/*])'
    r'(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\[\n])+/[gimsuydv]*)|'
    r'(/\*[\s\S]*?\*/|//[^\n]*)'
)
_JS_ESCAPE_DECODE_RE = re.compile(r'(\\\\)|\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))')

# Build tools legitimately spawned via execSync/exec inside install scripts (excludes echo/true/exit)
_INSTALL_SAFE_BUILD_PREFIX_RE = re.compile(
    r"^(?:npx\s+(?:-[yq]\s+|--yes\s+)?)?(?:node-gyp|@mapbox/node-pre-gyp|node-pre-gyp|"
    r"prebuild-install|node-gyp-build|napi-build|cmake-js|cmake|make|ninja|cargo|rustc|"
    r"pkg-config|tsc|esbuild|git)\b",
    re.IGNORECASE,
)


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect heavily obfuscated / high-entropy code."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = float(len(text))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_likely_minified_or_dist(rel_path: str, content: str) -> bool:
    """Determines whether a JS file is a genuine minified/bundled asset."""
    if not content or len(content) < 3000:
        return False
    norm_rel = rel_path.replace("\\", "/").lower()
    if norm_rel.endswith((".min.js", ".min.mjs", ".min.cjs", ".bundle.js", ".prod.js", ".umd.js")):
        return True
    if norm_rel.startswith(("dist/", "umd/", "bundles/", "cjs/", "esm/", "build/", "browser/dist/")) or "/dist/" in f"/{norm_rel}":
        return True
    avg_line_len = len(content) / (content.count("\n") + 1)
    if avg_line_len >= 180:
        return True
    if "__webpack_require__" in content or "parcelRequire" in content:
        return True
    if "sourceMappingURL=" in content and re.search(
        r"(?:typeof\s+exports\s*===\s*['\"]object['\"].{0,120}?module\s*!==\s*['\"]undefined['\"]|"
        r"typeof\s+define\s*===\s*['\"]function['\"].{0,120}?define\.amd|"
        r"\(\s*function\s*\(\s*global\s*,\s*factory\s*\))",
        content,
        re.DOTALL,
    ):
        return True
    return False


def strip_js_comments_safely(content: str) -> str:
    """Fast single-regex pass stripping JS line (`//`) and block (`/* ... */`) comments."""
    if not content or ("//" not in content and "/*" not in content):
        return content
    return _JS_COMMENT_AND_LITERAL_RE.sub(
        lambda m: m.group(1) if m.group(1) is not None else ("\n" if "\n" in m.group(2) else " "),
        content,
    )


def normalize_js_for_static_scan(content: str) -> str:
    """Decodes safe ASCII `\\xXX`/`\\uXXXX`, folds string literal concatenation, normalizes bracket access."""
    if not content:
        return content

    def _decode_esc(match: re.Match) -> str:
        if match.group(1):
            return match.group(1)
        hx = match.group(2) or match.group(3)
        try:
            cp = int(hx, 16)
        except ValueError:
            return match.group(0)
        if 0x20 <= cp <= 0x7E:
            ch = chr(cp)
            if ch not in ('"', "'", "\\"):
                return ch
        return match.group(0)

    norm = _JS_ESCAPE_DECODE_RE.sub(_decode_esc, content) if ("\\x" in content or "\\u" in content) else content

    def _fold_same_quote(match: re.Match, q: str) -> str:
        return f"{q}{match.group(1)}{match.group(2)}{q}"

    def _fold_any_pair(match: re.Match) -> str:
        g = match.groups()
        a = g[0] if g[0] is not None else (g[1] if g[1] is not None else g[2])
        b = g[3] if g[3] is not None else (g[4] if g[4] is not None else g[5])
        combined = a + b
        if "'" not in combined:
            return f"'{combined}'"
        if '"' not in combined:
            return f'"{combined}"'
        if "`" not in combined and "${" not in combined:
            return f"`{combined}`"
        return match.group(0)

    if "+" in norm and re.search(r"['\"`]\s*\+\s*['\"`]", norm):
        tail_guard = r"(?!\s*(?:\.(?!\.\.)|\[))"
        sq_re = re.compile(rf"'([^'\\\n]{{0,200}})'\s*\+\s*'([^'\\\n]{{0,200}})'{tail_guard}")
        dq_re = re.compile(rf'"([^"\\\n]{{0,200}})"\s*\+\s*"([^"\\\n]{{0,200}})"{tail_guard}')
        bt_re = re.compile(
            rf"`((?:(?!\$\{{)[^`\\\n]){{0,200}})`\s*\+\s*`((?:(?!\$\{{)[^`\\\n]){{0,200}})`{tail_guard}"
        )
        any_side = r"(?:'([^'\\\n]{0,200})'|\"([^\"\\\n]{0,200})\"|`((?:(?!\$\{)[^`\\\n]){0,200})`)"
        mix_any_re = re.compile(rf"{any_side}\s*\+\s*{any_side}{tail_guard}")

        for _ in range(6):
            updated = sq_re.sub(lambda m: _fold_same_quote(m, "'"), norm)
            updated = dq_re.sub(lambda m: _fold_same_quote(m, '"'), updated)
            updated = bt_re.sub(lambda m: _fold_same_quote(m, "`"), updated)
            updated = mix_any_re.sub(_fold_any_pair, updated)
            if updated == norm:
                break
            norm = updated

    if "[" in norm:
        norm = re.sub(
            r"""(?<=[\w$\)\]])\s*\[\s*(['"`])([A-Za-z_$][\w$]*)\1\s*\](?!\s*:)""",
            r".\2",
            norm,
        )
    return norm


def is_malicious_public_ipv4(ip_str: str) -> bool:
    """Validates an IPv4 string, allowing IMDS targets while filtering private/doc/DNS IPs."""
    if ip_str in ("169.254.169.254", "100.100.100.200"):
        return True
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    if any(addr in net for net in DOC_AND_CGNAT_NETS):
        return False
    if ip_str in PUBLIC_DNS_IPS:
        return False
    return True


def find_suspicious_exfil_endpoints(code_no_comments: str) -> Optional[str]:
    """Scans comment-stripped JS code for OAST/webhook/tunnel/paste/IMDS domains and raw public IPv4."""
    if not code_no_comments:
        return None
    dom_match = MALICIOUS_EXFIL_ENDPOINT_REGEX.search(code_no_comments)
    if dom_match:
        return dom_match.group(0)

    url_ip_re = re.compile(
        r"(?:https?|wss?)://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?=[/?#'\"`\s]|$)",
        re.IGNORECASE,
    )
    for m in url_ip_re.finditer(code_no_comments):
        if is_malicious_public_ipv4(m.group(1)):
            return m.group(0)

    sock_ip_re = re.compile(
        r"(?:(?:net\.(?:connect|createConnection)|tls\.connect|dgram\.createSocket|\.\s*connect)\s*\([^;\n]{0,140}?|"
        r"\bhost(?:name)?\s*:\s*)['\"`](\d{1,3}(?:\.\d{1,3}){3})['\"`]",
        re.IGNORECASE,
    )
    for m in sock_ip_re.finditer(code_no_comments):
        if is_malicious_public_ipv4(m.group(1)):
            return m.group(1)

    return None


def is_scannable_text_file(full_path: str) -> bool:
    """Returns True if `full_path` is an existing non-binary file."""
    if not os.path.isfile(full_path):
        return False
    if full_path.lower().endswith(STATIC_NON_CODE_EXTENSIONS):
        return False
    try:
        with open(full_path, "rb") as f:
            sample = f.read(512)
        return b"\x00" not in sample
    except OSError:
        return False


def resolve_pkg_script_candidate(
    pkg_dir: str,
    raw_path: str,
    base_dir: Optional[str] = None,
) -> Optional[str]:
    """Safely resolves a relative/extensionless script specifier inside `pkg_dir`."""
    if not isinstance(raw_path, str):
        return None
    cleaned = raw_path.strip().strip("'\"")
    if not cleaned or cleaned.startswith(("http://", "https://", "node:", "data:")):
        return None
    pkg_real = os.path.realpath(pkg_dir)
    root_base = base_dir or pkg_dir
    candidates = [cleaned]
    if not cleaned.endswith((".js", ".cjs", ".mjs")):
        candidates.extend([
            cleaned + ".js",
            cleaned + ".cjs",
            cleaned + ".mjs",
            os.path.join(cleaned, "index.js"),
            os.path.join(cleaned, "index.cjs"),
            os.path.join(cleaned, "index.mjs"),
        ])
    else:
        candidates.append(os.path.join(cleaned, "index.js"))

    for cand in candidates:
        full_p = os.path.normpath(os.path.join(root_base, cand))
        try:
            full_real = os.path.realpath(full_p)
            if os.path.commonpath([pkg_real, full_real]) != pkg_real:
                continue
        except ValueError:
            continue
        if not is_scannable_text_file(full_p):
            continue
        rel_norm = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
        if rel_norm.startswith("../") or "/node_modules/" in f"/{rel_norm}" or rel_norm.startswith("node_modules/"):
            continue
        return rel_norm
    return None


def _bfs_local_imports(pkg_dir: str, seed_files: Set[str], max_depth: int = 2, max_files: int = 200) -> Set[str]:
    local_import_patterns = (
        re.compile(r"""\brequire\s*\(\s*['"](\.[^'"\n]+)['"]\s*\)"""),
        re.compile(r"""\bimport\s+(?:[*\w{},\s$]+\s+from\s+)?['"](\.[^'"\n]+)['"]"""),
        re.compile(r"""\bexport\s+[\w*{},\s$]+\s+from\s+['"](\.[^'"\n]+)['"]"""),
        re.compile(r"""\bimport\s*\(\s*['"](\.[^'"\n]+)['"]\s*\)"""),
    )
    visited: Set[str] = set(seed_files)
    queue: List[Tuple[str, int]] = [(ep, 0) for ep in sorted(seed_files)]
    while queue and len(visited) < max_files:
        rel_ep, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        ep_full = os.path.normpath(os.path.join(pkg_dir, rel_ep))
        ep_dir = os.path.dirname(ep_full)
        try:
            with open(ep_full, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read(512 * 1024)
        except OSError:
            continue
        norm_src = normalize_js_for_static_scan(strip_js_comments_safely(src))
        for pat in local_import_patterns:
            for m in pat.finditer(norm_src):
                added_rel = resolve_pkg_script_candidate(pkg_dir, m.group(1), base_dir=ep_dir)
                if added_rel and added_rel not in visited:
                    visited.add(added_rel)
                    if len(visited) < max_files:
                        queue.append((added_rel, depth + 1))
    return visited


def extract_declared_entrypoints(pkg_dir: str, manifest: Dict[str, Any]) -> Set[str]:
    """Collects `main`, `bin`, `exports`, bridged lifecycle targets + 2-hop local BFS imports."""
    entrypoints: Set[str] = set()

    def add_candidate(raw_path: str, base_dir: Optional[str] = None) -> Optional[str]:
        rel_norm = resolve_pkg_script_candidate(pkg_dir, raw_path, base_dir=base_dir)
        if rel_norm:
            entrypoints.add(rel_norm)
        return rel_norm

    if isinstance(manifest.get("main"), str):
        add_candidate(manifest["main"])

    bin_field = manifest.get("bin")
    if isinstance(bin_field, str):
        add_candidate(bin_field)
    elif isinstance(bin_field, dict):
        for v in bin_field.values():
            if isinstance(v, str):
                add_candidate(v)

    def walk_exports(node: Any):
        if isinstance(node, str):
            norm_ep = node.strip().replace("\\", "/").lstrip("./")
            if norm_ep and not IGNORED_TEST_DOC_SEG_RE.search(norm_ep):
                add_candidate(node)
        elif isinstance(node, list):
            for item in node:
                walk_exports(item)
        elif isinstance(node, dict):
            for val in node.values():
                walk_exports(val)

    if "exports" in manifest:
        walk_exports(manifest["exports"])

    scripts = manifest.get("scripts", {})
    if isinstance(scripts, dict):
        seen_scripts: Set[str] = set()
        to_inspect: List[str] = [str(scripts[h]) for h in EXTENDED_SANDBOX_HOOKS if h in scripts]
        while to_inspect:
            cmd = to_inspect.pop()
            for c in (cmd, deobfuscate_shell_cmd(cmd)):
                for t in extract_node_targets_from_cmd(c):
                    add_candidate(t)
            for sub_name, sub_cmd in resolve_script_chain(cmd, scripts):
                if sub_name not in seen_scripts:
                    seen_scripts.add(sub_name)
                    to_inspect.append(sub_cmd)

    return _bfs_local_imports(pkg_dir, entrypoints)


def verify_decoded_payload_bytes(
    decoded_bytes: bytes,
    encoding_label: str,
    has_url_risk_context: bool = False,
) -> Optional[str]:
    """Semantically verifies decoded Base64/Hex bytes against `DECODED_PAYLOAD_INDICATORS`."""
    if not decoded_bytes or len(decoded_bytes) < 8:
        return None
    printable = sum(1 for b in decoded_bytes if (0x20 <= b <= 0x7E) or b in (9, 10, 13))
    if printable / len(decoded_bytes) < 0.85:
        return None

    decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
    if "-----BEGIN " in decoded_text and "-----END " in decoded_text:
        return None
    if '"version":3' in decoded_text and '"mappings":' in decoded_text:
        return None
    if "sourceMappingURL=" in decoded_text and "eval" not in decoded_text:
        return None

    cleaned = HARMLESS_XML_NS_RE.sub(" ", decoded_text)
    preview = re.sub(r"\s+", " ", decoded_text).strip()[:80]
    if DECODED_PAYLOAD_INDICATORS.search(cleaned):
        return f"Decoded {encoding_label} payload contains executable indicator: '{preview}'"
    if re.search(r"(?:https?|wss?)://[^\s'\"`<>]+", cleaned, re.IGNORECASE):
        exfil_ep = find_suspicious_exfil_endpoints(cleaned)
        if exfil_ep or has_url_risk_context:
            return f"Decoded {encoding_label} payload contains suspicious URL indicator: '{preview}'"
    return None


def inspect_encoded_strings(
    norm_code: str, has_url_risk_context: bool = False
) -> Tuple[bool, Optional[str]]:
    """Rule 2.8: Semantically verified encoded payload inspection."""
    if not norm_code:
        return False, None

    for uri_match in re.finditer(
        r"data:([^,'\"`\s]+);base64,([A-Za-z0-9+/=]{24,})['\"`](?:\s*\.\s*(?:split|slice|substring|replace)\s*\()?",
        norm_code,
        re.IGNORECASE,
    ):
        mime = uri_match.group(1).lower()
        is_manipulated = uri_match.group(0).rstrip().endswith("(")
        if not is_manipulated and (mime.startswith("image/") or mime.startswith("font/")):
            continue
        try:
            raw = base64.b64decode(uri_match.group(2), validate=True)
            verdict = verify_decoded_payload_bytes(
                raw, "Data-URI Base64", has_url_risk_context=has_url_risk_context
            )
            if verdict:
                return True, verdict
        except Exception:
            pass

    has_reverse = bool(re.search(r"\.reverse\s*\(", norm_code))
    has_b64url = bool(re.search(r"base64url", norm_code, re.IGNORECASE))
    lit_pattern = (
        r"(['\"`])([A-Za-z0-9+/=_-]{24,})\1"
        if (has_b64url or has_reverse)
        else r"(['\"`])([A-Za-z0-9+/=]{24,})\1"
    )

    for match in re.finditer(lit_pattern, norm_code):
        candidate = match.group(2)
        start_pos = max(0, match.start() - 40)
        prefix = norm_code[start_pos:match.start()].lower()

        if any(tag in prefix for tag in ("data:image/", "data:font/", "sourcemappingurl", "integrity", "sha512-")):
            ctx_window = norm_code[max(0, match.start() - 60):min(len(norm_code), match.end() + 60)]
            if not re.search(r"\.(?:split|slice|substring|replace)\s*\(", ctx_window):
                continue

        is_b64url_cand = "-" in candidate or "_" in candidate
        if not is_b64url_cand or has_b64url:
            try:
                padded = candidate + ("=" * ((4 - len(candidate) % 4) % 4)) if is_b64url_cand else candidate
                if len(padded) % 4 == 0:
                    if is_b64url_cand:
                        if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", padded):
                            raise ValueError("Invalid Base64URL")
                        raw = base64.urlsafe_b64decode(padded)
                    else:
                        raw = base64.b64decode(padded, validate=True)
                    verdict = verify_decoded_payload_bytes(
                        raw, "Base64", has_url_risk_context=has_url_risk_context
                    )
                    if verdict:
                        return True, verdict
            except Exception:
                pass

        if has_reverse:
            rev_cand = candidate[::-1]
            rev_is_b64url = "-" in rev_cand or "_" in rev_cand
            if len(rev_cand) % 4 != 1:
                try:
                    rev_padded = rev_cand + ("=" * ((4 - len(rev_cand) % 4) % 4))
                    raw_rev = None
                    if rev_is_b64url:
                        if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", rev_padded):
                            raw_rev = base64.urlsafe_b64decode(rev_padded)
                    elif len(rev_padded) % 4 == 0:
                        raw_rev = base64.b64decode(rev_padded, validate=True)
                    if raw_rev:
                        verdict = verify_decoded_payload_bytes(
                            raw_rev, "Reversed Base64", has_url_risk_context=has_url_risk_context
                        )
                        if verdict:
                            return True, verdict
                except Exception:
                    pass

        if len(candidate) >= 40 and len(candidate) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", candidate):
            try:
                raw_hex = bytes.fromhex(candidate)
                verdict = verify_decoded_payload_bytes(
                    raw_hex, "Hexadecimal", has_url_risk_context=has_url_risk_context
                )
                if verdict:
                    return True, verdict
            except Exception:
                pass

    return False, None


def is_benign_sequential_charcodes(vals: List[int]) -> bool:
    """Returns True if numeric charcodes represent a benign sequential lookup table."""
    if len(vals) < 8:
        return False
    diffs_one = sum(1 for a, b in zip(vals, vals[1:]) if b - a == 1)
    if diffs_one < max(len(vals) - 2, int(0.85 * (len(vals) - 1))):
        return False
    decoded = "".join(chr(v) for v in vals if 0 <= v <= 0x10FFFF)
    return not bool(DECODED_PAYLOAD_INDICATORS.search(decoded))


def detect_heavy_obfuscation(
    raw_content: str,
    no_comments: str,
    norm_code: Optional[str] = None,
    is_minified: bool = False,
) -> Optional[str]:
    """Rule 2.6: JSFuck, XOR loops, `_0x` identifiers, dense escapes, and numeric fromCharCode arrays."""
    for jsf_m in re.finditer(r"[!+()\[\]{}]{30,}", raw_content):
        if jsf_m.group(0).count("[]") >= 8:
            return "JSFuck bracket/operator obfuscation signature"

    cc_haystack = norm_code if norm_code is not None else no_comments

    if not is_minified:
        for cc_call in re.finditer(r"\bfrom(?:CharCode|CodePoint)\b", cc_haystack):
            win = cc_haystack[max(0, cc_call.start() - 350):min(len(cc_haystack), cc_call.end() + 200)]
            win_no_str = re.sub(r"(['\"`])(?:\\[\s\S]|(?!\1)[^\\])*\1", " ", win)
            win_no_regex = re.sub(
                r"(?<=[=(,:!&|?~;{\[\n])\s*/(?:\\.|[^/\\\n])+/[gimsuydv]*",
                " ",
                win_no_str,
            )
            if re.search(
                r"(?:charCodeAt|codePointAt)\s*\([^)]*\)\s*\^|\^\s*[^;,\n]{0,40}?(?:charCodeAt|codePointAt)\s*\(",
                win_no_regex,
            ):
                return "XOR charCodeAt/array dynamic payload decoding loop"

    obf_vars = len(re.findall(r"\b[A-Za-z0-9_$]*_0x[a-fA-F0-9]{4,}\b", no_comments))
    if obf_vars >= 5:
        return "Heavy JS obfuscation (_0x identifier arrays)"

    escape_seq_re = re.compile(
        r"(?:(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})(?:\s*['\"`]\s*\+\s*['\"`]\s*)?){10,}"
    )
    for esc_m in escape_seq_re.finditer(no_comments):
        vals = [
            int(hx, 16)
            for hx in re.findall(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))", esc_m.group(0))
            for hx in hx if hx
        ]
        ascii_count = sum(1 for v in vals if 0 <= v <= 0x7F)
        if ascii_count >= 8 and ascii_count >= len(vals) / 2:
            if not is_benign_sequential_charcodes(vals):
                return "Dense hex/unicode escape obfuscation sequence"

    direct_cc_re = re.compile(
        r"String\.from(?:CharCode|CodePoint)\s*\(\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){7,})\s*\)"
    )
    for cc_m in direct_cc_re.finditer(cc_haystack):
        nums = [
            int(tok, 16) if tok.lower().startswith("0x") else int(tok)
            for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", cc_m.group(1))
        ]
        if not is_benign_sequential_charcodes(nums):
            return "String.fromCharCode/fromCodePoint integer array obfuscation"

    num_arr_re = re.compile(r"\[\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){7,})\s*\]")

    apply_spread_re = re.compile(
        r"String\.from(?:CharCode|CodePoint)\s*\.\s*apply\s*\(|"
        r"String\.from(?:CharCode|CodePoint)\s*\(\s*\.\.\.\s*[A-Za-z_$\[]"
    )
    for ind_m in apply_spread_re.finditer(cc_haystack):
        win = cc_haystack[max(0, ind_m.start() - 300):min(len(cc_haystack), ind_m.end() + 200)]
        inline_arrays = list(num_arr_re.finditer(win))
        if not inline_arrays:
            continue
        all_benign = all(
            is_benign_sequential_charcodes([
                int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", arr_m.group(1))
            ])
            for arr_m in inline_arrays
        )
        if not all_benign:
            return "Indirect String.fromCharCode (.apply/spread) obfuscation"

    map_cc_re = re.compile(
        r"\.\s*map\s*\(\s*(?:"
        r"String\.from(?:CharCode|CodePoint)\b|"
        r"(?:function\s*\([^)]*\)\s*\{\s*(?:return\s+)?|\([^)]*\)\s*=>\s*|[A-Za-z_$][\w$]*\s*=>\s*)"
        r"[^;{}]{0,120}?\bString\.from(?:CharCode|CodePoint)\s*\([^)]*\)"
        r")"
    )
    has_obf_or_exec_ctx = bool(
        re.search(
            r"\b[A-Za-z0-9_$]*_0x[a-fA-F0-9]{4,}\b|"
            r"(?<!\.)\b(?:eval|Function|exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|"
            r"\bnew\s+Function\s*\(|\bvm\.runIn|"
            r"(?:child_process|\bcp)\s*\.\s*(?:exec|spawn)\s*\(",
            cc_haystack,
        )
    )
    for ind_m in map_cc_re.finditer(cc_haystack):
        win = cc_haystack[max(0, ind_m.start() - 300):min(len(cc_haystack), ind_m.end() + 200)]
        inline_arrays = list(num_arr_re.finditer(win))
        if inline_arrays:
            all_benign = all(
                is_benign_sequential_charcodes([
                    int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                    for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", arr_m.group(1))
                ])
                for arr_m in inline_arrays
            )
            if all_benign:
                continue
            return "Indirect String.fromCharCode (.map inline array) obfuscation"
        has_math_or_bit_op = bool(re.search(r"\^|<<|>>|[+\-~%]|\bcharCodeAt\b", ind_m.group(0)))
        if has_math_or_bit_op or has_obf_or_exec_ctx:
            return "Indirect String.fromCharCode (.map) obfuscation"

    return None


def classify_sensitive_host_path(norm_code: str) -> Tuple[int, Optional[str]]:
    """Rule 2.7: Tier 1 unconditional sensitive host paths vs Tier 2 context-gated tool configs."""
    tier1_static_re = re.compile(
        r"(['\"`])[^'\"`\n]*(?:/etc/(?:passwd|shadow|sudoers|crontab)|/proc/self/environ|"
        r"\.ssh[/\\]+(?:id_rsa|id_ed25519|authorized_keys)|~[/\\]+\.ssh|/root/\.ssh|"
        r"\.(?:bash_history|zsh_history|git-credentials|netrc))\b[^'\"`\n]*\1",
        re.IGNORECASE,
    )
    m1 = tier1_static_re.search(norm_code)
    if m1:
        return 1, m1.group(0)

    path_call = r"(?:path\.(?:(?:posix|win32)\.)?(?:join|resolve)|\b(?:join|resolve))\s*\("
    home_expr = rf"(?:{path_call}|(?:homedir(?:\s*\(\))?|process\.env\.(?:HOME|USERPROFILE)))"
    tier1_dyn_patterns = (
        rf"{home_expr}[^;\n]{{0,180}}?"
        r"(['\"`])\.ssh\1[^;\n]{0,60}?(['\"`])(?:id_rsa|id_ed25519|authorized_keys)\2",
        rf"{home_expr}[^;\n]{{0,180}}?"
        r"(['\"`])(?:\.bash_history|\.zsh_history|\.git-credentials|\.netrc)\1",
        rf"{path_call}[^;\n]{{0,120}}?(['\"`])/?etc\1[^;\n]{{0,60}}?(['\"`])(?:passwd|shadow|sudoers|crontab)\2",
        rf"{path_call}[^;\n]{{0,120}}?(['\"`])/?proc(?:/self)?\1(?:[^;\n]{{0,40}}?(['\"`])self\2)?[^;\n]{{0,60}}?(['\"`])environ\3",
    )
    for dp in tier1_dyn_patterns:
        dm = re.search(dp, norm_code, re.IGNORECASE)
        if dm:
            return 1, dm.group(0)[:80]

    tier2_static_re = re.compile(
        r"(['\"`])[^'\"`\n]*(?:\.npmrc|\.aws[/\\]+credentials|\.kube[/\\]+config|\.docker[/\\]+config\.json)\b[^'\"`\n]*\1",
        re.IGNORECASE,
    )
    m2 = tier2_static_re.search(norm_code)
    if m2:
        return 2, m2.group(0)

    tier2_dyn_patterns = (
        rf"{home_expr}[^;\n]{{0,180}}?(['\"`])\.npmrc\1",
        rf"{home_expr}[^;\n]{{0,180}}?(['\"`])\.aws\1[^;\n]{{0,60}}?(['\"`])credentials\2",
        rf"{home_expr}[^;\n]{{0,180}}?(['\"`])\.kube\1[^;\n]{{0,60}}?(['\"`])config\2",
        rf"{home_expr}[^;\n]{{0,180}}?(['\"`])\.docker\1[^;\n]{{0,60}}?(['\"`])config\.json\2",
    )
    for dp in tier2_dyn_patterns:
        dm = re.search(dp, norm_code, re.IGNORECASE)
        if dm:
            return 2, dm.group(0)[:80]

    return 0, None


def calculate_windowed_entropy(content: str, already_stripped: bool = False) -> float:
    """Computes max Shannon entropy over 512-byte sliding windows (step 256)."""
    if not content:
        return 0.0
    stripped = content if already_stripped else strip_js_comments_safely(content)
    if "data:" in stripped:
        stripped = re.sub(
            r"data:(?:image|font|audio|video)/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=\s]{24,}",
            " ",
            stripped,
            flags=re.IGNORECASE,
        )
    if "sourceMappingURL=" in stripped:
        stripped = re.sub(r"sourceMappingURL=[^\s]+", " ", stripped)
    n = len(stripped)
    if n <= 200:
        return 0.0
    if n <= 512:
        return calculate_entropy(stripped)
    max_ent = 0.0
    for start in range(0, max(1, n - 512 + 1), 256):
        ent = calculate_entropy(stripped[start:start + 512])
        if ent > max_ent:
            max_ent = ent
    tail_ent = calculate_entropy(stripped[-512:])
    return max(max_ent, tail_ent)


def extract_call_args_slice(code: str, open_idx: int, max_len: int = 400) -> str:
    """Extracts argument text up to matching `)` or statement end for taint inspection."""
    n = len(code)
    limit = min(n, max(0, open_idx) + max_len)
    if open_idx < 0 or open_idx >= n or code[open_idx] != "(":
        tail = code[max(0, open_idx):limit]
        for sep in (";", "\n"):
            idx = tail.find(sep)
            if idx != -1:
                tail = tail[:idx]
        return tail
    depth = 0
    quote = ""
    i = open_idx
    while i < limit:
        ch = code[i]
        if quote:
            if ch == "\\" and i + 1 < limit:
                i += 2
                continue
            if ch == quote:
                quote = ""
        else:
            if ch in ("'", '"', "`"):
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return code[open_idx:i + 1]
        i += 1
    return code[open_idx:limit]


def extract_js_assignments(code: str) -> List[Tuple[str, str]]:
    """ASI-aware statement extractor for JS variable assignments (`lhs = rhs`)."""
    assign_hdr_re = re.compile(
        r"(?:^|[;\n{},])\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)\s*"
    )
    n = len(code)
    pairs: List[Tuple[str, str]] = []
    for m in assign_hdr_re.finditer(code):
        lhs = m.group(1)
        start = m.end()
        limit = min(n, start + 1000)
        i = start
        depth = 0
        quote = ""
        while i < limit:
            ch = code[i]
            if quote:
                if ch == "\\" and i + 1 < limit:
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
                i += 1
                continue
            if ch in ("'", '"', "`"):
                quote = ch
                i += 1
                continue
            if ch in ("(", "[", "{"):
                depth += 1
                i += 1
                continue
            if ch in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
                i += 1
                continue
            if ch == ";" and depth == 0:
                break
            if ch == "\n" and depth == 0:
                prev_tok = code[start:i].rstrip()
                nxt_pos = i + 1
                while nxt_pos < limit and code[nxt_pos] in (" ", "\t", "\r", "\n"):
                    nxt_pos += 1
                continues_expr = bool(prev_tok and prev_tok[-1] in (",", "+", "=", "?", ":", "."))
                starts_dot_chain = nxt_pos < n and code[nxt_pos] == "."
                if not continues_expr and not starts_dot_chain:
                    break
            i += 1
        rhs = code[start:i].strip()
        if rhs:
            pairs.append((lhs, rhs))
    return pairs


def parse_js_module_bindings(
    norm_code: str, mod_names: Tuple[str, ...]
) -> Tuple[Set[str], List[Tuple[str, str]]]:
    """Extracts CJS/ESM namespace aliases and destructured/named bindings."""
    mod_alt = "|".join(re.escape(m) for m in mod_names)
    aliases: Set[str] = set()
    destructured: List[Tuple[str, str]] = []

    cjs_alias_re = re.compile(
        rf"(?:^|[;\n,]|\b(?:const|let|var))\s*([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"`](?:node:)?(?:{mod_alt})['\"`]\s*\)"
    )
    esm_alias_re = re.compile(
        rf"\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['\"`](?:node:)?(?:{mod_alt})['\"`]"
    )
    for m in cjs_alias_re.finditer(norm_code):
        aliases.add(m.group(1))
    for m in esm_alias_re.finditer(norm_code):
        aliases.add(m.group(1))

    cjs_destr_re = re.compile(
        rf"(?:^|[;\n,]|\b(?:const|let|var))\s*\{{([^}}]+)\}}\s*=\s*require\s*\(\s*['\"`](?:node:)?(?:{mod_alt})['\"`]\s*\)"
    )
    esm_destr_re = re.compile(
        rf"\bimport\s*\{{([^}}]+)\}}\s+from\s+['\"`](?:node:)?(?:{mod_alt})['\"`]"
    )
    for m in cjs_destr_re.finditer(norm_code):
        for part in m.group(1).split(","):
            pm = re.match(r"^\s*([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?\s*$", part)
            if pm:
                destructured.append((pm.group(1), pm.group(2) or pm.group(1)))
    for m in esm_destr_re.finditer(norm_code):
        for part in m.group(1).split(","):
            pm = re.match(r"^\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*$", part)
            if pm:
                destructured.append((pm.group(1), pm.group(2) or pm.group(1)))

    return aliases, destructured


def analyze_decode_eval_flows(
    norm_code: str,
    has_net_sink: bool,
    has_hook_context: bool,
    is_minified: bool = False,
) -> Tuple[bool, bool]:
    """Detects Rule 2.2 decoded-payload-to-eval flows via proximity or 1-2 hop taint."""
    code = re.sub(
        r"(?:\bnew\s+)?Function\s*\(\s*['\"`]return\s+this['\"`]\s*\)|"
        r"(?:\[\s*\]|\(\s*(?:function\s*\(\s*\)\s*\{\s*\}|\(\s*\)\s*=>\s*\{\s*\})\s*\))\s*\.\s*constructor\s*\(\s*['\"`]return\s+this['\"`]\s*\)",
        " ",
        norm_code,
    )
    has_zlib_import = bool(
        re.search(r"require\s*\(\s*['\"`](?:node:)?zlib['\"`]\s*\)|from\s+['\"`](?:node:)?zlib['\"`]", code)
    )
    decode_parts = [
        r"Buffer\.from\s*\([^;\)]{0,400},\s*['\"`](?:base64|base64url|hex)['\"`]\s*\)",
        r"Buffer\.from\s*\(\s*\[\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*(?:,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*){3,}\s*\]\s*\)",
        r"\batob\s*\(",
        r"\bString\.from(?:CharCode|CodePoint)\s*(?:\.\s*apply\s*\(|\(\s*\.\.\.|\(\s*(?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){3,}|\([^;\n]{0,120}\^)",
        r"\bzlib\.(?:unzip|gunzip|inflate|inflateRaw|brotliDecompress)(?:Sync)?\s*\(",
    ]
    if has_zlib_import:
        decode_parts.append(r"\b(?:unzip|gunzip|inflate|inflateRaw|brotliDecompress)(?:Sync)?\s*\(")
    decode_re = re.compile("|".join(decode_parts), re.IGNORECASE)

    eval_parts = [
        r"(?<!\.)\beval\s*\(",
        r"(?:globalThis|global)(?:\s*\[\s*['\"`]eval['\"`]\s*\]|\s*\.\s*eval)\s*\(",
        r"\bnew\s+Function\s*\(",
        r"(?<!\.)\bFunction\s*\(",
        r"\(\s*0\s*,\s*eval\s*\)\s*\(",
        r"\bReflect\.construct\s*\(\s*Function\b",
        r"(?:\bModule\._compile|[\w$\)\]]\s*\._compile)\s*\(",
    ]
    eval_alias_re = re.compile(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
        r"(?:eval|\(\s*0\s*,\s*eval\s*\)|(?:globalThis|global)(?:\s*\[\s*['\"`]eval['\"`]\s*\]|\s*\.\s*eval)|"
        r"(?:globalThis\s*\.\s*|global\s*\.\s*)?Function)\s*(?=[;\n]|$)"
    )
    for am in eval_alias_re.finditer(code):
        eval_parts.append(rf"(?:\bnew\s+)?\b{re.escape(am.group(1))}\s*\(")
    eval_sink_re = re.compile("|".join(eval_parts))

    has_vm_import = bool(
        re.search(r"require\s*\(\s*['\"`](?:node:)?vm['\"`]\s*\)|from\s+['\"`](?:node:)?vm['\"`]", code)
    )
    vm_parts = [
        r"\bvm\.runIn(?:New|This)?Context\s*\(",
        r"\bnew\s+vm\.Script\s*\(",
        r"\bvm\.compileFunction\s*\(",
    ]
    if has_vm_import:
        vm_parts.append(r"\b(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+Script\s*\(")
    vm_sink_re = re.compile("|".join(vm_parts))

    vm_matches = list(vm_sink_re.finditer(code))
    if is_minified:
        return False, bool(vm_matches and has_hook_context and has_net_sink)

    decode_matches = list(decode_re.finditer(code))
    eval_matches = list(eval_sink_re.finditer(code))

    has_linked_decode_eval = False
    vm_has_decode = False

    for dm in decode_matches:
        for em in eval_matches:
            if min(abs(em.start() - dm.end()), abs(dm.start() - em.end())) <= 800:
                has_linked_decode_eval = True
                break
        for vm in vm_matches:
            if min(abs(vm.start() - dm.end()), abs(dm.start() - em.end())) <= 800:
                vm_has_decode = True
                break

    if decode_matches and ((eval_matches and not has_linked_decode_eval) or (vm_matches and not vm_has_decode)):
        assigns = extract_js_assignments(code)
        tainted_vars: Set[str] = set()
        for lhs, rhs in assigns:
            if len(lhs) >= 2 and decode_re.search(rhs):
                tainted_vars.add(lhs)
        for _ in range(2):
            if not tainted_vars:
                break
            taint_ref_re = re.compile(r"\b(?:" + "|".join(re.escape(v) for v in sorted(tainted_vars)) + r")\b")
            for lhs, rhs in assigns:
                if len(lhs) >= 2 and taint_ref_re.search(rhs):
                    tainted_vars.add(lhs)

        if tainted_vars:
            taint_ref_re = re.compile(r"\b(?:" + "|".join(re.escape(v) for v in sorted(tainted_vars)) + r")\b")
            for em in eval_matches:
                open_pos = em.end() - 1 if code[em.end() - 1] == "(" else em.end()
                if taint_ref_re.search(extract_call_args_slice(code, open_pos)):
                    has_linked_decode_eval = True
                    break
            for vm in vm_matches:
                open_pos = vm.end() - 1 if code[vm.end() - 1] == "(" else vm.end()
                if taint_ref_re.search(extract_call_args_slice(code, open_pos)):
                    vm_has_decode = True
                    break

    has_risky_vm_eval = bool(vm_matches and (vm_has_decode or (has_hook_context and has_net_sink)))
    return has_linked_decode_eval, has_risky_vm_eval


def analyze_recon_and_net_sinks(norm_code: str) -> Dict[str, Any]:
    """
    Extracts host/credential recon signals alongside outbound network sinks.
    Also tracks `has_install_identity_recon` (excluding benign binary-selection OS calls
    like `os.platform()`, `os.arch()`, `os.homedir()`, `os.tmpdir()`) and `has_dns_sink`.
    """
    os_funcs: Set[str] = set()
    install_identity_funcs: Set[str] = set()
    high_risk_recon = False
    os_func_alt = "|".join(SENSITIVE_OS_RECON_FUNCS)

    os_aliases, os_destr = parse_js_module_bindings(norm_code, ("os",))
    os_target_parts = ["os"] + sorted(re.escape(t) for t in os_aliases) + [
        r"require\s*\(\s*['\"`](?:node:)?os['\"`]\s*\)"
    ]
    os_call_re = re.compile(
        rf"(?:\b(?:{'|'.join(os_target_parts[:-1])})|{os_target_parts[-1]})\s*\.\s*({os_func_alt})\s*\("
    )
    for m in os_call_re.finditer(norm_code):
        fn = m.group(1)
        os_funcs.add(fn)
        if fn in INSTALL_IDENTITY_OS_RECON_FUNCS:
            install_identity_funcs.add(fn)
        if fn in ("userInfo", "networkInterfaces"):
            high_risk_recon = True

    for orig, local in os_destr:
        if orig in SENSITIVE_OS_RECON_FUNCS and re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
            os_funcs.add(orig)
            if orig in INSTALL_IDENTITY_OS_RECON_FUNCS:
                install_identity_funcs.add(orig)
            if orig in ("userInfo", "networkInterfaces"):
                high_risk_recon = True

    has_net_sink = False
    has_dns_lookup = False
    has_dns_resolve = False
    dns_aliases, dns_destr = parse_js_module_bindings(norm_code, ("dns",))
    dns_ident_parts = ["dns"] + sorted(re.escape(t) for t in dns_aliases)
    dns_target_re_part = rf"(?:\b(?:{'|'.join(dns_ident_parts)})|require\s*\(\s*['\"`](?:node:)?dns['\"`]\s*\))"
    if re.search(rf"{dns_target_re_part}\s*\.\s*getServers\s*\(", norm_code):
        os_funcs.add("getServers")
        install_identity_funcs.add("getServers")
        high_risk_recon = True
    if re.search(rf"{dns_target_re_part}\s*\.\s*resolve\w*\s*\(", norm_code):
        has_net_sink = True
        has_dns_resolve = True
    if re.search(rf"{dns_target_re_part}\s*\.\s*lookup\s*\(", norm_code):
        has_dns_lookup = True

    for orig, local in dns_destr:
        if orig == "getServers" and re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
            os_funcs.add("getServers")
            install_identity_funcs.add("getServers")
            high_risk_recon = True
        elif orig.startswith("resolve") and re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
            has_net_sink = True
            has_dns_resolve = True
        elif orig == "lookup" and re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
            has_dns_lookup = True

    env_aliases = ["process\\.env"]
    for em in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\.env\b", norm_code):
        env_aliases.append(re.escape(em.group(1)))
    env_alt = "|".join(env_aliases)
    env_key_matches = re.findall(
        rf"(?:{env_alt})(?:\s*\.\s*|\s*\[\s*['\"`])({EXFIL_SENSITIVE_ENV_KEY_NAMES})\b|"
        rf"\{{[^}}]*\b({EXFIL_SENSITIVE_ENV_KEY_NAMES})\b[^}}]*\}}\s*=\s*(?:{env_alt})\b",
        norm_code,
    )
    matched_env_keys = {k for tup in env_key_matches for k in tup if k}
    has_bulk_env_exfil = bool(
        re.search(
            rf"\bJSON\.stringify\s*\(\s*(?:{env_alt})\s*[,)]|"
            rf"\b(?:headers|body|data|json|payload|params|query)\s*:\s*(?:{env_alt})\b",
            norm_code,
        )
    )
    env_recon_triggered = False
    if has_bulk_env_exfil:
        env_recon_triggered = True
    elif matched_env_keys:
        if matched_env_keys <= {"GITHUB_TOKEN", "GH_TOKEN"}:
            urls = re.findall(r"https?://([A-Za-z0-9.-]+)", norm_code, re.IGNORECASE)
            is_github_api_only = bool(urls) and all(
                u.lower() in ("api.github.com", "github.com") or u.lower().endswith(".github.com")
                for u in urls
            )
            if not is_github_api_only:
                env_recon_triggered = True
        else:
            env_recon_triggered = True
    if env_recon_triggered:
        high_risk_recon = True

    if (
        classify_sensitive_host_path(norm_code)[0] == 1
        or re.search(
            r"\b(?:readFile|readFileSync|createReadStream|openSync|readdirSync|readdir)\s*\("
            r"[^;\n]{0,180}?(?:\.ssh|id_rsa|id_ed25519|/etc/passwd|/etc/shadow|/etc/sudoers|/proc/self/environ)",
            norm_code,
        )
    ):
        high_risk_recon = True

    if has_dns_lookup and (
        "userInfo" in os_funcs
        or "getServers" in os_funcs
        or env_recon_triggered
        or classify_sensitive_host_path(norm_code)[0] == 1
    ):
        has_net_sink = True

    if not has_net_sink and re.search(
        r"\b(?:https?|http2)\.(?:request|get|post)\s*\(|\bfetch\s*\(|\bglobalThis\.fetch\s*\(|"
        r"\bnew\s+WebSocket\s*\(|\b(?:net|tls)\.(?:connect|createConnection)\s*\(|"
        r"\bnew\s+net\.Socket\b|\bdgram\.createSocket\s*\(|"
        r"require\s*\(\s*['\"`](?:node:)?(?:https?|http2)['\"`]\s*\)\s*\.\s*(?:request|get|post)\s*\(|"
        r"require\s*\(\s*['\"`](?:node:)?(?:net|tls)['\"`]\s*\)\s*\.\s*(?:connect|createConnection)\s*\(|"
        r"require\s*\(\s*['\"`](?:axios|got|undici|superagent|node-fetch|request)['\"`]\s*\)\s*(?:\(|\.(?:get|post|put|patch|delete|request|head|stream)\s*\()",
        norm_code,
    ):
        has_net_sink = True

    if not has_net_sink:
        http_aliases, http_destr = parse_js_module_bindings(norm_code, ("http", "https", "http2"))
        if http_aliases:
            alt = "|".join(re.escape(a) for a in sorted(http_aliases))
            if re.search(rf"\b(?:{alt})\.(?:request|get|post)\s*\(", norm_code):
                has_net_sink = True
        if not has_net_sink:
            for orig, local in http_destr:
                if orig in ("request", "get", "post") and re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
                    has_net_sink = True
                    break

    if not has_net_sink:
        sock_aliases, sock_destr = parse_js_module_bindings(norm_code, ("net", "tls", "dgram"))
        if sock_aliases:
            alt = "|".join(re.escape(a) for a in sorted(sock_aliases))
            if re.search(rf"\b(?:{alt})\.(?:connect|createConnection|createSocket)\s*\(|\bnew\s+(?:{alt})\.Socket\b", norm_code):
                has_net_sink = True
        if not has_net_sink:
            for orig, local in sock_destr:
                if orig in ("connect", "createConnection", "createSocket", "Socket") and re.search(
                    rf"\b{re.escape(local)}\s*\(", norm_code
                ):
                    has_net_sink = True
                    break

    if not has_net_sink:
        client_aliases, client_destr = parse_js_module_bindings(
            norm_code, ("axios", "got", "undici", "superagent", "node-fetch", "request")
        )
        if client_aliases:
            alt = "|".join(re.escape(a) for a in sorted(client_aliases))
            if re.search(
                rf"\b(?:{alt})\s*\(|\b(?:{alt})\.(?:get|post|put|patch|delete|request|head|stream)\s*\(",
                norm_code,
            ):
                has_net_sink = True
        if not has_net_sink:
            for orig, local in client_destr:
                if re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
                    has_net_sink = True
                    break

    return {
        "high_risk_recon": high_risk_recon,
        "os_funcs": os_funcs,
        "install_identity_funcs": install_identity_funcs,
        "has_net_sink": has_net_sink,
        "has_dns_lookup": has_dns_lookup,
        "has_dns_resolve": has_dns_resolve,
    }


def _detect_install_post_or_dns_exfil(
    norm_code: str,
    manifest: Optional[Dict[str, Any]],
    recon_info: Dict[str, Any],
) -> Optional[str]:
    """
    Install-context rule: flags HTTP POST/PUT (to non-own-repo/non-official endpoints)
    or dynamic DNS lookups/resolves inside install-reachable files.
    """
    has_post_put = bool(
        re.search(
            r"\bmethod\s*:\s*['\"`](?:POST|PUT)['\"`]|"
            r"\b(?:axios|got|superagent|request|http|https|http2)\.(?:post|put)\s*\(",
            norm_code,
            re.IGNORECASE,
        )
    )
    if has_post_put and recon_info.get("has_net_sink"):
        urls = re.findall(r"https?://([A-Za-z0-9.-]+)(/[^\s'\"`<>]*)?", norm_code, re.IGNORECASE)
        gh_pair = extract_github_owner_repo(manifest)
        official_hosts = {"registry.npmjs.org", "github.com", "api.github.com"}
        all_official = bool(urls) and all(
            (
                h.lower() in official_hosts
                and (
                    not gh_pair
                    or h.lower() == "registry.npmjs.org"
                    or f"{gh_pair[0]}/{gh_pair[1]}" in (p or "").lower()
                )
            )
            for h, p in urls
        )
        if not all_official:
            return "Outbound HTTP POST/PUT in install-time script"

    if recon_info.get("has_dns_resolve") or recon_info.get("has_dns_lookup"):
        dns_call_re = re.compile(
            r"\b(?:dns\s*\.\s*(?:resolve\w*|lookup)|resolve(?:4|6|Txt|Mx)?|lookup)\s*\("
        )
        for m in dns_call_re.finditer(norm_code):
            args_slice = extract_call_args_slice(norm_code, m.end() - 1, 240)
            if "`" in args_slice and "${" in args_slice:
                return "Dynamic template-literal DNS query in install-time script"
            if "+" in args_slice and not re.search(r"^\(\s*['\"`][A-Za-z0-9.-]+['\"`]\s*,", args_slice):
                return "Dynamic concatenated DNS query in install-time script"

    return None


def inspect_child_process_calls(
    norm_code: str,
) -> Tuple[bool, bool, bool, bool, bool]:
    """
    Inspects `child_process` invocations and returns:
    `(has_spawn_sync_binding, has_cp_calls, in_dangerous_window, only_safe_tool_spawn, only_safe_build_exec)`.
    """
    has_spawn_sync_binding = bool(
        re.search(
            r"\bprocess\.(?:binding|_linkedBinding)\s*\(\s*['\"`]spawn_sync['\"`]\s*\)",
            norm_code,
        )
    )
    cp_aliases, cp_destr = parse_js_module_bindings(norm_code, ("child_process",))
    has_cp_import = bool(
        cp_aliases
        or cp_destr
        or re.search(
            r"require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)|from\s+['\"`](?:node:)?child_process['\"`]",
            norm_code,
        )
    )

    destr_map: Dict[str, str] = {local: orig for orig, local in cp_destr if orig in CP_FUNC_NAMES}
    cp_names = "|".join(CP_FUNC_NAMES)
    cp_call_patterns = [r"(?<![.\w$])(?:" + cp_names + r")\s*\("]
    cp_call_patterns.append(
        r"require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)\s*\.\s*(?:" + cp_names + r")\s*\("
    )
    for alias in cp_aliases:
        cp_call_patterns.append(rf"\b{re.escape(alias)}\s*\.\s*(?:{cp_names})\s*\(")
    for orig, local in cp_destr:
        if orig in CP_FUNC_NAMES and local not in CP_FUNC_NAMES:
            cp_call_patterns.append(rf"(?<![.\w$]){re.escape(local)}\s*\(")
    cp_call_re = re.compile("|".join(cp_call_patterns))
    cp_calls = list(cp_call_re.finditer(norm_code)) if has_cp_import else []

    in_dangerous_window = False
    safe_tool_re = re.compile(
        r"^\(\s*(['\"`])(?:" + "|".join(re.escape(t) for t in SAFE_NON_SHELL_TOOLS) + r")\1"
    )
    lit_cmd_re = re.compile(r"^\(\s*(['\"])([^'\"\n]{1,200})\1")
    only_safe_tool_spawn = bool(cp_calls)
    only_safe_build_exec = bool(cp_calls)

    for m in cp_calls:
        win_start = max(0, m.start() - 300)
        win_end = min(len(norm_code), m.end() + 300)
        if DANGEROUS_SHELL_ARG_REGEX.search(norm_code[win_start:win_end]):
            in_dangerous_window = True
            only_safe_tool_spawn = False
            only_safe_build_exec = False
            break
        callee = m.group(0).rstrip("( \t\r\n").split(".")[-1].strip()
        orig_fn = destr_map.get(callee, callee)
        call_args = extract_call_args_slice(norm_code, m.end() - 1, 320)

        is_safe_non_shell = (
            orig_fn in ("spawn", "spawnSync", "execFile", "execFileSync")
            and bool(safe_tool_re.match(call_args))
            and not re.search(r"\bshell\s*:\s*(?:true|['\"`]\s*[^'\"`\s][^'\"`]*['\"`])", call_args)
        )
        if not is_safe_non_shell:
            only_safe_tool_spawn = False

        if not is_safe_non_shell:
            lm = lit_cmd_re.match(call_args)
            if lm:
                cmd_lit = lm.group(2).strip()
                chain_ok = split_safe_shell_chain(cmd_lit) is not None
                if not (
                    chain_ok
                    and _INSTALL_SAFE_BUILD_PREFIX_RE.match(cmd_lit)
                    and not re.search(r"https?://|ftp://|\$\(|`", cmd_lit, re.IGNORECASE)
                ):
                    only_safe_build_exec = False
            else:
                only_safe_build_exec = False

    return has_spawn_sync_binding, bool(cp_calls), in_dangerous_window, only_safe_tool_spawn, only_safe_build_exec


def analyze_source_code_detailed(
    pkg_dir: str,
    manifest: Optional[Dict[str, Any]] = None,
    is_tarball: bool = False,
    install_entry_files: Optional[Set[str]] = None,
    inline_js_snippets: Optional[List[Tuple[str, str]]] = None,
    has_hard_l1_evidence: bool = False,
    has_install_capability: bool = False,
    nm_cache: Optional[Dict[Tuple[str, bool, int], Dict[str, Any]]] = None,
) -> Tuple[int, List[Dict[str, Any]], Dict[str, Tuple[int, str, str, str]], bool, Set[str]]:
    """
    Layer 2: Context-Aware Static Source Analysis with L1->L2 Install-Context Contract.
    Returns `(total_l2_score, findings, triggered_rules, obf_corroborated, install_ctx_rules)`.
    """
    findings: List[Dict[str, Any]] = []
    triggered_rules: Dict[str, Tuple[int, str, str, str]] = {}
    install_ctx_rules: Set[str] = set()
    manifest_obj = manifest or {}
    entrypoints = extract_declared_entrypoints(pkg_dir, manifest_obj)

    install_seeds: Set[str] = set(install_entry_files or set())
    if not install_seeds and isinstance(manifest_obj.get("scripts"), dict):
        scripts = manifest_obj["scripts"]
        for hook in EXTENDED_SANDBOX_HOOKS:
            if hook not in scripts:
                continue
            cmd = str(scripts[hook]).strip()
            for c in (cmd, deobfuscate_shell_cmd(cmd)):
                for t in extract_node_targets_from_cmd(c):
                    rel = resolve_pkg_script_candidate(pkg_dir, t)
                    if rel:
                        install_seeds.add(rel)
            for _, sub_cmd in resolve_script_chain(cmd, scripts):
                for c in (sub_cmd, deobfuscate_shell_cmd(sub_cmd)):
                    for t in extract_node_targets_from_cmd(c):
                        rel = resolve_pkg_script_candidate(pkg_dir, t)
                        if rel:
                            install_seeds.add(rel)

    install_reachable_files: Set[str] = _bfs_local_imports(pkg_dir, install_seeds) if install_seeds else set()
    entrypoints.update(install_reachable_files)

    def record_l2(
        rule_key: str,
        points: int,
        rule_name: str,
        severity: str,
        detail: str,
        in_install_ctx: bool = False,
    ):
        if in_install_ctx:
            install_ctx_rules.add(rule_key)
        if rule_key not in triggered_rules or points > triggered_rules[rule_key][0]:
            triggered_rules[rule_key] = (points, rule_name, severity, detail)

    js_files: List[str] = []
    seen_js_paths: Set[str] = set()
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules"))
        rel_parts = os.path.relpath(root, pkg_dir).replace("\\", "/").split("/")
        if ".git" in rel_parts or "node_modules" in rel_parts:
            continue
        for file in sorted(files):
            full_p = os.path.join(root, file)
            rel_f = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
            is_js_ext = file.endswith((".js", ".cjs", ".mjs"))
            is_declared_ep = rel_f in entrypoints
            if not (is_js_ext or is_declared_ep):
                continue
            if not is_js_ext and not is_scannable_text_file(full_p):
                continue
            if not is_declared_ep:
                rel_l = rel_f.lower()
                if rel_l.startswith((
                    "test/", "tests/", "__tests__/", "spec/", "example/", "examples/",
                    "docs/", "doc/", "benchmark/", "benchmarks/", "fixtures/", "__mocks__/",
                    "integration/", "e2e/",
                )):
                    continue
                if any(seg in f"/{rel_l}" for seg in (
                    "/test/", "/tests/", "/__tests__/", "/test-utils/", "/testing/",
                    "/__mocks__/", "/fixtures/", "/examples/", "/example/",
                )):
                    continue
                if re.search(r"(?:\.(?:test|spec|mock)|[-_](?:test|spec|mock))\.(?:js|cjs|mjs)$", rel_l):
                    continue
            if full_p not in seen_js_paths:
                seen_js_paths.add(full_p)
                js_files.append(full_p)

    nm_info = inspect_bundled_node_modules(pkg_dir, manifest=manifest, is_tarball=is_tarball, cache=nm_cache)
    nm_script_files: List[str] = []
    if nm_info.get("should_scan"):
        for full_p in nm_info.get("budget_code_files", []):
            fp_l = full_p.lower()
            if fp_l.endswith((".js", ".cjs", ".mjs")):
                if full_p not in seen_js_paths:
                    seen_js_paths.add(full_p)
                    js_files.append(full_p)
            elif fp_l.endswith((".sh", ".bash", ".ps1", ".bat", ".cmd", ".py")):
                nm_script_files.append(full_p)

    if len(js_files) > 150:
        def _js_priority(fp: str) -> Tuple[int, int, int, str]:
            rl_raw = os.path.relpath(fp, pkg_dir).replace("\\", "/")
            rl = rl_raw.lower()
            is_inst = 0 if rl_raw in install_reachable_files else 1
            is_ep = 0 if rl_raw in entrypoints else 1
            is_dist = 1 if (
                rl.startswith(("dist/", "build/", "umd/", "bundles/", "cjs/", "esm/"))
                or "/dist/" in f"/{rl}"
                or rl.endswith(".min.js")
            ) else 0
            return (is_inst, is_ep, is_dist, rl)
        js_files = sorted(js_files, key=_js_priority)[:150]

    # Scan bundled shell/Python scripts in node_modules/
    py_net_re = re.compile(r"\b(?:urllib\.request|requests\.(?:get|post|put)|http\.client|socket\.connect|socket\.create_connection)\b")
    py_exec_re = re.compile(r"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output)|eval\(|exec\(|base64\.b64decode)\b")
    for spath in nm_script_files:
        srel = os.path.relpath(spath, pkg_dir).replace("\\", "/")
        try:
            with open(spath, "r", encoding="utf-8", errors="ignore") as sf:
                scontent = sf.read(256 * 1024)
        except Exception:
            continue
        if not scontent:
            continue
        sdeobf = deobfuscate_shell_cmd(scontent)
        nm_exfil = find_suspicious_exfil_endpoints(scontent)
        if nm_exfil:
            record_l2(
                "malicious_exfil_endpoint",
                50,
                "Suspicious Exfiltration Endpoint",
                "CRITICAL",
                f"Hardcoded external exfiltration/OAST endpoint '{nm_exfil}' in bundled {srel}",
            )
        if spath.lower().endswith(".py"):
            if (py_net_re.search(scontent) and py_exec_re.search(scontent)) or SENSITIVE_SOURCE_PATH_REGEX.search(scontent):
                record_l2(
                    "nm_bundled_script_exec",
                    45,
                    "Obfuscation / Dynamic Exec Pattern",
                    "CRITICAL",
                    f"Suspicious bundled Python execution/exfiltration payload in {srel}",
                )
        else:
            for pat, desc in SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pat, scontent, re.IGNORECASE) or re.search(pat, sdeobf, re.IGNORECASE):
                    record_l2(
                        "nm_bundled_script_exec",
                        45,
                        "Obfuscation / Dynamic Exec Pattern",
                        "CRITICAL",
                        f"{desc} in bundled {srel}",
                    )
                    break

    hook_context = has_hard_l1_evidence or has_install_capability
    non_minified_count = 0
    cross_high_risk_recon = False
    cross_os_funcs: Set[str] = set()
    cross_has_net_sink = False
    cross_has_exec_or_obf = False
    has_any_cp_call = False
    pkg_has_eval_or_vm = False
    pkg_has_net_sink = False
    pkg_has_unsafe_cp = False
    pkg_has_jsfuck_or_xor = False
    pending_tier2_paths: List[Tuple[str, str, bool]] = []
    entropy_candidates: List[Tuple[bool, str, str]] = []

    # Build scan targets list: real files + inline `node -e` snippets
    inline_map: Dict[str, str] = {}
    for idx_sn, (virt_name, snip_code) in enumerate(inline_js_snippets or []):
        uniq_name = f"{virt_name}#{idx_sn}" if virt_name in inline_map else virt_name
        inline_map[uniq_name] = snip_code
    scan_items: List[Tuple[str, Optional[str], bool]] = [
        (
            os.path.relpath(fp, pkg_dir).replace("\\", "/"),
            fp,
            os.path.relpath(fp, pkg_dir).replace("\\", "/") in install_reachable_files,
        )
        for fp in js_files
    ] + [(vname, None, True) for vname in inline_map]

    for rel_path, file_path, is_install_ctx in scan_items:
        if file_path is not None:
            try:
                max_bytes = 1024 * 1024
                half_bytes = 512 * 1024
                file_size = os.path.getsize(file_path)
                with open(file_path, "rb") as f:
                    if file_size <= max_bytes:
                        content = f.read(max_bytes).decode("utf-8", errors="ignore")
                    else:
                        head = f.read(half_bytes).decode("utf-8", errors="ignore")
                        f.seek(max(0, file_size - half_bytes))
                        tail = f.read(half_bytes).decode("utf-8", errors="ignore")
                        content = head + "\n" + tail
            except Exception:
                continue
        else:
            content = inline_map.get(rel_path, "")

        if not content:
            continue

        is_minified = False if file_path is None else is_likely_minified_or_dist(rel_path, content)
        if not is_minified:
            non_minified_count += 1
        no_comments = strip_js_comments_safely(content)
        norm_code = normalize_js_for_static_scan(no_comments)

        # 1. Critical inline dynamic evaluation patterns (+45 CRITICAL)
        has_crit_exec = False
        for pattern, desc in SOURCE_CRITICAL_EXEC_PATTERNS:
            if re.search(pattern, norm_code, re.IGNORECASE):
                has_crit_exec = True
                record_l2(
                    "inline_encoded_eval",
                    45,
                    "Obfuscation / Dynamic Exec Pattern",
                    "CRITICAL",
                    f"{desc} detected in {rel_path}",
                )

        # 3. Malicious Exfil / OAST / IMDS / Public IP Endpoints (+50 CRITICAL)
        exfil_hit = find_suspicious_exfil_endpoints(norm_code)
        if exfil_hit:
            record_l2(
                "malicious_exfil_endpoint",
                50,
                "Suspicious Exfiltration Endpoint",
                "CRITICAL",
                f"Hardcoded external exfiltration/OAST/IMDS endpoint '{exfil_hit}' in {rel_path}",
            )
        bare_bot_match = (
            re.search(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks/", norm_code, re.IGNORECASE)
            if not exfil_hit
            else None
        )

        # 4. Recon + Net Sinks
        recon_info = analyze_recon_and_net_sinks(norm_code)
        file_high_risk_recon = recon_info["high_risk_recon"]
        file_os_funcs = recon_info["os_funcs"]
        file_install_id_funcs = recon_info["install_identity_funcs"]
        file_has_net_sink = recon_info["has_net_sink"] or bool(exfil_hit)
        file_has_strong_recon = bool(file_high_risk_recon or len(file_os_funcs) >= 2)

        if not is_minified:
            if file_high_risk_recon:
                cross_high_risk_recon = True
            cross_os_funcs.update(file_os_funcs)
            if file_has_net_sink:
                cross_has_net_sink = True

        if file_has_strong_recon and file_has_net_sink and not is_minified:
            record_l2(
                "static_recon_exfil_flow",
                45,
                "Host Fingerprinting & Exfiltration Flow",
                "CRITICAL",
                f"File {rel_path} combines host/credential fingerprinting with outbound network/DNS calls",
            )
        elif is_install_ctx and not is_minified and (file_high_risk_recon or file_install_id_funcs) and file_has_net_sink:
            record_l2(
                "install_identity_exfil",
                40,
                "Host Fingerprinting & Exfiltration Flow",
                "CRITICAL",
                f"Install-time script {rel_path} pairs host/identity recon ({', '.join(sorted(file_install_id_funcs)) or 'credential/env'}) with outbound network",
            )

        if is_install_ctx and not is_minified:
            inst_exfil_reason = _detect_install_post_or_dns_exfil(norm_code, manifest, recon_info)
            if inst_exfil_reason:
                record_l2(
                    "install_post_or_dns_exfil",
                    35,
                    "Suspicious Install-Time Data Exfiltration",
                    "HIGH",
                    f"{inst_exfil_reason} in {rel_path}",
                )

        # 2. Decode -> Eval / Contextual VM
        has_linked_decode_eval, has_risky_vm_eval = analyze_decode_eval_flows(
            norm_code, file_has_net_sink, hook_context, is_minified=is_minified
        )
        if has_linked_decode_eval or has_risky_vm_eval:
            detail_msg = (
                f"Decoded Buffer/zlib/Base64 payload linked to dynamic eval/Function in {rel_path}"
                if has_linked_decode_eval
                else f"Contextual vm.runIn*/vm.Script execution paired with decode/network/hook in {rel_path}"
            )
            record_l2(
                "inline_encoded_eval",
                45,
                "Obfuscation / Dynamic Exec Pattern",
                "CRITICAL",
                detail_msg,
            )

        # 5. Context-aware child_process inspection
        (
            has_spawn_sync_binding,
            has_cp_calls,
            in_dangerous_window,
            only_safe_tool_spawn,
            only_safe_build_exec,
        ) = inspect_child_process_calls(norm_code)

        if has_spawn_sync_binding:
            record_l2(
                "child_process_high",
                45,
                "Obfuscation / Dynamic Exec Pattern",
                "CRITICAL",
                f"Low-level process.binding/linkedBinding('spawn_sync') evasion in {rel_path}",
            )
        elif has_cp_calls:
            if in_dangerous_window or has_linked_decode_eval:
                record_l2(
                    "child_process_high",
                    45,
                    "Obfuscation / Dynamic Exec Pattern",
                    "CRITICAL",
                    f"High-risk OS child_process execution with shell/encoded payload in {rel_path}",
                )
            elif not only_safe_tool_spawn and not only_safe_build_exec and not is_minified:
                if is_install_ctx or len(js_files) <= 3:
                    record_l2(
                        "child_process_low",
                        20,
                        "Direct Child Process Invocation",
                        "MEDIUM",
                        f"Direct child_process invocation in {'install-time' if is_install_ctx else 'small package'} file {rel_path}",
                        in_install_ctx=is_install_ctx,
                    )

        is_unsafe_cp = bool(has_spawn_sync_binding or (has_cp_calls and not only_safe_tool_spawn and not only_safe_build_exec))
        if is_unsafe_cp:
            has_any_cp_call = True
            pkg_has_unsafe_cp = True
        if file_has_net_sink:
            pkg_has_net_sink = True

        eval_check_src = re.sub(
            r"(?:\bnew\s+)?Function\s*\(\s*['\"`]return\s+this['\"`]\s*\)",
            " ",
            norm_code,
        )
        has_file_eval_or_vm = bool(
            has_crit_exec
            or has_linked_decode_eval
            or has_risky_vm_eval
            or re.search(
                r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(|(?<!\.)\bFunction\s*\(|"
                r"(?:globalThis|global)\s*(?:\.\s*eval|\[\s*['\"`]eval['\"`]\s*\])\s*\(|"
                r"\bReflect\.construct\s*\(\s*Function\b|\bModule\._compile\s*\(|"
                r"\bvm\.(?:runIn(?:New|This)?Context|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(",
                eval_check_src,
            )
        )
        if has_file_eval_or_vm:
            pkg_has_eval_or_vm = True

        if (
            has_crit_exec
            or has_linked_decode_eval
            or has_risky_vm_eval
            or has_spawn_sync_binding
            or in_dangerous_window
        ):
            cross_has_exec_or_obf = True

        # 6. Heavy Obfuscation Signatures (+40 HIGH)
        obf_desc = detect_heavy_obfuscation(
            content, no_comments, norm_code=norm_code, is_minified=is_minified
        )
        if obf_desc:
            cross_has_exec_or_obf = True
            if obf_desc.startswith(("JSFuck", "XOR")):
                pkg_has_jsfuck_or_xor = True
            record_l2(
                "heavy_js_obfuscation",
                40,
                "Obfuscation / Dynamic Exec Pattern",
                "HIGH",
                f"{obf_desc} detected in {rel_path}",
            )

        if bare_bot_match and (
            has_hard_l1_evidence
            or (
                not is_minified
                and (
                    is_install_ctx
                    or file_has_strong_recon
                    or has_crit_exec
                    or has_linked_decode_eval
                    or is_unsafe_cp
                    or bool(obf_desc)
                )
            )
        ):
            pkg_has_net_sink = True
            if not is_minified:
                cross_has_net_sink = True
            record_l2(
                "malicious_exfil_endpoint",
                50,
                "Suspicious Exfiltration Endpoint",
                "CRITICAL",
                f"Exfiltration webhook/bot endpoint '{bare_bot_match.group(0)}' paired with risky context in {rel_path}",
            )

        # 7. Sensitive Host Path Targeting (Tier 1 +40, Tier 2 context-gated)
        path_tier, path_desc = classify_sensitive_host_path(norm_code)
        if path_tier == 1 and path_desc:
            record_l2(
                "sensitive_host_path",
                40,
                "Sensitive Host Path Targeting",
                "HIGH",
                f"Direct reference to sensitive OS path in {rel_path}: {path_desc}",
            )
        elif path_tier == 2 and path_desc:
            has_file_risk_context = bool(
                file_has_net_sink
                or has_crit_exec
                or has_linked_decode_eval
                or has_risky_vm_eval
                or is_unsafe_cp
                or obf_desc
                or has_hard_l1_evidence
            )
            if has_file_risk_context:
                record_l2(
                    "sensitive_host_path",
                    40,
                    "Sensitive Host Path Targeting",
                    "HIGH",
                    f"Credential/tool config path targeted alongside network/exec/obfuscation in {rel_path}: {path_desc}",
                )
            else:
                pending_tier2_paths.append((rel_path, path_desc, is_install_ctx))
                if "sensitive_host_path" not in triggered_rules:
                    record_l2(
                        "sensitive_host_path_cfg",
                        15,
                        "Config File Reference",
                        "MEDIUM",
                        f"Standalone credential/config file reference in {rel_path}: {path_desc}",
                    )

        # 8. Semantically Verified Encoded Payload Artifact (+40 HIGH)
        has_explicit_decode_call = bool(re.search(r"\b(?:Buffer\.from|atob)\s*\(|\.reverse\s*\(", norm_code))
        has_b64_url_risk_ctx = bool(
            has_explicit_decode_call
            and (
                file_has_net_sink
                or has_crit_exec
                or has_linked_decode_eval
                or has_risky_vm_eval
                or is_unsafe_cp
                or obf_desc
                or has_hard_l1_evidence
                or is_install_ctx
            )
        )
        b64_flagged, b64_detail = inspect_encoded_strings(norm_code, has_url_risk_context=has_b64_url_risk_ctx)
        if b64_flagged and b64_detail:
            cross_has_exec_or_obf = True
            record_l2(
                "verified_b64_artifact",
                40,
                "Long Encoded String Artifact",
                "HIGH",
                f"{b64_detail} in {rel_path}",
            )

        # 9. Whitespace Padding Cloaking & Windowed Entropy
        if re.search(r"[ \t]{200,}|\t{50,}", content):
            record_l2(
                "whitespace_cloaking",
                20,
                "Whitespace Padding Cloaking",
                "MEDIUM",
                f"Suspicious horizontal whitespace padding (>=200 spaces/tabs or >=50 tabs) in {rel_path}",
                in_install_ctx=is_install_ctx,
            )

        if len(content) > 200 and file_path is not None:
            entropy_candidates.append((is_minified, no_comments[:262144], rel_path))

    # Cross-file recon -> exfil correlation
    if (
        "static_recon_exfil_flow" not in triggered_rules
        and 0 < non_minified_count <= 5
        and len(js_files) <= 15
        and (cross_high_risk_recon or len(cross_os_funcs) >= 2)
        and cross_has_net_sink
    ):
        record_l2(
            "static_recon_exfil_flow",
            45,
            "Host Fingerprinting & Exfiltration Flow",
            "CRITICAL",
            f"Cross-file correlation across {non_minified_count} source files combines host/credential recon with outbound network/DNS calls",
        )

    # Tier 2 cross-file correlation (do NOT promote merely on bare install capability!)
    if "sensitive_host_path" in triggered_rules:
        triggered_rules.pop("sensitive_host_path_cfg", None)
    elif pending_tier2_paths:
        small_pkg_net = 0 < non_minified_count <= 5 and len(js_files) <= 15 and cross_has_net_sink
        has_install_tier2_net = cross_has_net_sink and any(in_inst for _, _, in_inst in pending_tier2_paths)
        if (
            cross_has_exec_or_obf
            or small_pkg_net
            or has_hard_l1_evidence
            or has_install_tier2_net
            or "static_recon_exfil_flow" in triggered_rules
            or "install_identity_exfil" in triggered_rules
        ):
            t2_rel, t2_desc, _ = pending_tier2_paths[0]
            triggered_rules.pop("sensitive_host_path_cfg", None)
            record_l2(
                "sensitive_host_path",
                40,
                "Sensitive Host Path Targeting",
                "HIGH",
                f"Credential/tool config path targeted alongside cross-file network/exec/obfuscation in {t2_rel}: {t2_desc}",
            )

    has_entropy_support = bool(
        has_hard_l1_evidence
        or has_any_cp_call
        or any(k != "sensitive_host_path_cfg" for k in triggered_rules)
    )
    if entropy_candidates and has_entropy_support:
        pending_entropy_alerts: List[Tuple[float, str]] = []
        for cand_minified, cand_src, cand_rel in entropy_candidates:
            win_entropy = calculate_windowed_entropy(cand_src, already_stripped=True)
            if (not cand_minified and win_entropy > 5.65) or win_entropy > 6.15:
                pending_entropy_alerts.append((win_entropy, cand_rel))
        if pending_entropy_alerts:
            max_ent, max_rel = max(pending_entropy_alerts, key=lambda x: x[0])
            record_l2(
                "high_entropy_source",
                15,
                "High Entropy Code Section",
                "MEDIUM",
                f"Windowed entropy of {max_rel} reaches {max_ent:.2f} (packed/obfuscated indicator)",
            )

    obf_corroborated = bool(
        pkg_has_jsfuck_or_xor
        or pkg_has_eval_or_vm
        or pkg_has_net_sink
        or pkg_has_unsafe_cp
        or "whitespace_cloaking" in triggered_rules
        or "sensitive_host_path" in triggered_rules
    )

    total_l2_score = 0
    for pts, rule_name, severity, detail in triggered_rules.values():
        total_l2_score += pts
        findings.append({
            "layer": "Layer 2 - Source Code",
            "rule": rule_name,
            "severity": severity,
            "detail": detail,
        })

    return total_l2_score, findings, triggered_rules, obf_corroborated, install_ctx_rules
