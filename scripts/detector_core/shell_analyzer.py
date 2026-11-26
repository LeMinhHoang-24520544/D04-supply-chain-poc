"""
scripts/detector_core/shell_analyzer.py
Structural shell command parsing, deobfuscation, build-tool validation, and binding.gyp inspection.
"""

import os
import re
import shlex
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import (
    BUILD_TOOL_SPECS,
    DANGEROUS_WHITELIST_FLAGS_RE,
    INLINE_NODE_RISK_RE,
    INLINE_SCRIPT_RISK_RE,
    NATIVE_BUILD_CMD_RE,
    SCRIPT_BRIDGE_CALL_RE,
    SINGLE_SCRIPT_BRIDGE_SEGMENT_RE,
    SUSPICIOUS_SCRIPT_PATTERNS,
    WHITELISTED_HOOK_COMMANDS,
)
from .models import CommandClassification

_INLINE_NODE_DESC = "Inline Node.js code evaluation (-e/--eval/-p/--print)"
_INLINE_SCRIPT_DESC = "Inline scripting interpreter execution (python/perl/ruby/php)"
_SHELL_INTERP_DESC = "External shell interpreter spawned"

_GYP_BENIGN_ADDON_RE = re.compile(
    r"^\s*node\s+(?:--no-warnings\s+)?-(?:p|e|-print|-eval)\s+"
    r"[\"']?\s*(?:console\.log\s*\(\s*)?require\s*\(\s*[\"'](?:node-addon-api|nan|node-gyp-build)[\"']\s*\)"
    r"(?:\.(?:include|include_dir|gyp|targets|path))?\s*\)?\s*;?\s*[\"']?\s*$",
    re.IGNORECASE,
)

_GYP_MALICIOUS_RE = re.compile(
    r"\b(?:curl|wget|netcat|ncat|socat|bitsadmin|certutil|mshta|eval|Function)\b|"
    r"(?:^|[;&|]\s*)nc\s+(?:-[A-Za-z0-9]+\s+)*(?:[A-Za-z0-9.-]+\s+\d{1,5}\b|-[lec]\b)|"
    r"(?<!\|)\|\s*(?!\|)(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|python\d?(?:\.\d+)?|perl|ruby|php|node|iex)\b|"
    r"\b(?:base64\s+(?:-d|--decode|-D)|b64decode|openssl\s+(?:enc|base64)\b.*?-d|xxd\s+-r)\b|"
    r"/dev/(?:tcp|udp)/|\bmkfifo\b|"
    r"\b(?:urllib\.request|requests\.(?:get|post|put)|http\.client|socket\.(?:connect|create_connection))\b|"
    r"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output))\b|"
    r"\b(?:child_process|writeFile|writeFileSync|chmod)\b|"
    r"(?:https?|ftp)://|/tmp/|/var/tmp/|/dev/shm/|/etc/passwd|/etc/shadow|\.npmrc|\.ssh|\.aws|"
    r"\b(?:userInfo|networkInterfaces)\b",
    re.IGNORECASE,
)

_AUX_SCRIPT_EXTS = (".sh", ".bash", ".ps1", ".bat", ".cmd", ".py")
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")


def deobfuscate_shell_cmd(cmd: str) -> str:
    """
    Normalizes shell-level obfuscation before pattern matching:
    - Replaces ${IFS} / $IFS with spaces
    - Joins intra-token single/double quotes (e.g. c'u'r'l' -> curl)
    - Strips redundant backslash escapes inside shell tokens (e.g. c\\url -> curl)
    """
    if not cmd:
        return ""
    deobf = re.sub(r"\$\{IFS\}|\$IFS\b", " ", cmd)
    deobf = re.sub(r"(?<=[A-Za-z0-9_./-])(?:''|\"\")(?=[A-Za-z0-9_./-])", "", deobf)
    for _ in range(8):
        new_deobf = re.sub(
            r"(?<=[A-Za-z0-9_./'\"-])(['\"])([A-Za-z0-9_./-]+)\1",
            r"\2",
            deobf,
        )
        new_deobf = re.sub(
            r"(['\"])([A-Za-z0-9_./-]+)\1(?=[A-Za-z0-9_./'\"-])",
            r"\2",
            new_deobf,
        )
        new_deobf = re.sub(
            r"(?<=[A-Za-z0-9_./-])['\"](?=[A-Za-z0-9_./-])",
            "",
            new_deobf,
        )
        if new_deobf == deobf:
            break
        deobf = new_deobf
    deobf = re.sub(r"(?<![A-Za-z]:)(?<=[A-Za-z])\\(?=[a-z])", "", deobf)
    deobf = re.sub(r"(?:^|(?<=\s))\\(?=[a-z]{2,})", "", deobf)
    return deobf


def tokenize_shell_tokens(cmd: str) -> List[str]:
    """Minimal quote-aware tokenizer preserving shell control operators."""
    tokens: List[str] = []
    i = 0
    n = len(cmd)
    op_chars = (";", "&", "|", ">", "<")
    while i < n:
        while i < n and cmd[i].isspace():
            i += 1
        if i >= n:
            break
        prev_i = i
        buf: List[str] = []
        quote = ""
        while i < n:
            ch = cmd[i]
            if quote:
                if ch == "\\" and quote == '"' and i + 1 < n:
                    buf.append(cmd[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
                    i += 1
                    continue
                buf.append(ch)
                i += 1
            else:
                if ch in ("'", '"'):
                    quote = ch
                    i += 1
                    continue
                if ch.isspace() or ch in op_chars:
                    break
                buf.append(ch)
                i += 1
        if buf:
            tokens.append("".join(buf))
        while i < n and cmd[i] in op_chars:
            op_ch = cmd[i]
            if i + 1 < n and (
                (op_ch in ("&", "|", ">", "<") and cmd[i + 1] == op_ch)
                or (op_ch in (">", "<", "|") and cmd[i + 1] == "&")
            ):
                tokens.append(cmd[i:i + 2])
                i += 2
            else:
                tokens.append(op_ch)
                i += 1
        if i == prev_i:
            i += 1
    return tokens


def split_safe_shell_chain(cmd: str) -> Optional[List[str]]:
    """
    Quote-aware split of `&&` / `||` command chains.
    Returns None if unquoted dangerous shell syntax (`;`, single `|`, `` ` ``, `$(`, `<`, `>`, newline) appears.
    """
    segments: List[str] = []
    buf: List[str] = []
    i = 0
    n = len(cmd)
    quote = ""
    while i < n:
        ch = cmd[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(cmd[i:i + 2])
                i += 2
                continue
            if quote == '"' and (ch == "`" or (ch == "$" and i + 1 < n and cmd[i + 1] == "(")):
                return None
            if ch == quote:
                quote = ""
            buf.append(ch)
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in (";", "`", ">", "<", "\r", "\n"):
            return None
        if ch == "$" and i + 1 < n and cmd[i + 1] == "(":
            return None
        if cmd[i:i + 2] in ("&&", "||"):
            seg = "".join(buf).strip()
            if not seg:
                return None
            segments.append(seg)
            buf = []
            i += 2
            continue
        if ch in ("&", "|"):
            return None
        buf.append(ch)
        i += 1

    if quote:
        return None
    tail = "".join(buf).strip()
    if not tail:
        return None
    segments.append(tail)
    return segments


def _shlex_split_safe(segment: str) -> Optional[List[str]]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return None


def _strip_benign_wrappers(tokens: List[str]) -> Optional[List[str]]:
    """Strips leading clean KEY=VALUE env assignments, `cross-env`, `env`, and `npx`."""
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if _ENV_ASSIGN_RE.match(tok):
            val = tok.split("=", 1)[1]
            if re.search(r"https?://|ftp://|\$\(|`|[;|<>]", val, re.IGNORECASE):
                return None
            idx += 1
            continue
        low = tok.lower()
        if low in ("cross-env", "env"):
            idx += 1
            continue
        if low == "npx":
            idx += 1
            while idx < len(tokens) and tokens[idx].lower() in ("-y", "--yes", "-q", "--quiet", "--no-install"):
                idx += 1
            continue
        break
    return tokens[idx:] if idx < len(tokens) else None


def _is_safe_build_tool_tokens(tokens: List[str], has_malicious_gyp: bool) -> Tuple[bool, bool]:
    """
    Validates tokenized command against `BUILD_TOOL_SPECS`.
    Returns `(is_safe_build_tool, used_native_tool)`.
    """
    stripped = _strip_benign_wrappers(tokens)
    if not stripped:
        return False, False

    raw_tool = stripped[0]
    tool_l = raw_tool.lower()
    if tool_l not in BUILD_TOOL_SPECS:
        tool_base = os.path.basename(raw_tool).lower()
        if tool_base in BUILD_TOOL_SPECS:
            tool_l = tool_base
        else:
            return False, False

    spec = BUILD_TOOL_SPECS[tool_l]
    is_native = bool(spec.get("native"))
    if is_native and has_malicious_gyp:
        return False, True

    args = stripped[1:]
    max_args = spec.get("max_args")
    if max_args is not None and len(args) > max_args:
        return False, is_native

    # Echo allows safe informational text only (no shell interpolation/redirection/URLs)
    if tool_l == "echo":
        joined = " ".join(args)
        if re.search(r"https?://|ftp://|\$\(|`|[|;&><\r\n]", joined, re.IGNORECASE):
            return False, False
        return True, False

    dangerous_flags: Set[str] = set(spec.get("dangerous_flags", set()))
    dangerous_prefixes: Tuple[str, ...] = tuple(spec.get("dangerous_prefixes", ()))
    subcommands: Optional[Set[str]] = spec.get("subcommands")

    positional_args: List[str] = []
    for tok in args:
        tl = tok.lower()
        if re.search(r"https?://|ftp://|\$\(|`", tok, re.IGNORECASE):
            return False, is_native
        flag_name = tl.split("=", 1)[0]
        if flag_name in dangerous_flags:
            return False, is_native
        if any(tl.startswith(pref) for pref in dangerous_prefixes):
            return False, is_native
        if not tok.startswith("-"):
            positional_args.append(tok)

    if spec.get("require_subcommand") and (not positional_args or positional_args[0].lower() not in (subcommands or set())):
        return False, is_native
    if subcommands is not None and tool_l in ("node-gyp", "exit"):
        if tool_l == "exit" and positional_args and positional_args[0] not in subcommands:
            return False, is_native
        if tool_l == "node-gyp" and positional_args and positional_args[0].lower() not in subcommands:
            # Allow flags with space-separated values such as `--arch x64` after subcommand,
            # but require first non-flag arg of node-gyp to be a valid subcommand if no subcommand found anywhere
            if not any(p.lower() in subcommands for p in positional_args):
                return False, is_native

    return True, is_native


def resolve_script_chain(
    command: str, scripts: Dict[str, Any], max_depth: int = 5
) -> List[Tuple[str, str]]:
    """Recursively resolves multi-hop `npm/yarn/pnpm run <sub_script>` chains inside package.json scripts."""
    if not isinstance(scripts, dict) or not command:
        return []
    resolved: List[Tuple[str, str]] = []
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(command, 0)]
    while queue:
        cur_cmd, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for match in SCRIPT_BRIDGE_CALL_RE.finditer(cur_cmd):
            sub_name = match.group(1)
            if sub_name in scripts and sub_name not in visited:
                visited.add(sub_name)
                sub_cmd = str(scripts[sub_name]).strip()
                resolved.append((sub_name, sub_cmd))
                queue.append((sub_cmd, depth + 1))
    return resolved


def extract_gyp_command_expansions(gyp_content: str) -> List[str]:
    """Extracts full expressions inside `<!(...)` and `<!@(...)` using balanced parenthesis counting."""
    expansions: List[str] = []
    for m in re.finditer(r"<!@?\(", gyp_content):
        start_idx = m.end()
        depth = 1
        in_quote: Optional[str] = None
        escaped = False
        i = start_idx
        n = len(gyp_content)
        while i < n and depth > 0:
            ch = gyp_content[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif in_quote is not None:
                if ch == in_quote:
                    in_quote = None
            else:
                if ch in ("'", '"'):
                    in_quote = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        expansions.append(gyp_content[start_idx:i])
                        break
            i += 1
    return expansions


def inspect_binding_gyp(
    pkg_dir: str,
    manifest: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Principled inspection of `binding.gyp` `<!(...)` / `<!@(...)` expansions, suspicious
    compiler/linker flags, and undeclared gyp shell actions.
    """
    if not pkg_dir:
        return []
    gyp_path = os.path.join(pkg_dir, "binding.gyp")
    if not os.path.isfile(gyp_path):
        return []
    try:
        with open(gyp_path, "r", encoding="utf-8", errors="ignore") as f:
            gyp_content = f.read(512 * 1024)
    except Exception:
        return []

    findings: List[str] = []
    inline_node_re = re.compile(r"\bnode\s+(?:-[^\s]*\s+)*(?:-e|--eval|-p|--print)\b", re.IGNORECASE)
    expansions = extract_gyp_command_expansions(gyp_content)
    for raw_expr in expansions:
        norm_expr = re.sub(r"\\+(['\"])", r"\1", raw_expr).strip()
        if not norm_expr or _GYP_BENIGN_ADDON_RE.match(norm_expr):
            continue
        deobf_expr = deobfuscate_shell_cmd(norm_expr)

        matched_descs = match_suspicious_hook_patterns(norm_expr, deobf_expr, is_author_hook=True)
        has_malicious_token = bool(
            _GYP_MALICIOUS_RE.search(norm_expr) or _GYP_MALICIOUS_RE.search(deobf_expr)
        )
        has_risky_node = bool(
            inline_node_re.search(deobf_expr)
            and (INLINE_NODE_RISK_RE.search(norm_expr) or INLINE_NODE_RISK_RE.search(deobf_expr))
        )

        # In binding.gyp, filter out non-risky shell/interpreter wrappers unless concrete attack token exists
        concrete_descs = [
            d for d in matched_descs
            if d not in (_INLINE_NODE_DESC, _INLINE_SCRIPT_DESC, _SHELL_INTERP_DESC)
        ]
        if concrete_descs or has_malicious_token or has_risky_node:
            preview = re.sub(r"\s+", " ", norm_expr)[:100]
            reason = (concrete_descs[0] if concrete_descs else (matched_descs[0] if matched_descs else "Suspicious command in binding.gyp"))
            findings.append(f"{reason} in binding.gyp <!({preview})")

    # Suspicious C/C++ compiler defines or linker libraries (`npm-scan` build-config-abuse)
    non_comment_gyp = "\n".join(
        ln for ln in gyp_content.splitlines() if not ln.lstrip().startswith("#")
    )
    if re.search(
        r"-D\s*[A-Za-z0-9_]+=system\b|(?:^|[\s'\"])-l(?:curl|pcap)\b|\bcurl_easy_perform\b",
        non_comment_gyp,
        re.IGNORECASE,
    ):
        findings.append("Suspicious native compiler/linker flag (-D...=system / -lcurl / -lpcap) in binding.gyp")

    # Undeclared binding.gyp shell/action execution without gypfile or native build declaration
    if isinstance(manifest, dict) and not findings:
        scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
        scripts_blob = " ".join(str(v) for v in scripts.values()).lower()
        deps_keys: Set[str] = set()
        for dk_field in ("dependencies", "devDependencies", "optionalDependencies"):
            dk_obj = manifest.get(dk_field)
            if isinstance(dk_obj, dict):
                deps_keys.update(str(k).lower() for k in dk_obj.keys())
        declared_native = (
            bool(manifest.get("gypfile"))
            or any(
                kw in scripts_blob
                for kw in ("node-gyp", "node-pre-gyp", "prebuild", "cmake-js", "napi", "gyp")
            )
            or bool(
                deps_keys & {"node-gyp", "node-pre-gyp", "@mapbox/node-pre-gyp", "prebuild", "prebuild-install", "node-gyp-build", "nan", "node-addon-api", "bindings"}
            )
        )
        has_shell_action = bool(
            re.search(
                r"['\"]actions['\"]\s*:[\s\S]{0,400}['\"](?:sh|bash|cmd|powershell|pwsh|curl|wget)['\"]",
                non_comment_gyp,
                re.IGNORECASE,
            )
        )
        if not declared_native and (expansions or has_shell_action):
            findings.append("Undeclared binding.gyp executes shell/action commands without gypfile or native build dependency")

    return findings


def _extract_balanced_paren_calls(text: str, prefix_re: re.Pattern, max_len: int = 1000) -> List[str]:
    """Extracts balanced `(...)` blocks following matches of `prefix_re`."""
    results: List[str] = []
    n = len(text)
    for m in prefix_re.finditer(text):
        i = m.end()
        depth = 1
        quote = ""
        limit = min(n, i + max_len)
        while i < limit and depth > 0:
            ch = text[i]
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
                    if depth == 0:
                        results.append(text[m.end():i])
                        break
            i += 1
    return results


def inspect_build_files(pkg_dir: str, hook_commands: List[str]) -> List[str]:
    """
    Inspects root `Makefile` / `CMakeLists.txt` when any lifecycle hook invokes `make`/`cmake`
    (`npm-scan` build-config-abuse).
    """
    if not pkg_dir or not hook_commands:
        return []
    hooks_blob = "\n".join(str(c) for c in hook_commands)
    if not re.search(r"\b(?:make|gmake|cmake|cmake-js|ninja)\b", hooks_blob, re.IGNORECASE):
        return []

    findings: List[str] = []
    makefile_path = os.path.join(pkg_dir, "Makefile")
    if os.path.isfile(makefile_path):
        try:
            with open(makefile_path, "r", encoding="utf-8", errors="ignore") as mf:
                mf_lines = [ln for ln in mf.read(256 * 1024).splitlines() if not ln.lstrip().startswith("#")]
            mf_clean = "\n".join(mf_lines)
            for shell_body in _extract_balanced_paren_calls(mf_clean, re.compile(r"\$\(\s*shell\s+")):
                deobf_body = deobfuscate_shell_cmd(shell_body)
                matched = match_suspicious_hook_patterns(shell_body, deobf_body, is_author_hook=False)
                if matched or _GYP_MALICIOUS_RE.search(shell_body):
                    preview = re.sub(r"\s+", " ", shell_body).strip()[:80]
                    findings.append(f"Suspicious $(shell ...) command in Makefile: {preview}")
                    break
        except OSError:
            pass

    cmake_path = os.path.join(pkg_dir, "CMakeLists.txt")
    if os.path.isfile(cmake_path):
        try:
            with open(cmake_path, "r", encoding="utf-8", errors="ignore") as cf:
                cf_lines = [ln for ln in cf.read(256 * 1024).splitlines() if not ln.lstrip().startswith("#")]
            cf_clean = "\n".join(cf_lines)
            for exec_body in _extract_balanced_paren_calls(cf_clean, re.compile(r"\bexecute_process\s*\(", re.IGNORECASE)):
                if re.search(
                    r"\b(?:curl|wget|powershell|pwsh|Invoke-WebRequest|bash\s+-c|sh\s+-c)\b|/dev/(?:tcp|udp)/",
                    exec_body,
                    re.IGNORECASE,
                ):
                    preview = re.sub(r"\s+", " ", exec_body).strip()[:80]
                    findings.append(f"Suspicious execute_process() command in CMakeLists.txt: {preview}")
                    break
        except OSError:
            pass

    return findings


def match_suspicious_hook_patterns(
    raw_cmd: str, deobf_cmd: str, is_author_hook: bool = False
) -> List[str]:
    """
    Matches `SUSPICIOUS_SCRIPT_PATTERNS`, requiring concrete risk tokens for inline code
    eval (`node -e/-p`, `python -c`, `sh -c`) so neutral build/platform checks are not hard-flagged.
    """
    matched: List[str] = []
    for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS:
        if re.search(pattern, raw_cmd, re.IGNORECASE) or re.search(pattern, deobf_cmd, re.IGNORECASE):
            if desc == _INLINE_NODE_DESC:
                if not (INLINE_NODE_RISK_RE.search(raw_cmd) or INLINE_NODE_RISK_RE.search(deobf_cmd)):
                    continue
            elif desc in (_INLINE_SCRIPT_DESC, _SHELL_INTERP_DESC):
                # Require either concrete risk indicator OR pipe-to-shell / malicious keyword
                if not (
                    INLINE_SCRIPT_RISK_RE.search(raw_cmd)
                    or INLINE_SCRIPT_RISK_RE.search(deobf_cmd)
                    or re.search(r"\|", deobf_cmd)
                ):
                    continue
            matched.append(desc)
    return matched


def is_whitelisted_command(
    command: str,
    scripts: Optional[Dict[str, Any]] = None,
    pkg_dir: Optional[str] = None,
    enable_whitelist: bool = True,
    _visited: Optional[Set[str]] = None,
    _gyp_malicious: Optional[bool] = None,
) -> bool:
    """
    Structural, token-based build-tool validator (handles space-separated flags, env wrappers,
    and bridged npm/yarn/pnpm scripts) with fallback safety checks.
    """
    if not enable_whitelist:
        return False
    cmd = command.strip()
    if not cmd:
        return False

    segments = split_safe_shell_chain(cmd)
    if segments is None:
        return False

    visited = _visited if _visited is not None else set()
    if len(visited) > 5:
        return False

    if _gyp_malicious is None and pkg_dir:
        _gyp_malicious = bool(inspect_binding_gyp(pkg_dir))
    gyp_bad = bool(_gyp_malicious)

    for seg in segments:
        seg_clean = seg.strip()
        if not seg_clean:
            return False

        bridge_match = SINGLE_SCRIPT_BRIDGE_SEGMENT_RE.match(seg_clean)
        if bridge_match:
            sub_name = bridge_match.group(1)
            if not isinstance(scripts, dict) or sub_name not in scripts or sub_name in visited:
                return False
            sub_cmd = str(scripts[sub_name]).strip()
            if not is_whitelisted_command(
                sub_cmd,
                scripts=scripts,
                pkg_dir=pkg_dir,
                enable_whitelist=enable_whitelist,
                _visited=visited | {sub_name},
                _gyp_malicious=gyp_bad,
            ):
                return False
            continue

        toks = _shlex_split_safe(seg_clean)
        if toks:
            ok, _ = _is_safe_build_tool_tokens(toks, gyp_bad)
            if ok:
                continue

        # Fallback compatibility with explicit WHITELISTED_HOOK_COMMANDS (guarded by global dangerous flags)
        if not DANGEROUS_WHITELIST_FLAGS_RE.search(seg_clean):
            if NATIVE_BUILD_CMD_RE.match(seg_clean) and gyp_bad:
                return False
            if any(re.search(pat, seg_clean, re.IGNORECASE) for pat in WHITELISTED_HOOK_COMMANDS):
                continue

        return False
    return True


def is_benign_local_node_script(
    hook_name: str,
    command: str,
    pkg_dir: str,
    sensitive_env_key_names: str,
    detect_heavy_obf_fn,
) -> bool:
    """
    Identifies clean short postinstall/install/prepare banner/funding scripts (<= 16 KB,
    no network/process/eval/writeFile/sensitive env/obfuscation). Never exempts `preinstall`.
    """
    if hook_name == "preinstall" or not pkg_dir:
        return False
    cleaned_cmd = re.sub(r"(?:\s*\|\|\s*(?:exit(?:\s+0)?|true)\s*)$", "", command.strip(), flags=re.IGNORECASE).strip()
    m = re.match(r"^node\s+['\"]?([A-Za-z0-9_./-]+?\.(?:js|cjs|mjs))['\"]?$", cleaned_cmd, re.IGNORECASE)
    if not m:
        return False
    rel_script = m.group(1)
    if ".." in rel_script.replace("\\", "/").split("/"):
        return False
    full_p = os.path.normpath(os.path.join(pkg_dir, rel_script))
    if not os.path.isfile(full_p):
        return False
    try:
        if os.path.getsize(full_p) > 16384:
            return False
        with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return False

    if not content.strip():
        return False

    unsafe_tokens_re = re.compile(
        r"\b(?:child_process|exec|execSync|spawn|spawnSync|execFile|execFileSync|fork|"
        r"eval|Function|vm|runInNewContext|runInThisContext|_compile|Buffer\.from|atob|unescape|zlib|"
        r"http|https|http2|net|dgram|dns|tls|fetch|WebSocket|XMLHttpRequest|axios|got|request|undici|"
        r"writeFileSync|writeFile|appendFile|createWriteStream|readFileSync|readFile|openSync|unlink|rmSync|chmod|"
        r"userInfo|networkInterfaces|hostname|process\.binding|process\._linkedBinding|process\.dlopen|mainModule|"
        r"fromCharCode|fromCodePoint|Atomics|Reflect|Proxy)\b|"
        r"import\s*\(|"
        r"\b_0x[a-fA-F0-9]{3,}\b",
        re.IGNORECASE,
    )
    if unsafe_tokens_re.search(content) or detect_heavy_obf_fn(content, content):
        return False

    for lit_m in re.finditer(r"(['\"`])([A-Za-z0-9+/=]{32,})\1", content):
        lit = lit_m.group(2)
        if len(set(lit)) < 8:
            continue
        has_upper = any("A" <= c <= "Z" for c in lit)
        has_lower = any("a" <= c <= "z" for c in lit)
        has_digit = any("0" <= c <= "9" for c in lit)
        if (has_upper and has_lower and has_digit) or (re.fullmatch(r"[0-9a-fA-F]{32,}", lit) and len(set(lit)) >= 8):
            return False

    all_reqs = re.findall(r"\brequire\s*\(", content)
    valid_reqs = re.findall(
        r"\brequire\s*\(\s*['\"](?:(?:\.\.?/)+package\.json|(?:node:)?(?:os|path|tty|util|fs|url|chalk|colors|picocolors|kleur|ansi-styles|supports-color|boxen))['\"]\s*\)",
        content,
        flags=re.IGNORECASE,
    )
    if len(all_reqs) != len(valid_reqs):
        return False

    if re.search(r"^\s*import\s+", content, re.MULTILINE):
        return False

    if re.search(
        rf"\bprocess\.env(?:\s*\.\s*|\s*\[\s*['\"`])(?:{sensitive_env_key_names})\b|"
        rf"\bJSON\.stringify\s*\(\s*process\.env\b|"
        rf"\{{[^}}]*\b(?:{sensitive_env_key_names})\b[^}}]*\}}\s*=\s*process\.env\b",
        content,
    ):
        return False

    return True


def is_official_github_release_download(command: str, manifest: Dict[str, Any]) -> bool:
    """
    Checks if a curl/wget hook strictly performs a single clean GET download from the package's
    own declared GitHub repository Releases URL.
    """
    repo = manifest.get("repository")
    repo_url = repo.get("url", "") if isinstance(repo, dict) else (repo if isinstance(repo, str) else "")
    repo_match = re.search(
        r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$",
        repo_url.strip(),
        re.IGNORECASE,
    )
    if not repo_match:
        return False
    owner_repo = repo_match.group(1).lower()

    deobf = deobfuscate_shell_cmd(command).strip()
    for candidate in (command.strip(), deobf):
        if re.search(r"&&|\|\||[;|`><\r\n]|\$\(|\$\{?|\$[A-Za-z_]", candidate):
            return False
        if re.search(
            r"\b(?:nc|netcat|ncat|socat|chmod|chown|node|python\d?|perl|ruby|php|"
            r"bash|sh|zsh|dash|ksh|cmd|powershell|pwsh|iex|eval|base64|openssl|xxd|"
            r"certutil|bitsadmin|mshta|mkfifo)\b|"
            r"\s(?:-d|--data\S*|-F|--form|-X\s*POST|--post-\S+)\b|/tmp/|/etc/|\.npmrc|\.ssh",
            candidate,
            re.IGNORECASE,
        ):
            return False

    if not re.match(r"^(?:curl|wget)\b", deobf, re.IGNORECASE):
        return False
    if len(re.findall(r"\b(?:curl|wget)\b", deobf, re.IGNORECASE)) != 1:
        return False

    urls = re.findall(r"https?://[^\s'\"`<>|;&]+", deobf, re.IGNORECASE)
    if len(urls) != 1:
        return False
    expected_prefix = f"https://github.com/{owner_repo}/releases/download/"
    return urls[0].lower().startswith(expected_prefix)


def extract_node_targets_from_cmd(cmd_str: str) -> List[str]:
    """
    Parses a shell command string and returns Node.js preload/script targets (`-r`/`--require`/
    `--import`/`--loader` and positional entrypoints, skipping `-e`/`--eval`/`-p`/`--print`).
    """
    if not cmd_str or not isinstance(cmd_str, str):
        return []
    targets: List[str] = []
    tokens = tokenize_shell_tokens(cmd_str)
    ctrl_ops = (";", "&", "|", "&&", "||", "|&")
    redir_ops = (">", ">>", "<", "<<", ">&", "<&")
    node_value_flags = (
        "-C", "--conditions", "--input-type", "--max-old-space-size",
        "--inspect", "--inspect-brk", "--env-file", "--title",
    )
    i = 0
    while i < len(tokens):
        tok_base = os.path.basename(tokens[i]).lower()
        if tok_base in ("node", "node.exe", "nodejs"):
            i += 1
            expect_code_arg = False
            expect_require_arg = False
            expect_other_val = False
            expect_redir_arg = False
            while i < len(tokens):
                t = tokens[i]
                if t in ctrl_ops:
                    break
                if expect_redir_arg:
                    expect_redir_arg = False
                    i += 1
                    continue
                if expect_code_arg:
                    expect_code_arg = False
                    i += 1
                    continue
                if expect_other_val:
                    expect_other_val = False
                    i += 1
                    continue
                if expect_require_arg:
                    expect_require_arg = False
                    if t.startswith((".", "/")) or "/" in t or t.endswith((".js", ".cjs", ".mjs")):
                        targets.append(t)
                    i += 1
                    continue
                if t in redir_ops:
                    expect_redir_arg = True
                    i += 1
                    continue
                if t.isdigit() and i + 1 < len(tokens) and tokens[i + 1] in redir_ops:
                    i += 1
                    continue
                if t in ("-e", "--eval", "-p", "--print"):
                    expect_code_arg = True
                    i += 1
                    continue
                if t in ("-r", "--require", "--loader", "--experimental-loader", "--import"):
                    expect_require_arg = True
                    i += 1
                    continue
                if t in node_value_flags:
                    expect_other_val = True
                    i += 1
                    continue
                if t.startswith(("--require=", "--import=", "--loader=", "--experimental-loader=")):
                    req_target = t.split("=", 1)[1]
                    if req_target.startswith((".", "/")) or "/" in req_target or req_target.endswith((".js", ".cjs", ".mjs")):
                        targets.append(req_target)
                    i += 1
                    continue
                if t.startswith("-"):
                    i += 1
                    continue
                targets.append(t)
                break
        elif tok_base in ("bun", "bun.exe"):
            i += 1
            if i < len(tokens) and tokens[i] == "run":
                i += 1
            expect_val = False
            while i < len(tokens):
                t = tokens[i]
                if t in ctrl_ops:
                    break
                if expect_val:
                    expect_val = False
                    i += 1
                    continue
                if t in ("-e", "--eval", "-p", "--print", "-r", "--preload", "-c", "--config", "--cwd"):
                    expect_val = True
                    i += 1
                    continue
                if t.startswith("-"):
                    i += 1
                    continue
                if t.endswith((".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx")) or "/" in t:
                    targets.append(t)
                break
        elif tok_base in ("deno", "deno.exe"):
            i += 1
            if i < len(tokens) and tokens[i] == "run":
                i += 1
                expect_val = False
                while i < len(tokens):
                    t = tokens[i]
                    if t in ctrl_ops:
                        break
                    if expect_val:
                        expect_val = False
                        i += 1
                        continue
                    if t in ("-c", "--config", "--import-map", "--location", "--lock"):
                        expect_val = True
                        i += 1
                        continue
                    if t.startswith("-"):
                        i += 1
                        continue
                    if not t.startswith(("http://", "https://")) and (
                        t.endswith((".js", ".cjs", ".mjs", ".ts", ".tsx")) or "/" in t
                    ):
                        targets.append(t)
                    break
        elif tokens[i].startswith(("./", "bin/", "scripts/")) and "/" in tokens[i]:
            targets.append(tokens[i])
        i += 1
    return targets


def extract_inline_node_snippets(cmd_str: str) -> List[str]:
    """Extracts JS code strings passed to `node -e/-p/--eval/--print` inside a hook command."""
    if not cmd_str or not isinstance(cmd_str, str):
        return []
    snippets: List[str] = []
    tokens = tokenize_shell_tokens(cmd_str)
    ctrl_ops = (";", "&", "|", "&&", "||", "|&")
    i = 0
    while i < len(tokens):
        tok_base = os.path.basename(tokens[i]).lower()
        if tok_base in ("node", "node.exe", "nodejs"):
            i += 1
            expect_code = False
            while i < len(tokens):
                t = tokens[i]
                if t in ctrl_ops:
                    break
                if expect_code:
                    snippets.append(t)
                    expect_code = False
                    i += 1
                    continue
                if t in ("-e", "--eval", "-p", "--print"):
                    expect_code = True
                    i += 1
                    continue
                if t.startswith(("--eval=", "--print=")):
                    snippets.append(t.split("=", 1)[1])
                    i += 1
                    continue
                if not t.startswith("-"):
                    break
                i += 1
            continue
        i += 1
    return snippets


def extract_aux_targets_from_cmd(cmd_str: str) -> List[str]:
    """Extracts referenced `.sh/.bash/.ps1/.bat/.cmd/.py` paths from a hook command."""
    if not cmd_str:
        return []
    targets: List[str] = []
    for tok in tokenize_shell_tokens(cmd_str):
        tl = tok.strip("'\"").lower()
        if tl.endswith(_AUX_SCRIPT_EXTS) and not tl.startswith(("http://", "https://")):
            targets.append(tok.strip("'\""))
    return targets


def classify_hook_command(
    hook_name: str,
    command: str,
    manifest: Dict[str, Any],
    scripts: Dict[str, Any],
    pkg_dir: str,
    enable_whitelist: bool,
    gyp_malicious: bool,
    sensitive_env_key_names: str,
    detect_heavy_obf_fn,
    resolve_script_fn,
) -> CommandClassification:
    """
    Neutral structural classifier for a single package.json lifecycle command.
    Separates Hard Evidence (malicious inline/bridged patterns) from Install Execution Capability
    (local JS/unclassified commands) and safe build tools.
    """
    deobf_cmd = deobfuscate_shell_cmd(command)
    bridged_chain = resolve_script_chain(command, scripts)

    local_js_targets: List[str] = []
    local_aux_targets: List[str] = []
    inline_snippets: List[Tuple[str, str]] = []
    seen_js: Set[str] = set()

    def _collect_targets(cmd_text: str, label: str):
        for raw_c in (cmd_text, deobfuscate_shell_cmd(cmd_text)):
            for tgt in extract_node_targets_from_cmd(raw_c):
                rel = resolve_script_fn(pkg_dir, tgt)
                if rel and rel not in seen_js:
                    seen_js.add(rel)
                    local_js_targets.append(rel)
            for aux in extract_aux_targets_from_cmd(raw_c):
                if aux not in local_aux_targets:
                    local_aux_targets.append(aux)
        for snip in extract_inline_node_snippets(cmd_text):
            if snip.strip():
                inline_snippets.append((f"<inline:{label}>", snip))

    _collect_targets(command, hook_name)
    for sub_name, sub_cmd in bridged_chain:
        _collect_targets(sub_cmd, f"{hook_name}->{sub_name}")

    is_author = hook_name not in ("preinstall", "install", "postinstall", "preuninstall", "postuninstall")
    hard_patterns = match_suspicious_hook_patterns(command, deobf_cmd, is_author_hook=is_author)
    bridged_hard: List[str] = []
    for sub_name, sub_cmd in bridged_chain:
        deobf_sub = deobfuscate_shell_cmd(sub_cmd)
        sub_pats = match_suspicious_hook_patterns(sub_cmd, deobf_sub, is_author_hook=is_author)
        for p in sub_pats:
            bridged_hard.append(f"{p} in bridged script '{sub_name}' (via '{hook_name}'): {sub_cmd}")

    all_hard = list(hard_patterns) + bridged_hard

    # Clean GitHub Releases download overrides generic remote-egress pattern
    non_egress_direct = [p for p in hard_patterns if p != "Remote network egress / LOLBin tool invoked in script"]
    if (
        not is_author
        and enable_whitelist
        and not bridged_hard
        and not non_egress_direct
        and is_official_github_release_download(command, manifest)
    ):
        return CommandClassification(
            kind="github_release_download",
            local_js_targets=local_js_targets,
            local_aux_targets=local_aux_targets,
            inline_js_snippets=inline_snippets,
            detail=f"Hook '{hook_name}' downloads binary from package's own GitHub Releases: {command}",
        )

    if not is_author and not all_hard:
        if is_whitelisted_command(
            command,
            scripts=scripts,
            pkg_dir=pkg_dir,
            enable_whitelist=enable_whitelist,
            _gyp_malicious=gyp_malicious,
        ):
            return CommandClassification(
                kind="whitelisted_build",
                local_js_targets=local_js_targets,
                local_aux_targets=local_aux_targets,
                inline_js_snippets=inline_snippets,
                detail=f"Command '{command}' matches whitelist rule.",
            )

        if enable_whitelist and is_benign_local_node_script(
            hook_name, command, pkg_dir, sensitive_env_key_names, detect_heavy_obf_fn
        ):
            return CommandClassification(
                kind="benign_banner",
                local_js_targets=local_js_targets,
                local_aux_targets=local_aux_targets,
                inline_js_snippets=inline_snippets,
                detail=f"Hook '{hook_name}' invokes short local banner/check Node script: {command}",
            )

    if all_hard:
        return CommandClassification(
            kind="malicious_inline",
            hard_patterns=all_hard,
            local_js_targets=local_js_targets,
            local_aux_targets=local_aux_targets,
            inline_js_snippets=inline_snippets,
            detail=f"Detected malicious '{hook_name}' hook pattern(s): {command}",
        )

    kind = "local_script" if local_js_targets else "capability_other"
    return CommandClassification(
        kind=kind,
        local_js_targets=local_js_targets,
        local_aux_targets=local_aux_targets,
        inline_js_snippets=inline_snippets,
        detail=f"Detected active '{hook_name}' hook with command: {command}",
    )
