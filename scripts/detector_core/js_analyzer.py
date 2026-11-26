"""
scripts/detector_core/js_analyzer.py
Pure-Python zero-dependency JavaScript expression folder, local constant tracer,
scope analyzer, timer evasion detector, and structural anti-obfuscation checks.
Inspired by NodeSecure/js-x-ray, DataDog/guarddog, and lateos-ai/npm-scan.
"""

import ast
import base64
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import SAFE_NON_SHELL_TOOLS

SENSITIVE_NODE_BUILTINS = frozenset({
    "child_process",
    "vm",
    "fs",
    "http",
    "https",
    "http2",
    "net",
    "tls",
    "dns",
    "dgram",
    "os",
    "worker_threads",
    "cluster",
})

_JS_LITERAL_STR_RE = re.compile(
    r"""^\s*(?:'((?:\\[\s\S]|[^'\\\n])*)'|"((?:\\[\s\S]|[^"\\\n])*)"|`((?:(?!\$\{)(?:\\[\s\S]|[^`\\]))*)`)\s*$"""
)

_FROM_CHAR_CODE_RE = re.compile(
    r"\bString\s*\.\s*from(?:CharCode|CodePoint)\s*\(\s*"
    r"((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){1,199})\s*\)"
)

_INLINE_ARRAY_JOIN_RE = re.compile(
    r"\[\s*([^\[\]\n]{1,1200})\s*\]\s*"
    r"(?:(?:\.\s*(reverse)\s*\(\s*\)\s*)?\.\s*join\s*\(\s*(['\"`])([^'\"`\n]{0,16})\3\s*\))"
)

_PLAIN_SHORT_B64_RE = re.compile(
    r"""\batob\s*\(\s*(['"`])([A-Za-z0-9+/=]{4,280})\1\s*\)|"""
    r"""Buffer\s*\.\s*from\s*\(\s*(['"`])([A-Za-z0-9+/=_-]{4,280})\3\s*,\s*"""
    r"""(['"`])(base64|base64url|hex)\5\s*\)\s*\.\s*toString\s*\(\s*(?:['"`](?:utf-?8|ascii)['"`])?\s*\)""",
    re.IGNORECASE,
)

_INSTALL_SAFE_BUILD_RE = re.compile(
    r"^(?:npx\s+(?:-[yq]\s+|--yes\s+)?)?(?:node-gyp|@mapbox/node-pre-gyp|node-pre-gyp|"
    r"prebuild-install|node-gyp-build|napi-build|cmake-js|cmake|make|ninja|cargo|rustc|"
    r"pkg-config|tsc|esbuild|git)\b",
    re.IGNORECASE,
)

_SAFE_TOOL_CALL_RE = re.compile(
    r"^\(\s*(['\"`])(?:" + "|".join(re.escape(t) for t in SAFE_NON_SHELL_TOOLS) + r")\1"
)

_CP_METHODS_ALT = "exec|execSync|spawn|spawnSync|execFile|execFileSync|fork"

# Pre-compiled hot regexes for fold_js_expressions / constant extraction
_NO_LIT_RE = re.compile(r"(['\"`])(?:\\[\s\S]|(?!\1)[^\\])*\1")
_WRITE_CNT_RE = re.compile(r"(?<![.\w$!<>+*/=-])([A-Za-z_$][\w$]*)\s*(?:\+|-|\*|/)?=(?![=>])")
_INC_DEC_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*(?:\+\+|--)|(?:\+\+|--)\s*([A-Za-z_$][\w$]*)\b")
_DECL_RE = re.compile(r"(?:^|[;\n{},])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?!=)\s*")
_BARE_RE = re.compile(r"(?:^|[;\n{}])\s*([A-Za-z_$][\w$]*)\s*=(?!=)\s*")
_ARR_JOIN_VAR_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*(?:\.\s*(reverse)\s*\(\s*\)\s*)?\.\s*join\s*\(\s*(['\"`])([^'\"`\n]{0,16})\3\s*\)"
)
_TPL_LIT_RE = re.compile(r"`([^`\\]*(?:\\.[^`\\]*)*)`")
_TPL_INTERP_RE = re.compile(r"\$\{([^}]+)\}")
_PLUS_TERM_PAT = r"""(?:'[^'\\\n]{0,200}'|"[^"\\\n]{0,200}"|(?<![.\w$])[A-Za-z_$][\w$]*(?!\s*(?:\(|\[|\.|[:=]|=>)))"""
_PLUS_CHAIN_RE = re.compile(rf"({_PLUS_TERM_PAT}(?:\s*\+\s*{_PLUS_TERM_PAT}){{1,12}})")
_HAS_LIT_PLUS_RE = re.compile(r"['\"`]\s*\+\s*['\"`]")
_MIX_PLUS_RE = re.compile(
    r"(?:'([^'\\\n]{0,200})'|\"([^\"\\\n]{0,200})\"|`((?:(?!\$\{)[^`\\\n]){0,200})`)"
    r"\s*\+\s*"
    r"(?:'([^'\\\n]{0,200})'|\"([^\"\\\n]{0,200})\"|`((?:(?!\$\{)[^`\\\n]){0,200})`)"
    r"(?!\s*(?:\.(?!\.\.)|\[))"
)
_REQ_ALIAS_RE = re.compile(
    r"(?:^|[;\n{},]|\b(?:const|let|var))\s*([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:require|process\s*\.\s*mainModule\s*\.\s*require|process\s*\.\s*getBuiltinModule|"
    r"(?:globalThis|global)\s*(?:\.\s*require|\[\s*['\"`]require['\"`]\s*\]))\s*(?=[;\n,]|$)"
)
_INDIRECT_BASE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("process.mainModule.require", re.compile(r"\bprocess\s*\.\s*mainModule\s*\.\s*require\s*\(")),
    ("process.getBuiltinModule", re.compile(r"\bprocess\s*\.\s*getBuiltinModule\s*\(")),
    ("globalThis.require", re.compile(r"\b(?:globalThis|global)\s*(?:\.\s*require|\[\s*['\"`]require['\"`]\s*\])\s*\(")),
    ("Function.call(require)", re.compile(r"\bFunction\s*\.\s*prototype\s*\.\s*call\s*\.\s*call\s*\(\s*require\s*,")),
]
_REQUIRE_CALL_RE = re.compile(r"(?<![.\w$])require\s*\(")
_SINK_VAR_RE = re.compile(rf"(\b(?:{_CP_METHODS_ALT})\s*\(\s*)([A-Za-z_$][\w$]*)(\s*(?:,|\)))")
_BRACKET_PROP_RE = re.compile(r"""(?<=[\w$\)\]])\s*\[\s*(['"`])([A-Za-z_$][\w$]*)\1\s*\](?!\s*:)""")

_FOLD_TRIGGER_SUBSTRS = (
    "require", "child_process", "exec", "spawn", "eval", "Function",
    "setTimeout", "setInterval", "Buffer", "fetch", "http", "dns", "net",
    ".join", "fromCharCode", "fromCodePoint", "atob", "getBuiltinModule", "mainModule",
)


def _unescape_js_string(raw: str) -> str:
    """Decodes basic JS string escape sequences safely."""
    if "\\" not in raw:
        return raw
    return (
        raw.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\\'", "'")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
    )


def _parse_single_js_literal(expr: str) -> Optional[str]:
    """Parses a plain JS string literal expression or returns None."""
    m = _JS_LITERAL_STR_RE.match(expr)
    if not m:
        return None
    raw = m.group(1) if m.group(1) is not None else (m.group(2) if m.group(2) is not None else m.group(3))
    return _unescape_js_string(raw)


def _make_js_literal(value: str) -> str:
    """Formats a Python string back into a safe single-line JS string literal."""
    escaped = value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
    if "'" not in escaped:
        return f"'{escaped}'"
    if '"' not in escaped:
        return f'"{escaped}"'
    return "'" + escaped.replace("'", "\\'") + "'"


def _decode_short_ascii(raw_encoded: str, encoding: str) -> Optional[str]:
    """Decodes short base64/base64url/hex into printable ASCII if safe."""
    enc_l = encoding.lower()
    try:
        if enc_l == "hex":
            raw = bytes.fromhex(raw_encoded)
        elif enc_l == "base64url":
            padded = raw_encoded + ("=" * ((4 - len(raw_encoded) % 4) % 4))
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(raw_encoded, validate=True)
    except Exception:
        return None
    if not (2 <= len(raw) <= 200):
        return None
    if all(0x20 <= b <= 0x7E or b in (9, 10, 13) for b in raw):
        return raw.decode("ascii", errors="ignore")
    return None


def _fold_inline_literals(code: str) -> str:
    """Folds literal String.fromCharCode, inline string array joins, short atob/Buffer, and `+` chains."""
    work = code

    if "fromCharCode" in work or "fromCodePoint" in work:
        def _repl_charcode(m: re.Match) -> str:
            toks = re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))
            chars: List[str] = []
            for tok in toks:
                cp = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                if not (0x20 <= cp <= 0x7E):
                    return m.group(0)
                chars.append(chr(cp))
            return _make_js_literal("".join(chars))
        work = _FROM_CHAR_CODE_RE.sub(_repl_charcode, work)

    if "atob" in work or "Buffer" in work:
        def _repl_b64(m: re.Match) -> str:
            if m.group(2) is not None:
                dec = _decode_short_ascii(m.group(2), "base64")
            else:
                dec = _decode_short_ascii(m.group(4), m.group(6))
            return _make_js_literal(dec) if dec is not None else m.group(0)
        work = _PLAIN_SHORT_B64_RE.sub(_repl_b64, work)

    if ".join" in work and "[" in work:
        def _repl_arr_join(m: re.Match) -> str:
            inner, has_rev, _, sep = m.group(1), m.group(2), m.group(3), m.group(4)
            elems = _parse_js_string_list(inner)
            if elems is None:
                return m.group(0)
            if has_rev:
                elems = list(reversed(elems))
            return _make_js_literal(sep.join(elems))
        work = _INLINE_ARRAY_JOIN_RE.sub(_repl_arr_join, work)

    return _fold_plus_string_literals(work)


def _parse_js_string_list(inner: str) -> Optional[List[str]]:
    """Parses comma-separated JS string literals (no expressions) up to 32 elements."""
    items: List[str] = []
    i = 0
    n = len(inner)
    while i < n:
        while i < n and inner[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        q = inner[i]
        if q not in ("'", '"', "`"):
            return None
        i += 1
        start = i
        escaped = False
        closed = False
        while i < n:
            ch = inner[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == q:
                closed = True
                break
            i += 1
        if not closed:
            return None
        raw_val = inner[start:i]
        if q == "`" and "${" in raw_val:
            return None
        items.append(_unescape_js_string(raw_val))
        i += 1
        if len(items) > 32:
            return None
        while i < n and inner[i] in " \t\r\n":
            i += 1
        if i < n:
            if inner[i] != ",":
                return None
            i += 1
    return items if items else None


def _fold_plus_string_literals(code: str) -> str:
    """Iteratively folds `'a' + 'b'` style literal string concatenations."""
    if "+" not in code or not _HAS_LIT_PLUS_RE.search(code):
        return code
    norm = code

    def _repl(m: re.Match) -> str:
        g = m.groups()
        a = g[0] if g[0] is not None else (g[1] if g[1] is not None else g[2])
        b = g[3] if g[3] is not None else (g[4] if g[4] is not None else g[5])
        return _make_js_literal(a + b)

    for _ in range(6):
        updated = _MIX_PLUS_RE.sub(_repl, norm)
        if updated == norm:
            break
        norm = updated
    return norm


def _split_top_level_plus(expr: str) -> Optional[List[str]]:
    """Splits a JS expression on top-level `+` outside quotes/brackets/parens."""
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    quote = ""
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                buf.append(expr[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
            buf.append(ch)
        else:
            if ch in ("'", '"', "`"):
                quote = ch
                buf.append(ch)
            elif ch in ("(", "[", "{"):
                depth += 1
                buf.append(ch)
            elif ch in (")", "]", "}"):
                if depth == 0:
                    return None
                depth -= 1
                buf.append(ch)
            elif ch == "+" and depth == 0:
                if i + 1 < n and expr[i + 1] == "+":
                    return None
                seg = "".join(buf).strip()
                if not seg:
                    return None
                parts.append(seg)
                buf = []
                i += 1
                continue
            else:
                buf.append(ch)
        i += 1
    if quote or depth != 0:
        return None
    tail = "".join(buf).strip()
    if not tail:
        return None
    parts.append(tail)
    return parts


def _eval_const_string_expr(
    raw_expr: str,
    const_str: Dict[str, str],
    const_arr: Dict[str, List[str]],
) -> Optional[str]:
    """Evaluates a constant JS string expression built from literals, known vars, joins, or decodes."""
    expr = raw_expr.strip()
    if not expr or len(expr) > 1200:
        return None
    while expr.startswith("(") and expr.endswith(")"):
        inner = expr[1:-1].strip()
        if not inner:
            break
        if _split_top_level_plus(inner) is None:
            break
        expr = inner

    lit = _parse_single_js_literal(expr)
    if lit is not None:
        return lit

    if re.fullmatch(r"[A-Za-z_$][\w$]*", expr):
        return const_str.get(expr)

    # Folded template literal whose interpolations are all known constant identifiers
    if expr.startswith("`") and expr.endswith("`") and "`" not in expr[1:-1]:
        body = expr[1:-1]
        ok = True

        def _repl_tpl(tm: re.Match) -> str:
            nonlocal ok
            ident = tm.group(1).strip()
            if ident in const_str:
                return const_str[ident]
            ok = False
            return tm.group(0)

        rendered = re.sub(r"\$\{([^}]+)\}", _repl_tpl, body)
        if ok:
            return _unescape_js_string(rendered)

    arr_join_var = re.fullmatch(
        r"([A-Za-z_$][\w$]*)\s*(?:\.\s*(reverse)\s*\(\s*\)\s*)?\.\s*join\s*\(\s*(['\"`])([^'\"`\n]{0,16})\3\s*\)",
        expr,
    )
    if arr_join_var:
        arr_id, has_rev, _, sep = arr_join_var.groups()
        if arr_id in const_arr:
            items = list(reversed(const_arr[arr_id])) if has_rev else const_arr[arr_id]
            return sep.join(items)

    # Inline Folded sub-calls
    folded_sub = _fold_inline_literals(expr)
    if folded_sub != expr:
        lit2 = _parse_single_js_literal(folded_sub)
        if lit2 is not None:
            return lit2
        expr = folded_sub

    parts = _split_top_level_plus(expr)
    if parts and len(parts) >= 2:
        out_chunks: List[str] = []
        for p in parts:
            val = _eval_const_string_expr(p, const_str, const_arr)
            if val is None:
                return None
            out_chunks.append(val)
        return "".join(out_chunks)

    return None


def _collect_local_constants(work: str, is_minified: bool) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Extracts non-reassigned single-file constant string & string-array bindings."""
    no_lit_work = _NO_LIT_RE.sub(" ", work)
    write_counts: Dict[str, int] = {}
    for m in _WRITE_CNT_RE.finditer(no_lit_work):
        name = m.group(1)
        write_counts[name] = write_counts.get(name, 0) + 1
    for m in _INC_DEC_RE.finditer(no_lit_work):
        name = m.group(1) or m.group(2)
        write_counts[name] = write_counts.get(name, 0) + 2

    assigns: List[Tuple[str, str]] = []
    n = len(work)

    for hdr_re in (_DECL_RE, _BARE_RE):
        for m in hdr_re.finditer(work):
            lhs = m.group(1)
            if is_minified and len(lhs) <= 1:
                continue
            if write_counts.get(lhs, 0) != 1:
                continue
            rhs = _read_statement_rhs(work, m.end(), n)
            if rhs:
                assigns.append((lhs, rhs))

    const_str: Dict[str, str] = {}
    const_arr: Dict[str, List[str]] = {}

    for lhs, rhs in assigns:
        arr_m = re.fullmatch(r"\[\s*([^\[\]\n]{1,1200})\s*\]", rhs)
        if arr_m:
            parsed_list = _parse_js_string_list(arr_m.group(1))
            if parsed_list is not None:
                const_arr[lhs] = parsed_list

    for _ in range(3):
        changed = False
        for lhs, rhs in assigns:
            if lhs in const_str:
                continue
            val = _eval_const_string_expr(rhs, const_str, const_arr)
            if val is not None:
                const_str[lhs] = val
                changed = True
        if not changed:
            break

    return const_str, const_arr


def _read_statement_rhs(code: str, start: int, n: int) -> str:
    """Reads an ASI-aware statement RHS starting after `=` up to semicolon or closing brace."""
    limit = min(n, start + 1200)
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
        else:
            if ch in ("'", '"', "`"):
                quote = ch
            elif ch in ("(", "[", "{"):
                depth += 1
            elif ch in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            elif ch == "\n" and depth == 0:
                prev_tok = code[start:i].rstrip()
                nxt = i + 1
                while nxt < limit and code[nxt] in (" ", "\t", "\r", "\n"):
                    nxt += 1
                if not (prev_tok and prev_tok[-1] in (",", "+", "=", "?", ":", ".")) and not (nxt < n and code[nxt] == "."):
                    break
        i += 1
    return code[start:i].strip()


def _extract_balanced_parens_inner(code: str, open_paren_idx: int, max_len: int = 800) -> Optional[Tuple[str, int]]:
    """Returns `(inner_text, close_paren_idx)` for `(` at `open_paren_idx`."""
    n = len(code)
    if open_paren_idx < 0 or open_paren_idx >= n or code[open_paren_idx] != "(":
        return None
    limit = min(n, open_paren_idx + max_len)
    depth = 0
    quote = ""
    i = open_paren_idx
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
                if depth == 0:
                    return code[open_paren_idx + 1:i], i
        i += 1
    return None


def _split_top_level_comma_args(args_inner: str) -> List[str]:
    """Splits balanced argument inner string by top-level commas."""
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    quote = ""
    i = 0
    n = len(args_inner)
    while i < n:
        ch = args_inner[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                buf.append(args_inner[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
            buf.append(ch)
        else:
            if ch in ("'", '"', "`"):
                quote = ch
                buf.append(ch)
            elif ch in ("(", "[", "{"):
                depth += 1
                buf.append(ch)
            elif ch in (")", "]", "}"):
                depth = max(0, depth - 1)
                buf.append(ch)
            elif ch == "," and depth == 0:
                out.append("".join(buf).strip())
                buf = []
                i += 1
                continue
            else:
                buf.append(ch)
        i += 1
    if buf or out:
        out.append("".join(buf).strip())
    return out


def fold_js_expressions(norm_code: str, is_minified: bool = False) -> Dict[str, Any]:
    """
    Folds local JS string constants, array joins, short charcode/atob decodes, and
    detects indirect or obfuscated loading of sensitive Node built-in modules.
    Never modifies the caller's original string; returns `folded_code` for downstream sinks.
    """
    if not norm_code or (is_minified and len(norm_code) > 32768):
        return {"folded_code": norm_code, "obfuscated_builtin_requires": []}
    if not any(tok in norm_code for tok in _FOLD_TRIGGER_SUBSTRS):
        return {"folded_code": norm_code, "obfuscated_builtin_requires": []}

    work = _fold_inline_literals(norm_code)
    if (is_minified and len(work) > 32768) or len(work) > 131072:
        const_str, const_arr = {}, {}
    else:
        const_str, const_arr = _collect_local_constants(work, is_minified=is_minified)

    # Substitute known `<arrVar>.join('sep')` expressions
    if const_arr and ".join" in work:
        def _repl_arr_var(m: re.Match) -> str:
            arr_id, has_rev, _, sep = m.groups()
            if arr_id not in const_arr:
                return m.group(0)
            items = list(reversed(const_arr[arr_id])) if has_rev else const_arr[arr_id]
            return _make_js_literal(sep.join(items))
        work = _ARR_JOIN_VAR_RE.sub(_repl_arr_var, work)

    # Substitute template literals whose interpolations are known constants
    if const_str and "`" in work and "${" in work:
        def _repl_tpl_lit(m: re.Match) -> str:
            body = m.group(1)
            if "${" not in body:
                return m.group(0)
            ok = True
            def _sub(im: re.Match) -> str:
                nonlocal ok
                v = im.group(1).strip()
                if v in const_str:
                    return const_str[v]
                ok = False
                return im.group(0)
            res = _TPL_INTERP_RE.sub(_sub, body)
            return _make_js_literal(_unescape_js_string(res)) if ok else m.group(0)
        work = _TPL_LIT_RE.sub(_repl_tpl_lit, work)

    # Substitute known constant string `+` chains (`a + b`, `'ec' + 'ho ' + b`)
    if const_str and "+" in work:
        def _repl_plus(m: re.Match) -> str:
            val = _eval_const_string_expr(m.group(1), const_str, const_arr)
            if val is None or len(val) > 500:
                return m.group(0)
            return _make_js_literal(val)
        work = _PLUS_CHAIN_RE.sub(_repl_plus, work)

    work = _fold_plus_string_literals(work)

    # Detect indirect/obfuscated module loads and normalize them into require('<builtin>') in `work`
    obfuscated_requires: List[Tuple[str, str]] = []
    seen_obf_req: Set[Tuple[str, str]] = set()

    req_aliases: Set[str] = set()
    for am in _REQ_ALIAS_RE.finditer(norm_code):
        alias = am.group(1)
        if not (is_minified and len(alias) <= 1):
            req_aliases.add(alias)

    indirect_patterns: List[Tuple[str, re.Pattern]] = list(_INDIRECT_BASE_PATTERNS)
    for alias in sorted(req_aliases):
        indirect_patterns.append((f"alias:{alias}", re.compile(rf"(?<![.\w$]){re.escape(alias)}\s*\(")))

    def _record_obf_req(builtin: str, raw_evidence: str) -> None:
        key = (builtin, raw_evidence[:80])
        if key not in seen_obf_req:
            seen_obf_req.add(key)
            obfuscated_requires.append(key)

    # 1. Inspect indirect require APIs on raw `norm_code`, resolving arg via constant map
    rewrites: List[Tuple[str, str]] = []
    for label, pat in indirect_patterns:
        for m in pat.finditer(norm_code):
            open_idx = norm_code.rfind("(", m.start(), m.end())
            if open_idx == -1:
                continue
            parsed_p = _extract_balanced_parens_inner(norm_code, open_idx, max_len=600)
            if not parsed_p:
                continue
            inner, close_idx = parsed_p
            arg_expr = inner
            if label == "Function.call(require)":
                top_args = _split_top_level_comma_args(inner)
                if len(top_args) < 3:
                    continue
                arg_expr = top_args[2]
            mod_val = _eval_const_string_expr(arg_expr, const_str, const_arr)
            if mod_val is None:
                continue
            builtin = mod_val[5:] if mod_val.startswith("node:") else mod_val
            if builtin in SENSITIVE_NODE_BUILTINS:
                full_call = norm_code[m.start():close_idx + 1]
                _record_obf_req(builtin, full_call)
                rewrites.append((full_call, f"require('{builtin}')"))

    for full_call, repl in rewrites:
        work = work.replace(full_call, repl)
        folded_call = _fold_inline_literals(full_call)
        if folded_call != full_call:
            work = work.replace(folded_call, repl)

    # 2. Inspect plain `require(<non-literal-expr>)` on raw `norm_code` and fold remaining single-var `require(mod)` in `work`
    for rm in _REQUIRE_CALL_RE.finditer(norm_code):
        parsed_p = _extract_balanced_parens_inner(norm_code, rm.end() - 1, max_len=600)
        if not parsed_p:
            continue
        inner, _ = parsed_p
        inner_stripped = inner.strip()
        if not inner_stripped:
            continue
        if _parse_single_js_literal(inner_stripped) is not None:
            continue
        mod_val = _eval_const_string_expr(inner_stripped, const_str, const_arr)
        if mod_val is None:
            continue
        builtin = mod_val[5:] if mod_val.startswith("node:") else mod_val
        if builtin in SENSITIVE_NODE_BUILTINS:
            _record_obf_req(builtin, f"require({inner_stripped})")
            if re.fullmatch(r"[A-Za-z_$][\w$]*", inner_stripped):
                work = re.sub(
                    rf"(?<![.\w$])require\s*\(\s*{re.escape(inner_stripped)}\s*\)",
                    f"require('{builtin}')",
                    work,
                )

    # Fold remaining standalone constant args to common sinks like `execSync(cmdVar)`
    if const_str:
        work = _SINK_VAR_RE.sub(
            lambda sm: f"{sm.group(1)}{_make_js_literal(const_str[sm.group(2)])}{sm.group(3)}"
            if sm.group(2) in const_str
            else sm.group(0),
            work,
        )

    # Re-normalize computed bracket property access revealed by expression folding
    if "[" in work:
        work = _BRACKET_PROP_RE.sub(r".\2", work)

    return {
        "folded_code": work,
        "obfuscated_builtin_requires": obfuscated_requires,
    }


def is_at_top_level_scope(code: str, match_start: int) -> bool:
    """
    Returns True if `match_start` sits at module top-level scope (brace depth == 0)
    and not inside an unclosed arrow-function expression body (`() => execSync(...)`).
    """
    if match_start <= 0:
        return True
    brace_depth = 0
    quote = ""
    stmt_start = 0
    i = 0
    limit = min(match_start, len(code))
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
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth = max(0, brace_depth - 1)
                if brace_depth == 0:
                    stmt_start = i + 1
            elif ch == ";" and brace_depth == 0:
                stmt_start = i + 1
        i += 1

    if brace_depth > 0:
        return False
    stmt_prefix = code[stmt_start:limit]
    if "=>" in stmt_prefix:
        return False
    return True


def _parse_safe_delay_ms(delay_expr: str) -> Optional[float]:
    """Safely parses numeric literal / scientific notation / simple integer product delay in ms."""
    cleaned = delay_expr.strip()
    while cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1].strip()
    if not cleaned or len(cleaned) > 64:
        return None
    cleaned_no_sep = cleaned.replace("_", "")
    factors = [f.strip() for f in cleaned_no_sep.split("*")]
    if not factors or len(factors) > 6:
        return None
    product = 1.0
    num_re = re.compile(r"^(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?$")
    for f in factors:
        if not num_re.fullmatch(f):
            return None
        val = float(f)
        if not math.isfinite(val) or val < 0:
            return None
        product *= val
    return product


def detect_delayed_exec_timers(folded_code: str) -> Optional[str]:
    """
    Detects `setTimeout` / `setInterval` callbacks with delay >= 5000ms that invoke
    unsafe `child_process`, dynamic `eval`/`Function`/`vm`, or recon+network exfiltration.
    """
    if "setTimeout" not in folded_code and "setInterval" not in folded_code:
        return None

    has_cp_import = bool(
        re.search(r"require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)|from\s+['\"`](?:node:)?child_process['\"`]", folded_code)
    )
    cp_aliases: Set[str] = set()
    cp_destr_locals: Set[str] = set()
    for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)", folded_code):
        cp_aliases.add(m.group(1))
    for m in re.finditer(r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)", folded_code):
        for part in m.group(1).split(","):
            pm = re.match(r"^\s*([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?\s*$", part)
            if pm:
                cp_destr_locals.add(pm.group(2) or pm.group(1))

    cp_target_parts = [r"(?:require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)|child_process)\s*\.\s*(?:" + _CP_METHODS_ALT + r")\s*\("]
    for a in sorted(cp_aliases):
        cp_target_parts.append(rf"\b{re.escape(a)}\s*\.\s*(?:{_CP_METHODS_ALT})\s*\(")
    if has_cp_import:
        all_fn_names = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"} | cp_destr_locals
        cp_target_parts.append(r"(?<![.\w$])(?:" + "|".join(re.escape(fn) for fn in sorted(all_fn_names)) + r")\s*\(")
    cb_cp_re = re.compile("|".join(cp_target_parts))

    cb_eval_re = re.compile(
        r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(|(?<!\.)\bFunction\s*\(|"
        r"\bvm\.(?:runIn(?:New|This)?Context|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\("
    )
    cb_recon_re = re.compile(r"\b(?:userInfo|networkInterfaces|process\.env\.(?:NPM_TOKEN|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN))\b")
    cb_net_re = re.compile(r"\b(?:fetch|https?\.request|https?\.get|axios|got|net\.connect)\s*\(")

    for tm in re.finditer(r"\bset(?:Timeout|Interval)\s*\(", folded_code):
        parsed = _extract_balanced_parens_inner(folded_code, tm.end() - 1, max_len=2000)
        if not parsed:
            continue
        args = _split_top_level_comma_args(parsed[0])
        if len(args) < 2:
            continue
        callback_src, delay_expr = args[0], args[1]
        delay_ms = _parse_safe_delay_ms(delay_expr)
        if delay_ms is None or delay_ms < 5000:
            continue

        # Check unsafe child_process calls inside callback
        for cpm in cb_cp_re.finditer(callback_src):
            tail = callback_src[cpm.end() - 1:]
            if _SAFE_TOOL_CALL_RE.match(tail) and not re.search(r"\bshell\s*:\s*true", tail[:240]):
                continue
            lit_m = re.match(r"^\(\s*(['\"])([^'\"\n]{1,200})\1", tail)
            if lit_m and _INSTALL_SAFE_BUILD_RE.match(lit_m.group(2).strip()):
                continue
            return f"Delayed timer ({int(delay_ms)}ms) schedules unsafe child_process execution in callback"

        if cb_eval_re.search(callback_src):
            return f"Delayed timer ({int(delay_ms)}ms) schedules dynamic eval/Function/vm execution"

        if cb_recon_re.search(callback_src) and cb_net_re.search(callback_src):
            return f"Delayed timer ({int(delay_ms)}ms) schedules credential/host recon with network call"

    return None


_BIDI_ANY_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")
_BIDI_OPEN_RE = re.compile(r"[\u202A-\u202E\u2066-\u2068]")
_BIDI_CLOSE_RE = re.compile(r"[\u202C\u2069]")
_VS_STEGO_RE = re.compile(r"[\U000E0100-\U000E01EF]")
_ZW_STEGO_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")


def detect_trojan_source(raw_content: str, is_minified: bool = False) -> Optional[str]:
    """
    Detects Trojan Source bidirectional override/isolate characters (`U+202A..U+202E`,
    `U+2066..U+2069`), invisible tag variation selectors (`U+E0100..U+E01EF`), or
    zero-width Unicode steganography paired with decoder + eval primitives.
    Exempts minified UI/i18n bundles and benign balanced Bidi text inside string literals.
    """
    if not raw_content:
        return None

    if not is_minified and _BIDI_ANY_RE.search(raw_content):
        for ln in raw_content.splitlines():
            if not _BIDI_ANY_RE.search(ln):
                continue
            # Ignore Unicode range definitions or regex character classes matching bidi chars
            if "\\u202" in ln.lower() or "\\u206" in ln.lower():
                continue
            if re.search(r"/[^/\n]*[\u202A-\u202E\u2066-\u2069][^/\n]*/", ln):
                continue
            opens = len(_BIDI_OPEN_RE.findall(ln))
            closes = len(_BIDI_CLOSE_RE.findall(ln))
            unquoted_ln = _NO_LIT_RE.sub(" ", ln)
            if _BIDI_ANY_RE.search(unquoted_ln) or opens != closes:
                cnt = len(_BIDI_ANY_RE.findall(ln))
                return f"Trojan Source Unicode bidirectional control character detected ({cnt} occurrences)"

    vs_chars = _VS_STEGO_RE.findall(raw_content)
    if len(vs_chars) >= 8 or (
        len(vs_chars) >= 3
        and re.search(r"\b(?:codePointAt|fromCodePoint|eval|Function)\b", raw_content)
    ):
        return f"Hidden Unicode Variation Selector steganography detected ({len(vs_chars)} chars)"

    if not is_minified:
        zw_chars = _ZW_STEGO_RE.findall(raw_content[1:])
        if (
            len(zw_chars) >= 8
            and re.search(r"\b(?:codePointAt|charCodeAt|fromCharCode|fromCodePoint)\b", raw_content)
            and re.search(r"\b(?:eval|Function|Buffer\.from)\b", raw_content)
        ):
            return f"Zero-width Unicode steganography with decoder/exec detected ({len(zw_chars)} chars)"

    return None


def detect_structural_obfuscators(
    raw_content: str, no_comments: str, is_minified: bool = False
) -> Optional[str]:
    """
    Detects structural JS obfuscators & hidden horizontal cloaking (`js-x-ray` JJEncode +
    `guarddog` hidden-code space padding coupled with execution primitives).
    """
    if not no_comments:
        return None

    # GuardDog threat-runtime-obfuscation-hidden-code.yar: >=400 spaces + execution sink on same line
    for ln in raw_content.splitlines():
        if len(ln) >= 420 and re.search(r" {400,}\S", ln):
            if re.search(r"\b(?:eval|Function|require|child_process)\s*\(", ln):
                return "hidden_padding_exec"

    # JJEncode classifier (js-x-ray/src/obfuscators/jjencode.ts): >=12 identifiers with >80% [$ _] only
    if not is_minified and "$" in no_comments and not re.search(r"\bfunction\s+[A-Za-z][A-Za-z0-9_]*\s*\(", no_comments):
        all_ids = re.findall(r"(?<![A-Za-z0-9_$])[A-Za-z_$][A-Za-z0-9_$]*(?![A-Za-z0-9_$])", no_comments[:131072])
        if len(all_ids) >= 12:
            sym_only = sum(1 for ident in all_ids if re.fullmatch(r"[$_]+", ident))
            if (sym_only / len(all_ids)) > 0.80:
                return "jjencode"

    return None


def detect_self_defending_evasion(norm_code: str) -> Optional[str]:
    """
    Detects self-defending / anti-analysis runtime checks (`npm-scan` tier1-self-defending):
    debugger flags (`--inspect`, `v8debug`) or CI/SANDBOX env checks gating `process.exit`.
    """
    if not norm_code:
        return None
    if re.search(r"\b(?:globalThis|global)\s*\.\s*v8debug\b|\btypeof\s+v8debug\b", norm_code):
        return "Debugger detection (`v8debug`) anti-analysis check"
    if re.search(r"process\.execArgv[^\n;]{0,120}(?:--inspect|--debug)", norm_code):
        return "Debugger CLI flag (`process.execArgv` --inspect/--debug) check"
    if re.search(
        r"process\.env\.(?:CI|SANDBOX|GITHUB_ACTIONS|NODE_DEBUG)\b[^;\n]{0,200}process\.exit\s*\(",
        norm_code,
    ):
        return "Environment-conditional `process.exit()` sandbox/CI evasion"
    return None
