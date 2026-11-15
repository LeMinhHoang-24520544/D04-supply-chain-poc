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
import ipaddress
import posixpath
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List, Optional, Tuple, Set

# ==========================================
# CONSTANTS & DETECTION RULES
# ==========================================

SUSPICIOUS_LIFECYCLE_HOOKS = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepare",
    "prepack",
    "postpack",
    "prepublish"
]

EXTENDED_SANDBOX_HOOKS = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepare",
    "prepack",
    "postpack",
    "prepublish"
]

# Legitimate build/banner commands allowed by the whitelist to minimize False Positive Rate (FPR)
# Note: `npm/yarn/pnpm run <sub_script>` is resolved recursively via _resolve_script_chain
WHITELISTED_HOOK_COMMANDS = [
    r"^(?:npx\s+)?node-gyp\s+(?:rebuild|clean|configure|build|install)(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?(?:@mapbox/)?node-pre-gyp\s+install(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?prebuild-install(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?node-gyp-build(?:\s+[A-Za-z0-9_./:-]+)*$",
    r"^(?:npx\s+)?napi-build(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?esbuild(?:\s+[A-Za-z0-9_./*=-]+)*$",
    r"^(?:npx\s+)?tsc(?:\s+(?:-[pwbv]|--[A-Za-z0-9_-]+|[A-Za-z0-9_./-]+))*$",
    r"^(?:npx\s+)?husky(?:\s+install)?$",
    r"^(?:npx\s+)?patch-package(?:\s+--?[A-Za-z0-9_-]+)*$",
    r"^(?:npx\s+)?opencollective(?:-postinstall)?(?:\s+[A-Za-z0-9_./:-]+)*$",
    r"^(?:npx\s+)?is-ci$",
    r"^(?:exit(?:\s+0)?|true)$",
    r"^echo(?:\s+[^|;&><\\$`\r\n]*)?$"
]

DANGEROUS_WHITELIST_FLAGS_RE = re.compile(
    r"(?:https?|ftp)://|"
    r"(?:^|\s)(?:--python(?:=|\s|$)|--require(?:=|\s|$)|-r\b|--import(?:=|\s|$)|"
    r"--eval(?:=|\s|$)|-e\b|--print(?:=|\s|$)|--(?:experimental-)?loader(?:=|\s|$)|"
    r"--gyp-path(?:=|\s|$)|--node_gyp(?:=|\s|$)|"
    r"--download\b|--mirror\b|--dist-?url\b|--tarball\b|--hosted_tarball\b|"
    r"--prebuild\b|--custom-binary\b|--runtime_url\b|--inject:)",
    re.IGNORECASE
)

SCRIPT_BRIDGE_CALL_RE = re.compile(
    r"\b(?:npm\s+(?:(?:--silent|-s|--quiet|-q|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run(?:-script)?|"
    r"yarn\s+(?:(?:--silent|-s|--cwd(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run|"
    r"pnpm\s+(?:(?:--silent|-s|--dir(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run)\s+"
    r"(?:(?:--silent|-s|--quiet|-q|--if-present|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*['\"]?([A-Za-z0-9_:.-]+)['\"]?",
    re.IGNORECASE
)

SINGLE_SCRIPT_BRIDGE_SEGMENT_RE = re.compile(
    r"^(?:npm\s+(?:(?:--silent|-s|--quiet|-q|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run(?:-script)?|"
    r"yarn\s+(?:(?:--silent|-s|--cwd(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run|"
    r"pnpm\s+(?:(?:--silent|-s|--dir(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run)\s+"
    r"(?:(?:--silent|-s|--quiet|-q|--if-present|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*['\"]?([A-Za-z0-9_:.-]+)['\"]?$",
    re.IGNORECASE
)

NATIVE_BUILD_CMD_RE = re.compile(
    r"^(?:npx\s+)?(?:node-gyp|@mapbox/node-pre-gyp|node-pre-gyp|prebuild-install|node-gyp-build|napi-build)\b",
    re.IGNORECASE
)

POPULAR_NPM_PACKAGES = {
    "lodash", "axios", "express", "react", "react-dom", "chalk", "commander",
    "debug", "request", "moment", "dotenv", "cross-env", "webpack", "typescript",
    "eslint", "tslib", "uuid", "semver", "glob", "rimraf", "mkdirp", "ws",
    "minimist", "yargs", "inquirer", "fs-extra", "colors", "bluebird", "underscore",
    "async", "rxjs", "next", "vue", "jquery", "socket.io", "redis", "mongodb",
    "mongoose", "pg", "mysql", "mysql2", "sequelize", "prisma", "jsonwebtoken",
    "bcrypt", "bcryptjs", "crypto-js", "node-fetch", "got", "superagent", "cheerio",
    "puppeteer", "playwright", "jest", "mocha", "chai", "sinon", "vite", "rollup",
    "parcel", "esbuild", "prettier", "nodemon", "pm2", "cors", "body-parser",
    "cookie-parser", "helmet", "morgan", "winston", "pino", "ramda", "dayjs",
    "date-fns", "ajv", "joi", "zod", "redux", "tailwindcss", "postcss",
    "autoprefixer", "sass", "less", "styled-components", "three", "d3", "sharp",
    "jimp", "canvas", "nodemailer", "aws-sdk", "googleapis", "stripe", "twilio",
    "openai", "langchain"
}

TRUSTED_OFFICIAL_SCOPES = {
    "@types/", "@babel/", "@angular/", "@vue/", "@nestjs/",
    "@testing-library/", "@aws-sdk/", "@rollup/", "@vitejs/",
    "@eslint/", "@typescript-eslint/"
}

SHADOWED_CORE_BINARIES = {
    "node", "npm", "npx", "yarn", "pnpm", "git", "sh", "bash", "zsh",
    "python", "python3", "curl", "wget", "ssh", "sudo", "cmd", "powershell",
    "tsc", "esbuild"
}

COMMON_ENGLISH_PACKAGE_WORDS = {
    "core", "sync", "lite", "site", "blob", "ping",
    "pass", "char", "chat", "lens", "mass", "loss"
}

TELEMETRY_PREFIX = "__D04_TELEMETRY__"

# Trusted hosts allowed for URL-based dependencies without raising non-registry alerts
TRUSTED_DEPENDENCY_HOSTS = {
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.org",
    "yarnpkg.com",
}

# High-risk command patterns inside lifecycle scripts (Layer 1)
SUSPICIOUS_SCRIPT_PATTERNS = [
    (
        r"(?:(?<![A-Za-z0-9_./\\-])(?:curl|wget|netcat|ncat|socat|bitsadmin|certutil|mshta)(?![A-Za-z0-9_./\\-])(?:\s+|$)|"
        r"(?:^|[;&|]\s*)fetch\s+(?:-[A-Za-z0-9-]+\s+)*https?://|"
        r"(?:^|[;&|]\s*)nc\s+(?:-[A-Za-z0-9]+\s+)*(?:[A-Za-z0-9.-]+\s+\d{1,5}\b|-[lec]\b))",
        "Remote network egress / LOLBin tool invoked in script"
    ),
    (r"(?<!\|)\|\s*(?!\|)(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|python\d?(?:\.\d+)?|perl|ruby|php|node|iex)\b", "Piping output directly into shell/language interpreter"),
    (r"\b(bash|sh|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\s+(?:-c|/c)\b", "External shell interpreter spawned"),
    (r"\bnode\s+(?:-[^\s]*\s+)*(?:-e|--eval|-p|--print)\b", "Inline Node.js code evaluation (-e/--eval/-p/--print)"),
    (r"\b(?:python\d?(?:\.\d+)?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)\b", "Inline scripting interpreter execution (python/perl/ruby/php)"),
    (r"\b(?:powershell|pwsh)(?:\.exe)?\b.*?\b(?:-e|-enc|-encodedcommand|iex|invoke-webrequest|invoke-restmethod|iwr|irm|downloadstring|downloadfile)\b", "Suspicious PowerShell inline/encoded/web execution"),
    (r"/dev/(?:tcp|udp)/|\bmkfifo\b|\bnc(?:at)?\s+.*?-e\b", "Reverse shell / raw socket / FIFO device execution"),
    (r"\b(?:base64\s+(?:-d|--decode|-D)|openssl\s+(?:enc|base64)\b.*?-d|xxd\s+-r)\b", "Shell-level payload decoding (base64/openssl/xxd)"),
    (r"eval\s*\(\s*Buffer\.from\s*\(", "Inline dynamic Node.js Base64 execution"),
    (r"(?:>\s*)?(?:/tmp/|/var/tmp/|/dev/shm/|C:\\+Users\\+Public\\+|~/.ssh|~/.bashrc|~/.profile|/etc/passwd|/etc/shadow|\.npmrc\b)", "Accessing or writing to sensitive/public OS paths in script"),
    (r"\b(?:sleep\s+\d+|timeout\s+/t)\b", "Suspicious sleep/delay evasion technique"),
]

# High-confidence dynamic evaluation & obfuscation patterns in JS source code (Layer 2)
SOURCE_CRITICAL_EXEC_PATTERNS = [
    (r"eval\s*\(\s*Buffer\.from\s*\([^;]{0,300}?(?:base64|base64url|hex)", "Inline dynamic evaluation of encoded Buffer"),
    (r"eval\s*\(\s*atob\s*\(", "Inline dynamic evaluation of Base64 atob() string"),
    (r"eval\s*\(\s*unescape\s*\(", "Obfuscated unescape dynamic evaluation"),
    (r"(?:globalThis|global)(?:\s*\[\s*['\"`]eval['\"`]\s*\]|\s*\.\s*eval)\s*\(|\(\s*0\s*,\s*eval\s*\)\s*\(", "Indirect global/comma dynamic eval invocation"),
    (r"(?:filter|map|slice|constructor)\s*['\"`]?\s*\]?\s*\(\s*['\"`][^'\"`]*return\s+(?:process|global|require)", "Constructor chaining sandbox escape (return process/global)"),
    (r"\bReflect\.construct\s*\(\s*Function\b", "Dynamic code instantiation via Reflect.construct(Function, ...)"),
    (r"(?:\bModule\._compile|[\w$\)\]]\s*\._compile)\s*\(", "Low-level Module._compile dynamic code injection"),
    (r"\bimport\s*\(\s*['\"`]data:(?:text|application)/javascript;base64,", "Dynamic ESM base64 data-URI module import"),
    (r"Atomics\.wait\s*\(", "Low-level synchronous thread sleep evasion"),
]

# Known malicious OAST / Exfiltration / Webhook endpoints & Cloud IMDS SSRF targets (Layer 2)
MALICIOUS_EXFIL_ENDPOINT_REGEX = re.compile(
    r"(?:oastify\.com|\boast\.(?:pro|live|site|online|fun|me)\b|burpcollaborator\.net|"
    r"interact\.sh|interactsh\.com|webhook\.site|pipedream\.net|requestbin\.|"
    r"canarytokens\.com|dnslog\.cn|ceye\.io|ngrok\.io|ngrok-free\.app|"
    r"trycloudflare\.com|loca\.lt|serveo\.net|localhost\.run|beeceptor\.com|"
    r"mockbin\.org|hookbin\.com|pastebin\.com/raw|catbox\.moe|"
    r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|metadata\.google\.internal|"
    r"(?:https?|wss?)://(?:[A-Za-z0-9-]+\.)*(?:transfer\.sh|file\.io|rentry\.co|0x0\.st)(?=[/?#'\"`\s:]|$)|"
    r"\b169\.254\.169\.254\b(?!\.\d)|\b100\.100\.100\.200\b(?!\.\d))",
    re.IGNORECASE
)

# Dangerous shell commands when passed into child_process calls (Layer 2 - evaluated only inside call windows)
DANGEROUS_SHELL_ARG_REGEX = re.compile(
    r"(?:\b(?:curl|wget|nc|netcat|ncat|bash\s+-c|sh\s+-c|cmd(?:\.exe)?\s+/c|powershell|pwsh|"
    r"whoami|uname|nslookup|dig|ping\s+-[nc]|base64\s+-d|chmod\s+\+x|/dev/tcp/|"
    r"/etc/passwd|/etc/shadow|\.npmrc|\.ssh)\b|"
    r"(?:['\"`]|&&|\|\||;|\|)\s*id(?:\s+-[A-Za-z]+)*\s*(?:['\"`]|&&|\|\||;|\||\n|$))",
    re.IGNORECASE
)

# Sensitive host filesystem paths targeted directly in JS source code (Layer 2)
SENSITIVE_SOURCE_PATH_REGEX = re.compile(
    r"(['\"`])[^'\"`\n]*(?:/etc/(?:passwd|shadow|sudoers|crontab)|/proc/self/environ|"
    r"~/.ssh|/root/\.ssh|\.ssh/(?:id_rsa|id_ed25519|authorized_keys)|"
    r"\.(?:bash_history|zsh_history|git-credentials|netrc)|"
    r"\.npmrc|\.aws[/\\]+credentials|\.kube[/\\]+config|\.docker[/\\]+config\.json)\b",
    re.IGNORECASE
)

# Keywords inside decoded Base64/Hex strings that confirm executable/malicious payload vs benign asset
DECODED_PAYLOAD_INDICATORS = re.compile(
    r"(?:\b(?:eval|Function)\s*\(|\bchild_process\b|\b(?:execSync|execFile|execFileSync|spawnSync)\b|"
    r"(?<!\.)\b(?:exec|spawn|fork)\s*\(|(?:child_process|\bcp)\s*\.\s*(?:exec|spawn|fork)\s*\(|"
    r"\bfetch\s*\(|\b(?:https?|http2)\.(?:request|get|post)\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|"
    r"\bprocess\.env\b|\buserInfo\b|\bBuffer\.from\s*\(|"
    r"/bin/sh\b|/bin/bash\b|cmd\.exe\b|powershell\b|\bcurl\s+|\bwget\s+|"
    r"/etc/passwd\b|/etc/shadow\b|/etc/sudoers\b|/proc/self/environ\b|"
    r"\.npmrc\b|\.ssh\b|/tmp/|C:\\\\?Users\\\\?Public|"
    r"\[D04\b|\[OBFUSCATION MARKER\])",
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
    """Detects once whether Node.js supports --permission (22+) or --experimental-permission (20/21)."""
    global _NODE_PERMISSION_FLAGS
    if _NODE_PERMISSION_FLAGS is not None:
        return _NODE_PERMISSION_FLAGS
    for flag in ("--permission", "--experimental-permission"):
        try:
            res = subprocess.run(
                ["node", "--no-warnings", flag, "--allow-fs-read=*", "-e", ""],
                capture_output=True,
                timeout=3
            )
            if res.returncode == 0:
                _NODE_PERMISSION_FLAGS = ["--no-warnings", flag, "--allow-fs-read=*"]
                return _NODE_PERMISSION_FLAGS
        except Exception:
            continue
    _NODE_PERMISSION_FLAGS = ["--no-warnings"]
    return _NODE_PERMISSION_FLAGS


def verify_artifact_integrity(tarball_path: str, expected_sha512: str) -> Dict[str, Any]:
    """Auxiliary & automated check: verifies artifact integrity against SRI hashes (sha512/sha384/sha256/sha1, including multi-hash SRI)."""
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

    def __init__(self, enable_whitelist: bool = True, risk_threshold: int = 35, always_scan_l2: bool = False):
        self.enable_whitelist = enable_whitelist
        self.risk_threshold = risk_threshold
        self.always_scan_l2 = always_scan_l2
        self.sandbox_runner_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "sandbox_runner.js"
        )

    def _deobfuscate_shell_cmd(self, cmd: str) -> str:
        """
        Normalizes shell-level obfuscation before pattern matching:
        - Replaces ${IFS} / $IFS with spaces
        - Joins intra-token single/double quotes (e.g. c'u'r'l' -> curl, 'c'"u"'r'"l" -> curl)
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

    def _resolve_script_chain(
        self, command: str, scripts: Dict[str, Any], max_depth: int = 5
    ) -> List[Tuple[str, str]]:
        """
        Recursively resolves multi-hop `npm/yarn/pnpm run <sub_script>` chains inside package.json scripts.
        """
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

    def _extract_gyp_command_expansions(self, gyp_content: str) -> List[str]:
        """
        Extracts full expressions inside <!(...) and <!@(...) using balanced parenthesis counting
        while respecting single/double quoted strings and escapes.
        """
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

    def _inspect_binding_gyp(self, pkg_dir: str) -> List[str]:
        """
        Cross-checks binding.gyp for malicious command execution via <!(...) or <!@(...).
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

        benign_addon_re = re.compile(
            r"^\s*node\s+(?:--no-warnings\s+)?-(?:p|e|-print|-eval)\s+"
            r"[\"']?\s*(?:console\.log\s*\(\s*)?require\s*\(\s*[\"'](?:node-addon-api|nan|node-gyp-build)[\"']\s*\)"
            r"(?:\.(?:include|include_dir|gyp|targets|path))?\s*\)?\s*;?\s*[\"']?\s*$",
            re.IGNORECASE,
        )
        suspicious_kw_re = re.compile(
            r"\b(?:curl|wget|netcat|ncat|socat|bash|sh|zsh|cmd|powershell|pwsh|"
            r"python\d?|perl|ruby|php|base64|openssl|xxd|eval|exec|spawn|child_process)\b|"
            r"(?:^|[;&|]\s*)nc\s+(?:-[A-Za-z0-9]+\s+)*(?:[A-Za-z0-9.-]+\s+\d{1,5}\b|-[lec]\b)|"
            r"https?://|/tmp/|/var/tmp/|/dev/shm/|\.npmrc|\.ssh|\bnode\s+(?:-[^\s]*\s+)*(?:-e|--eval|-p|--print)\b",
            re.IGNORECASE,
        )

        findings: List[str] = []
        for raw_expr in self._extract_gyp_command_expansions(gyp_content):
            norm_expr = raw_expr.replace('\\"', '"').replace("\\'", "'").strip()
            if not norm_expr or benign_addon_re.match(norm_expr):
                continue
            deobf_expr = self._deobfuscate_shell_cmd(norm_expr)
            matched_desc = None
            for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, norm_expr, re.IGNORECASE) or re.search(pattern, deobf_expr, re.IGNORECASE):
                    matched_desc = desc
                    break
            if matched_desc or suspicious_kw_re.search(deobf_expr):
                preview = re.sub(r"\s+", " ", norm_expr)[:100]
                reason = matched_desc or "Suspicious shell/network/execution command"
                findings.append(f"{reason} in binding.gyp <!({preview})")
        return findings

    def _is_whitelisted_command(
        self,
        command: str,
        scripts: Optional[Dict[str, Any]] = None,
        pkg_dir: Optional[str] = None,
        _visited: Optional[Set[str]] = None,
    ) -> bool:
        if not self.enable_whitelist:
            return False
        cmd = command.strip()
        if not cmd:
            return False
        if re.search(r"[;><`()\r\n]|\$\(|(?<!\|)\|(?!\|)|(?<!&)&(?!&)", cmd):
            return False

        visited = _visited if _visited is not None else set()
        if len(visited) > 5:
            return False

        gyp_malicious: Optional[bool] = None
        for seg in re.split(r"\s*(?:&&|\|\|)\s*", cmd):
            seg_clean = seg.strip()
            if not seg_clean or re.search(r"[;><`()\r\n]|\$\(|(?<!\|)\|(?!\|)|(?<!&)&(?!&)", seg_clean):
                return False
            if DANGEROUS_WHITELIST_FLAGS_RE.search(seg_clean):
                return False

            bridge_match = SINGLE_SCRIPT_BRIDGE_SEGMENT_RE.match(seg_clean)
            if bridge_match:
                sub_name = bridge_match.group(1)
                if not isinstance(scripts, dict) or sub_name not in scripts or sub_name in visited:
                    return False
                sub_cmd = str(scripts[sub_name]).strip()
                if not self._is_whitelisted_command(
                    sub_cmd, scripts=scripts, pkg_dir=pkg_dir, _visited=visited | {sub_name}
                ):
                    return False
                continue

            if NATIVE_BUILD_CMD_RE.match(seg_clean) and pkg_dir:
                if gyp_malicious is None:
                    gyp_malicious = bool(self._inspect_binding_gyp(pkg_dir))
                if gyp_malicious:
                    return False

            if not any(re.search(wl_pattern, seg_clean, re.IGNORECASE) for wl_pattern in WHITELISTED_HOOK_COMMANDS):
                return False
        return True

    def _is_benign_local_node_script(self, hook_name: str, command: str, pkg_dir: str) -> bool:
        """
        Reduces FP for clean postinstall/install/prepare banner scripts like `node postinstall.js`
        (e.g., core-js funding/banner messages). Never applies to `preinstall`.
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
            if os.path.getsize(full_p) > 4096:
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
            r"fromCharCode|fromCodePoint|Atomics|global|globalThis|Reflect|Proxy|constructor)\b|"
            r"import\s*\(|\[\s*['\"`]|"
            r"\b_0x[a-fA-F0-9]{3,}\b|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|"
            r"\[(?:DEPENDENCY CONFUSION MARKER|D04|OBFUSCATION MARKER|TAMPER MARKER)",
            re.IGNORECASE,
        )
        if unsafe_tokens_re.search(content):
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

        all_reqs = re.findall(r"\brequire\b", content)
        valid_reqs = re.findall(
            r"\brequire\s*\(\s*['\"](?:node:)?(?:os|path|tty|util)['\"]\s*\)",
            content,
            flags=re.IGNORECASE,
        )
        if len(all_reqs) != len(valid_reqs):
            return False

        if re.search(r"^\s*import\s+", content, re.MULTILINE):
            return False

        benign_env_keys = {
            "NODE_ENV", "CI", "CONTINUOUS_INTEGRATION", "ADBLOCK",
            "DISABLE_OPENCOLLECTIVE", "OPEN_SOURCE_CONTRIBUTOR", "SILENT",
            "INIT_CWD", "COLOR", "FORCE_COLOR", "NO_COLOR", "TERM", "DEBUG"
        }
        for env_m in re.finditer(r"\bprocess\.env(?:\.([A-Za-z0-9_]+)|\[['\"]([A-Za-z0-9_]+)['\"]\])?", content):
            key = env_m.group(1) or env_m.group(2)
            if not key:
                return False
            if key not in benign_env_keys and not key.startswith("npm_"):
                return False

        return True

    def _is_official_github_release_download(self, command: str, manifest: Dict[str, Any]) -> bool:
        """
        Checks if a curl/wget hook strictly performs a single clean GET download from the package's
        own declared GitHub repository Releases URL (no chaining, no POST, no shell/interpreter).
        """
        repo = manifest.get("repository")
        repo_url = repo.get("url", "") if isinstance(repo, dict) else (repo if isinstance(repo, str) else "")
        repo_match = re.search(r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$", repo_url.strip(), re.IGNORECASE)
        if not repo_match:
            return False
        owner_repo = repo_match.group(1).lower()

        deobf = self._deobfuscate_shell_cmd(command).strip()
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

    def _scan_auxiliary_scripts(
        self,
        pkg_dir: str,
        hook_commands: List[str],
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
    ) -> List[Tuple[str, str, bool, bool]]:
        """
        Scans .sh, .bash, .ps1, .bat, .cmd, .py files referenced by hooks or bundled in the package.
        Returns [(rel_path, pattern_desc, is_referenced_in_hook, is_high_confidence), ...].
        """
        script_exts = (".sh", ".bash", ".ps1", ".bat", ".cmd", ".py")
        shell_exts = (".sh", ".bash", ".ps1", ".bat", ".cmd")
        test_doc_prefixes = ("test/", "tests/", "__tests__/", "spec/", "example/", "examples/", "docs/", "doc/", "benchmark/", "benchmarks/")
        high_conf_aux_re = re.compile(
            r"(?<!\|)\|\s*(?!\|)(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|python\d?(?:\.\d+)?|perl|ruby|php|node|iex)\b|"
            r"/dev/(?:tcp|udp)/|\bmkfifo\b|\bnc(?:at)?\s+.*?-e\b|"
            r"\b(?:base64\s+(?:-d|--decode|-D)|openssl\s+(?:enc|base64)\b.*?-d|xxd\s+-r)\b",
            re.IGNORECASE,
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
                        is_ref = (rel_p in referenced_files or os.path.basename(rel_p) in referenced_files)
                        candidate_paths.append((full_p, rel_p, is_ref))

        nm_info = self._inspect_bundled_node_modules(pkg_dir, manifest=manifest, is_tarball=is_tarball)
        if nm_info.get("should_scan"):
            for full_p in nm_info.get("budget_code_files", []):
                if full_p.lower().endswith(script_exts):
                    rel_p = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
                    if rel_p not in seen_rel:
                        seen_rel.add(rel_p)
                        is_ref = (rel_p in referenced_files or os.path.basename(rel_p) in referenced_files)
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
            deobf = self._deobfuscate_shell_cmd(cleaned)
            matched_descs: Set[str] = set()
            is_high_conf = is_ref or bool(
                high_conf_aux_re.search(cleaned)
                or high_conf_aux_re.search(deobf)
                or MALICIOUS_EXFIL_ENDPOINT_REGEX.search(cleaned)
            )
            for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, cleaned, re.IGNORECASE) or re.search(pattern, deobf, re.IGNORECASE):
                    if desc not in matched_descs:
                        matched_descs.add(desc)
                        hits.append((rel_p, desc, is_ref, is_high_conf))
        return hits

    def _damerau_levenshtein_distance(self, s1: str, s2: str) -> int:
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

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect heavily obfuscated / high-entropy code."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def analyze_manifest(
        self, pkg_path: str, data: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 1A: Manifest Analysis (package.json).
        Inspects lifecycle scripts, binding.gyp, auxiliary scripts, version anomalies,
        typosquatting, binary shadowing, and metadata indicators.
        """
        score = 0
        findings = []
        has_suspicious_install_hook = False
        all_hook_commands: List[str] = []

        # 0. Cross-check binding.gyp for malicious <!() command injection
        gyp_issues = self._inspect_binding_gyp(pkg_path)
        for g_issue in gyp_issues:
            score += 50
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Malicious binding.gyp Command Injection",
                "severity": "CRITICAL",
                "detail": g_issue
            })

        # 1. Inspect lifecycle scripts & multi-hop bridged scripts
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for hook in SUSPICIOUS_LIFECYCLE_HOOKS:
                if hook in scripts:
                    command = str(scripts[hook]).strip()
                    if not command:
                        continue
                    all_hook_commands.append(command)
                    deobf_cmd = self._deobfuscate_shell_cmd(command)
                    bridged_chain = self._resolve_script_chain(command, scripts)
                    for _, sub_cmd in bridged_chain:
                        all_hook_commands.append(sub_cmd)

                    whitelisted = self._is_whitelisted_command(command, scripts=scripts, pkg_dir=pkg_path)

                    direct_patterns: List[str] = []
                    for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS:
                        if re.search(pattern, command, re.IGNORECASE) or re.search(pattern, deobf_cmd, re.IGNORECASE):
                            direct_patterns.append(desc)

                    bridged_findings: List[Dict[str, Any]] = []
                    for sub_name, sub_cmd in bridged_chain:
                        deobf_sub = self._deobfuscate_shell_cmd(sub_cmd)
                        sub_has_inline_eval = bool(re.search(r"\bnode\s+(?:-[^\s]*\s+)*(?:-e|--eval|-p|--print)\b", deobf_sub, re.IGNORECASE))
                        sub_matched_patterns = [
                            desc for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS
                            if re.search(pattern, sub_cmd, re.IGNORECASE) or re.search(pattern, deobf_sub, re.IGNORECASE)
                        ]
                        if sub_matched_patterns or sub_has_inline_eval:
                            whitelisted = False
                            for desc in sub_matched_patterns:
                                bridged_findings.append({
                                    "layer": "Layer 1 - Manifest",
                                    "rule": "Suspicious Hook Command Pattern",
                                    "severity": "CRITICAL",
                                    "detail": f"{desc} in bridged script '{sub_name}' (via '{hook}'): {sub_cmd}"
                                })

                    if direct_patterns or bridged_findings:
                        whitelisted = False

                    if whitelisted:
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": f"Whitelisted Hook: {hook}",
                            "severity": "INFO",
                            "detail": f"Command '{command}' matches whitelist rule."
                        })
                    elif (
                        not bridged_findings
                        and self._is_official_github_release_download(command, data)
                        and not [d for d in direct_patterns if d != "Remote network egress / LOLBin tool invoked in script"]
                    ):
                        score += 15
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": f"Suspicious Lifecycle Hook: {hook}",
                            "severity": "MEDIUM",
                            "detail": f"Hook '{hook}' downloads binary from package's own GitHub Releases: {command}"
                        })
                        direct_patterns = [
                            d for d in direct_patterns
                            if d != "Remote network egress / LOLBin tool invoked in script"
                        ]
                    elif not direct_patterns and not bridged_findings and self._is_benign_local_node_script(hook, command, pkg_path):
                        score += 15
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": f"Suspicious Lifecycle Hook: {hook}",
                            "severity": "LOW",
                            "detail": f"Hook '{hook}' invokes short local banner/check Node script: {command}"
                        })
                    else:
                        has_suspicious_install_hook = True
                        score += 40
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": f"Suspicious Lifecycle Hook: {hook}",
                            "severity": "HIGH",
                            "detail": f"Detected active '{hook}' hook with command: {command}"
                        })

                    for desc in direct_patterns:
                        score += 25
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": "Suspicious Hook Command Pattern",
                            "severity": "CRITICAL",
                            "detail": f"{desc} in '{hook}': {command}"
                        })

                    for bf in bridged_findings:
                        score += 25
                        findings.append(bf)

        # 1b. Scan auxiliary shell/script files (.sh, .bash, .ps1, .bat, .cmd, .py)
        aux_hits = self._scan_auxiliary_scripts(pkg_path, all_hook_commands, manifest=data, is_tarball=is_tarball)
        unref_aux_scored = False
        for rel_p, desc, is_ref, is_high_conf in aux_hits:
            if is_ref or is_high_conf:
                score += 25
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": "Suspicious Hook Command Pattern" if is_ref else "Suspicious Auxiliary Script Pattern",
                    "severity": "CRITICAL",
                    "detail": f"{desc} in auxiliary script '{rel_p}'"
                })
            elif not unref_aux_scored:
                unref_aux_scored = True
                score += 15
                findings.append({
                    "layer": "Layer 1 - Manifest",
                    "rule": "Suspicious Auxiliary Script Pattern",
                    "severity": "MEDIUM",
                    "detail": f"{desc} in unreferenced auxiliary script '{rel_p}'"
                })

        # 2. Inspect version anomalies (Multi-factor Dependency Confusion)
        version_str = str(data.get("version", "1.0.0")).strip()
        ver_core = re.split(r"[-+]", version_str, maxsplit=1)[0]
        ver_parts = ver_core.split(".")
        try:
            major_version = int(ver_parts[0])
            minor_version = int(ver_parts[1]) if len(ver_parts) > 1 and ver_parts[1].isdigit() else 0
            patch_version = int(ver_parts[2]) if len(ver_parts) > 2 and ver_parts[2].isdigit() else 0

            is_calver = (2015 <= major_version <= 2035 and 1 <= minor_version <= 12 and patch_version < 999)
            is_high_ver = (
                (major_version >= SUSPICIOUS_VERSION_THRESHOLD and not is_calver)
                or minor_version >= 999
                or patch_version >= 999
            )
            if is_high_ver:
                js_count = 0
                for root, dirs, files in os.walk(pkg_path):
                    dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
                    js_count += sum(1 for fn in files if fn.endswith((".js", ".cjs", ".mjs")))

                pkg_name_l = str(data.get("name", "")).strip().lower()
                has_repo = bool(data.get("repository"))
                has_internal_name = bool(re.search(r"(?:^|[-_/])(?:internal|corp|private|staging|uit)(?:[-_/]|$)", pkg_name_l))
                has_untrusted_dep = False
                for dep_f in ("dependencies", "optionalDependencies"):
                    dep_obj = data.get(dep_f, {})
                    if isinstance(dep_obj, dict):
                        for sp in dep_obj.values():
                            if self._is_untrusted_dependency_url(str(sp), data):
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
                    score += 15
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": "Dependency Confusion Indicator",
                        "severity": "LOW",
                        "detail": f"High version '{version_str}' in established multi-file repository package (Chromium/date/database-style versioning)"
                    })
                else:
                    score += 50
                    findings.append({
                        "layer": "Layer 1 - Manifest",
                        "rule": "Dependency Confusion Indicator",
                        "severity": "CRITICAL",
                        "detail": f"Abnormally high version '{version_str}' (major >= {SUSPICIOUS_VERSION_THRESHOLD} or minor/patch >= 999)"
                    })
        except (ValueError, IndexError):
            pass

        # 3. Rule 1A.5: Typosquatting / Brandjacking Indicator
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
                    if ("-" in pop and unscoped_name == pop.replace("-", "")) or self._damerau_levenshtein_distance(unscoped_name, pop) == 1:
                        typo_target = pop
                        break
                if typo_target:
                    code_files_count = 0
                    for root, dirs, files in os.walk(pkg_path):
                        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
                        code_files_count += sum(
                            1 for fn in files if fn.endswith((".js", ".cjs", ".mjs", ".ts", ".sh", ".ps1", ".bat", ".py"))
                        )
                    has_any_lifecycle = isinstance(scripts, dict) and any(h in scripts for h in SUSPICIOUS_LIFECYCLE_HOOKS)
                    if has_any_lifecycle or code_files_count <= 3:
                        score += 35
                        findings.append({
                            "layer": "Layer 1 - Manifest",
                            "rule": "Typosquatting / Brandjacking Indicator",
                            "severity": "HIGH",
                            "detail": f"Package name '{pkg_name_raw}' closely resembles popular package '{typo_target}' with install hook or minimal file footprint"
                        })

        # 4. Rule 1A.6: Binary / Command Shadowing
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
            score += 45
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Binary / Command Shadowing",
                "severity": "CRITICAL",
                "detail": f"Package 'bin' overrides core system/toolchain command(s): {', '.join(shadowed_cmds)}"
            })

        # 5. Inspect missing or deceptive metadata
        if not data.get("description") or len(str(data.get("description")).strip()) == 0:
            score += 5
            findings.append({
                "layer": "Layer 1 - Manifest",
                "rule": "Empty Description",
                "severity": "LOW",
                "detail": "Package lacks metadata description."
            })

        return score, findings

    def _extract_github_owner_repo(self, manifest: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
        """Extracts lowercased (owner, repo) if manifest declares a GitHub repository."""
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

        # Bare "owner/repo" shorthand sometimes used in package.json "repository"
        if "://" not in repo_url and ":" not in repo_url:
            m_short = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", repo_url)
            if m_short:
                return (m_short.group(1).lower(), m_short.group(2).lower())
        return None

    def _is_untrusted_dependency_url(
        self,
        spec: str,
        manifest: Optional[Dict[str, Any]] = None,
        allow_raw_own_repo: bool = True,
    ) -> bool:
        """
        Returns True when a dependency spec is an explicit URL or SCP-style Git URL pointing
        outside trusted hosts, uses raw IP addresses, references mutable Gists (gist: or gist.github.com),
        or points to raw.githubusercontent.com (disallowed in lockfiles or mismatched repos).
        """
        cleaned = spec.strip()
        if cleaned.lower().startswith("npm:"):
            npm_target = cleaned[4:].strip()
            at_idx = npm_target.find("@", 1) if npm_target.startswith("@") else npm_target.find("@")
            if at_idx == -1:
                return False
            cleaned = npm_target[at_idx + 1:].strip()

        # Reject mutable anonymous GitHub Gist shorthands (gist:<id>)
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
            # Support SCP-style Git URLs: [git+]user@host:owner/repo.git
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

        # Reject raw IP addresses (IPv4, IPv6, decimal/hex encoded IP)
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            pass
        if re.fullmatch(r"(?:\d+|0x[0-9a-f]+)", host, re.IGNORECASE):
            return True

        # Reject anonymous mutable Gists
        if host in ("gist.github.com", "gist.githubusercontent.com"):
            return True

        # Handle raw.githubusercontent.com: banned in lockfiles, or must match root package's own repo
        if host == "raw.githubusercontent.com":
            if not allow_raw_own_repo:
                return True
            declared = self._extract_github_owner_repo(manifest)
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

    def _is_traversal_file_spec(self, pkg_dir: str, spec: str) -> bool:
        """Detects file:/link: specs that escape the package root via traversal or absolute paths."""
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

    def _extract_package_key_name(self, raw_key: str) -> str:
        """Normalizes dependency / override / resolution keys like '**/@babel/parser' or 'foo>bar@^1.0'."""
        part = raw_key.strip().split(">")[-1].strip()
        if "/" in part:
            segs = [s for s in part.split("/") if s]
            if len(segs) >= 2 and segs[-2].startswith("@"):
                part = f"{segs[-2]}/{segs[-1]}".strip()
            elif segs:
                part = segs[-1].strip()
        # Strip version qualifier (@^1.0.0) while preserving @scope/name
        if part.startswith("@"):
            at_idx = part.find("@", 1)
            if at_idx != -1:
                part = part[:at_idx]
        else:
            at_idx = part.find("@")
            if at_idx != -1:
                part = part[:at_idx]
        return part.strip().lower()

    def _is_suspicious_npm_alias(
        self,
        alias_key: str,
        spec: str,
        manifest: Optional[Dict[str, Any]] = None,
        pkg_dir: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Detects npm: protocol alias hijacking (e.g. 'lodash': 'npm:evil-pkg@1.0.0'
        or 'foo': 'npm:foo@https://evil.com/x.tgz') while permitting standard compat
        aliases such as 'string-width-cjs': 'npm:string-width@^4.2.0'.
        """
        cleaned = spec.strip()
        if not cleaned.lower().startswith("npm:"):
            return False, ""
        body = cleaned[4:].strip()
        if not body:
            return False, ""

        if body.startswith("@"):
            at_idx = body.find("@", 1)
        else:
            at_idx = body.find("@")

        if at_idx != -1:
            target_pkg = body[:at_idx].strip().lower()
            ver_part = body[at_idx + 1:].strip()
        else:
            target_pkg = body.strip().lower()
            ver_part = ""

        if ver_part:
            if self._is_untrusted_dependency_url(ver_part, manifest):
                return True, f"{alias_key} -> {spec} (untrusted tarball URL)"
            if pkg_dir and self._is_traversal_file_spec(pkg_dir, ver_part):
                return True, f"{alias_key} -> {spec} (path traversal target)"

        key_base = self._extract_package_key_name(alias_key)
        if not key_base or key_base == "*" or target_pkg == key_base:
            return False, ""

        # Allow common compat suffixes (-cjs, -esm, -compat, -legacy, -v4, 4) when scope matches
        key_stripped = re.sub(r"(?:-cjs|-esm|-compat|-legacy|-v?\d+|\d+)$", "", key_base)
        key_scoped = key_base.startswith("@")
        target_scoped = target_pkg.startswith("@")
        if key_stripped == target_pkg and key_scoped == target_scoped:
            return False, ""

        return True, f"{alias_key} -> {spec} (redirects to unrelated package '{target_pkg}')"

    def _inspect_bundled_node_modules(
        self,
        pkg_dir: str,
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
        budget: int = 50,
    ) -> Dict[str, Any]:
        """
        Inspects node_modules/ to distinguish legitimate dev npm installs
        (valid v2/v3 node_modules/.package-lock.json + declared/hoisted packages)
        from undeclared/bundled payloads, and prioritizes real code files up to `budget`.
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

        # Strictly validate node_modules/.package-lock.json (npm v7+ hidden lockfile)
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
                            if self._is_untrusted_dependency_url(r_clean, manifest=None, allow_raw_own_repo=False) or self._is_traversal_file_spec(pkg_dir, r_clean):
                                lock_valid = False
                                break
                            if lk_val.get("link") is True and self._is_traversal_file_spec(pkg_dir, f"file:{r_clean}"):
                                lock_valid = False
                                break
                        if isinstance(ver_s, str) and ver_s.strip():
                            v_clean = ver_s.strip()
                            if self._is_untrusted_dependency_url(v_clean, manifest=None, allow_raw_own_repo=False) or self._is_traversal_file_spec(pkg_dir, v_clean):
                                lock_valid = False
                                break
                        valid_entries += 1
                        # Record hoisted top-level packages declared in node_modules/.package-lock.json
                        rest = lk_str[len("node_modules/"):]
                        if "/node_modules/" not in rest:
                            nm_lock_declared_pkgs.add(rest.lower())
                    if lock_valid and valid_entries > 0:
                        has_valid_nm_lock = True
            except Exception:
                has_valid_nm_lock = False

        code_exts = (".js", ".cjs", ".mjs", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".py")
        all_code_check_exts = code_exts + (".node",)

        # Check top-level packages in node_modules/
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

        # In valid dev folders, hoisted transitive packages listed in .package-lock.json are legitimate
        dev_allowed_pkgs = all_declared | (nm_lock_declared_pkgs if has_valid_nm_lock else set())
        undeclared_dev_pkgs = {p for p in top_pkgs if p not in dev_allowed_pkgs}
        is_valid_dev_lock = (
            has_valid_nm_lock
            and (not is_tarball)
            and (not has_stray_root_code)
            and (not has_hidden_code_dir)
            and len(undeclared_dev_pkgs) == 0
        )

        # Clean npm-installed dev environment with no bundledDependencies: skip heavy walk (0 penalty, 0 scan)
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
                            # Strip comment-only lines so license headers (e.g. https://opensource.org/...) do not pollute top-50 budget
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

    def _should_scan_bundled_node_modules(
        self,
        pkg_dir: str,
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
    ) -> bool:
        """Returns True when node_modules contains non-dev/undeclared/bundled code that Layer 2/3 should inspect."""
        return self._inspect_bundled_node_modules(pkg_dir, manifest=manifest, is_tarball=is_tarball).get("should_scan", False)

    def analyze_dependency_graph(
        self, pkg_dir: str, manifest: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[int, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Layer 1B: Dependency Graph & Graph Feature Analysis.
        Extracts runtime dependencies (dependencies & optionalDependencies) from package.json
        plus transitive metadata from package-lock.json / npm-shrinkwrap.json, and detects:
        1. Non-Registry / Untrusted Dependency Source (+40 HIGH)
        2. Runtime Self-Dependency (+20 MEDIUM)
        3. File / Link Dependency Path Traversal (+40 HIGH)
        4. Protocol Alias Hijacking via npm: (+40 HIGH)
        5. Overrides / Resolutions Hijacking (+40 HIGH)
        6. Lockfile Resolved URL Poisoning (+45 CRITICAL)
        7. Undeclared Pre-bundled node_modules (+20 MEDIUM)
        """
        score = 0
        findings = []
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
                        "scope": field
                    })

        # Parse package-lock.json and npm-shrinkwrap.json recursively
        lockfile_candidates = [
            os.path.join(pkg_dir, "package-lock.json"),
            os.path.join(pkg_dir, "npm-shrinkwrap.json"),
        ]
        has_lockfile = False
        transitive_count = 0
        estimated_depth = 1 if direct_deps else 0
        lockfile_poisoned: List[str] = []

        def _lock_url_reason(raw_spec: str) -> Optional[str]:
            # Disallow raw.githubusercontent.com completely inside lockfiles (no root repo fallback confusion)
            if self._is_untrusted_dependency_url(raw_spec, manifest=None, allow_raw_own_repo=False):
                if "raw.githubusercontent.com" in raw_spec.lower():
                    return "mutable raw branch URL in lockfile"
                return "untrusted host URL"
            if self._is_traversal_file_spec(pkg_dir, raw_spec):
                return "path traversal target"
            return None

        def _check_lock_entry(entry_name: str, entry_obj: Dict[str, Any], lf_name: str) -> None:
            resolved_val = entry_obj.get("resolved")
            if isinstance(resolved_val, str) and resolved_val.strip():
                r_str = resolved_val.strip()
                url_reason = _lock_url_reason(r_str)
                if url_reason:
                    lockfile_poisoned.append(f"{lf_name}:{entry_name} -> {r_str} ({url_reason})")
                elif entry_obj.get("link") is True and self._is_traversal_file_spec(pkg_dir, f"file:{r_str}"):
                    lockfile_poisoned.append(f"{lf_name}:{entry_name} -> {r_str} (symlink escape)")
            ver_val = entry_obj.get("version")
            if isinstance(ver_val, str) and ver_val.strip():
                v_str = ver_val.strip()
                ver_reason = _lock_url_reason(v_str)
                if ver_reason:
                    lockfile_poisoned.append(f"{lf_name}:{entry_name} -> {v_str} ({ver_reason})")
                else:
                    bad_alias, reason = self._is_suspicious_npm_alias(entry_name, v_str, manifest=None, pkg_dir=pkg_dir)
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
                            "scope": "transitive"
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
                                    "scope": "transitive"
                                })

                v1_deps = lock_data.get("dependencies", {})
                if isinstance(v1_deps, dict) and v1_deps:
                    _walk_v1_deps(v1_deps, 1, lf_name)
            except Exception:
                pass

        # Collect dependency maps across dependencies, optionalDependencies, devDependencies, peerDependencies
        # (Checking devDependencies/peerDependencies for explicit hijacks/traversals too)
        all_manifest_deps: Dict[str, str] = dict(direct_deps)
        for extra_field in ("devDependencies", "peerDependencies"):
            extra_obj = manifest.get(extra_field, {})
            if isinstance(extra_obj, dict):
                for dk, dv in extra_obj.items():
                    all_manifest_deps.setdefault(str(dk).strip(), str(dv).strip())

        # Rule 1: Non-Registry / Untrusted Dependency Source (+40 HIGH)
        untrusted_deps = []
        for dep_name, spec in direct_deps.items():
            if self._is_untrusted_dependency_url(spec, manifest):
                untrusted_deps.append(f"{dep_name} -> {spec}")

        if untrusted_deps:
            score += 40
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Non-Registry / Untrusted Dependency Source",
                "severity": "HIGH",
                "detail": f"Dependency resolves from untrusted external host URL: {', '.join(untrusted_deps[:3])}"
            })

        # Rule 2: Runtime Self-Dependency (+20 MEDIUM, supporting signal below threshold)
        if manifest_name and manifest_name in direct_deps:
            score += 20
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Runtime Self-Dependency",
                "severity": "MEDIUM",
                "detail": f"Package '{manifest_name}' declares itself in runtime dependencies."
            })

        # Rule 3: File / Link Dependency Path Traversal (+40 HIGH)
        traversal_deps = []
        for dep_name, spec in all_manifest_deps.items():
            if self._is_traversal_file_spec(pkg_dir, spec):
                traversal_deps.append(f"{dep_name} -> {spec}")
        if traversal_deps:
            score += 40
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "File / Link Dependency Path Traversal",
                "severity": "HIGH",
                "detail": f"Local file:/link: dependency escapes package root: {', '.join(traversal_deps[:3])}"
            })

        # Rule 4: Protocol Alias Hijacking via npm: (+40 HIGH)
        alias_hijacks = []
        for dep_name, spec in all_manifest_deps.items():
            is_bad_alias, alias_reason = self._is_suspicious_npm_alias(dep_name, spec, manifest, pkg_dir)
            if is_bad_alias:
                alias_hijacks.append(alias_reason)
        if alias_hijacks:
            score += 40
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Protocol Alias Hijacking",
                "severity": "HIGH",
                "detail": f"Suspicious npm: alias redirect detected: {', '.join(alias_hijacks[:3])}"
            })

        # Rule 5: Overrides / Resolutions Hijacking (+40 HIGH)
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
                if self._is_untrusted_dependency_url(val_str, manifest):
                    override_hijacks.append(f"{origin}[{parent_key}] -> {val_str} (untrusted URL)")
                elif self._is_traversal_file_spec(pkg_dir, val_str):
                    override_hijacks.append(f"{origin}[{parent_key}] -> {val_str} (path traversal)")
                else:
                    bad_alias, reason = self._is_suspicious_npm_alias(parent_key, val_str, manifest, pkg_dir)
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
                "detail": f"Malicious dependency override/resolution target detected: {', '.join(override_hijacks[:3])}"
            })

        # Rule 6: Lockfile Resolved URL Poisoning (+45 CRITICAL)
        if lockfile_poisoned:
            score += 45
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Lockfile Resolved URL Poisoning",
                "severity": "CRITICAL",
                "detail": f"Lockfile resolves dependency from poisoned or untrusted location: {', '.join(lockfile_poisoned[:3])}"
            })

        # Rule 7: Undeclared Pre-bundled node_modules (+20 MEDIUM; clean npm install dev env exempted)
        nm_info = self._inspect_bundled_node_modules(pkg_dir, manifest, is_tarball=is_tarball)
        if not nm_info.get("is_valid_dev_lock") and nm_info.get("undeclared_code_files"):
            score += 20
            findings.append({
                "layer": "Layer 1 - Dependency Graph",
                "rule": "Pre-bundled node_modules Detected",
                "severity": "MEDIUM",
                "detail": (
                    f"Undeclared pre-bundled code inside node_modules/ ({nm_info['total_files']} scanned files): "
                    f"{', '.join(nm_info['undeclared_code_files'][:3])}"
                )
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

    def _inspect_tarball_structure(self, tarball_path: str) -> List[str]:
        """
        Inspects a tarball (.tgz / .tar.gz / .tar) for structural supply-chain attacks:
        - Path traversal / Tar Slip (leading '/', drive letter, '..')
        - Symlink or hardlink escaping package root
        - Duplicate file / manifest entries after posixpath.normpath (Tar Clobbering / Manifest Confusion)
        """
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

                    # 1. Tar Slip / Path Traversal check BEFORE normalization
                    if (
                        norm_name.startswith("/")
                        or bool(re.match(r"^[A-Za-z]:", norm_name))
                        or ".." in parts
                    ):
                        anomalies.append(f"Tar Slip path traversal member: '{raw_name}'")
                        continue

                    canon_rel = posixpath.normpath(norm_name)
                    if canon_rel == ".":
                        canon_rel = ""

                    # 2. Symlink / Hardlink escape check
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

                    # 3. Duplicate regular file / manifest / Tar Clobbering check
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

    def analyze_artifact_integrity(
        self,
        pkg_dir: str,
        manifest: Dict[str, Any],
        tarball_path: Optional[str] = None,
        expected_sha512: Optional[str] = None
    ) -> Tuple[int, List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Layer 1C: Automated Artifact Hash & Structural Integrity Verification.
        Checks package tarball (.tgz) SRI hash (sha512/sha384/sha256/sha1 & multi-hash) and inspects
        tarball members for Tar Slip, symlink/hardlink escapes, and duplicate package.json entries.
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

        if not resolved_tarball:
            return 0, [], None

        # Structural check runs on any existing tarball, even when no expected hash was supplied
        struct_anomalies = self._inspect_tarball_structure(resolved_tarball) if os.path.isfile(resolved_tarball) else []
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
                    )
                })
            elif not struct_anomalies:
                findings.append({
                    "layer": "Layer 1 - Integrity",
                    "rule": "Artifact Integrity Verified",
                    "severity": "INFO",
                    "detail": f"Tarball '{os.path.basename(resolved_tarball)}' matches expected SRI integrity hash."
                })

        if struct_anomalies:
            score += 50
            findings.append({
                "layer": "Layer 1 - Integrity",
                "rule": "Tarball Structural / Path Traversal Attack",
                "severity": "CRITICAL",
                "detail": f"Structural exploit detected in '{os.path.basename(resolved_tarball)}': {'; '.join(struct_anomalies[:3])}"
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

    _STATIC_NON_CODE_EXTENSIONS = (
        ".json", ".node", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".map", ".tar", ".tgz", ".gz", ".zip"
    )
    _JS_COMMENT_OR_STR_RE = re.compile(
        r'("(?:\\[\s\S]|[^"\\\n])*"|\'(?:\\[\s\S]|[^\'\\\n])*\'|`(?:\\[\s\S]|[^`\\])*`)|'
        r'(/\*[\s\S]*?\*/|//[^\n]*)'
    )
    _JS_ESCAPE_DECODE_RE = re.compile(r'(\\\\)|\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))')
    _PUBLIC_DNS_IPS = frozenset({"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"})
    _DOC_AND_CGNAT_NETS = (
        ipaddress.IPv4Network("192.0.2.0/24"),
        ipaddress.IPv4Network("198.51.100.0/24"),
        ipaddress.IPv4Network("203.0.113.0/24"),
        ipaddress.IPv4Network("100.64.0.0/10"),
    )

    def _is_likely_minified_or_dist(self, rel_path: str, content: str) -> bool:
        """
        Determines whether a JS file is a genuine minified/bundled asset (`len >= 3000`
        combined with high average line length or authentic bundler signatures),
        preventing attackers from abusing `dist/`, `sourceMappingURL=`, or small files
        to evade Layer 2 analysis.
        """
        if not content or len(content) < 3000:
            return False
        lines = content.splitlines()
        avg_line_len = len(content) / max(1, len(lines))
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

    def _strip_js_comments_safely(self, content: str) -> str:
        """
        Single-pass O(n) lexer that strips JS line (`//`) and block (`/* ... */`) comments
        while preserving string literals, template literals, and JS RegExp literals
        (e.g. `/a\\/*/`, `/https?:\\/\\//`, `/"/`) verbatim so regex slashes or quotes never
        trigger false comment truncation.
        """
        if not content:
            return content
        n = len(content)
        out: List[str] = []
        i = 0
        can_start_regex = True
        regex_prefix_keywords = {
            "return", "case", "throw", "in", "of", "typeof", "void",
            "delete", "new", "yield", "await", "else", "do",
            "instanceof", "export", "default",
        }

        while i < n:
            ch = content[i]
            if ch.isspace():
                out.append(ch)
                i += 1
                continue

            # String or template literals
            if ch in ("'", '"', "`"):
                quote = ch
                start = i
                i += 1
                while i < n:
                    sc = content[i]
                    if sc == "\\":
                        i += 2
                        continue
                    if sc == quote:
                        i += 1
                        break
                    if quote != "`" and sc in ("\n", "\r"):
                        break
                    i += 1
                out.append(content[start:i])
                can_start_regex = False
                continue

            # Comments (`//` and `/* ... */`)
            if ch == "/" and i + 1 < n:
                nxt = content[i + 1]
                if nxt == "/":
                    i += 2
                    while i < n and content[i] != "\n":
                        i += 1
                    out.append(" ")
                    continue
                if nxt == "*":
                    end = content.find("*/", i + 2)
                    if end == -1:
                        out.append("\n" if "\n" in content[i:] else " ")
                        break
                    block = content[i:end + 2]
                    out.append("\n" if "\n" in block else " ")
                    i = end + 2
                    continue

                # Contextual JS RegExp literal check
                if can_start_regex:
                    j = i + 1
                    in_class = False
                    found_close = False
                    while j < n:
                        rc = content[j]
                        if rc in ("\n", "\r"):
                            break
                        if rc == "\\":
                            j += 2
                            continue
                        if rc == "[" and not in_class:
                            in_class = True
                        elif rc == "]" and in_class:
                            in_class = False
                        elif rc == "/" and not in_class:
                            found_close = True
                            j += 1
                            break
                        j += 1
                    if found_close:
                        while j < n and content[j] in "gimsuydv":
                            j += 1
                        out.append(content[i:j])
                        i = j
                        can_start_regex = False
                        continue

                out.append(ch)
                i += 1
                can_start_regex = True
                continue

            # Identifiers / numbers / keywords
            if ch.isalnum() or ch in ("_", "$"):
                start = i
                i += 1
                while i < n and (content[i].isalnum() or content[i] in ("_", "$")):
                    i += 1
                word = content[start:i]
                out.append(word)
                can_start_regex = word in regex_prefix_keywords
                continue

            out.append(ch)
            if ch in ("=", "(", "[", "{", "}", ",", ";", ":", "!", "&", "|", "?", "~", "+", "-", "*", "%", "^", "<", ">"):
                can_start_regex = True
            elif ch in (")", "]", "."):
                can_start_regex = False
            else:
                can_start_regex = False
            i += 1

        return "".join(out)

    def _normalize_js_for_static_scan(self, content: str) -> str:
        """
        Preprocesses JS text by decoding safe printable ASCII `\\xXX` / `\\uXXXX` escapes,
        iteratively folding adjacent string literal concatenations (`'ev' + 'al'` -> `'eval'`),
        and converting valid identifier bracket access (`cp['execSync']`) to dot notation (`cp.execSync`).
        """
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

        norm = self._JS_ESCAPE_DECODE_RE.sub(_decode_esc, content)

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

        tail_guard = r"(?!\s*(?:\.(?!\.\.)|\[))"
        sq_re = re.compile(rf"'([^'\\\n]{{0,200}})'\s*\+\s*'([^'\\\n]{{0,200}})'{tail_guard}")
        dq_re = re.compile(rf'"([^"\\\n]{{0,200}})"\s*\+\s*"([^"\\\n]{{0,200}})"{tail_guard}')
        bt_re = re.compile(
            rf"`((?:(?!\$\{{)[^`\\\n]){{0,200}})`\s*\+\s*`((?:(?!\$\{{)[^`\\\n]){{0,200}})`{tail_guard}"
        )
        any_side = r"(?:'([^'\\\n]{0,200})'|\"([^\"\\\n]{0,200})\"|`((?:(?!\$\{)[^`\\\n]){0,200})`)"
        mix_any_re = re.compile(rf"{any_side}\s*\+\s*{any_side}{tail_guard}")

        for _ in range(16):
            updated = sq_re.sub(lambda m: _fold_same_quote(m, "'"), norm)
            updated = dq_re.sub(lambda m: _fold_same_quote(m, '"'), updated)
            updated = bt_re.sub(lambda m: _fold_same_quote(m, "`"), updated)
            updated = mix_any_re.sub(_fold_any_pair, updated)
            if updated == norm:
                break
            norm = updated

        # Convert bracket member access to dot notation for valid JS identifiers
        norm = re.sub(
            r"""(?<=[\w$\)\]])\s*\[\s*(['"`])([A-Za-z_$][\w$]*)\1\s*\](?!\s*:)""",
            r".\2",
            norm,
        )
        return norm

    def _is_malicious_public_ipv4(self, ip_str: str) -> bool:
        """
        Validates an IPv4 string, explicitly permitting Cloud IMDS targets while filtering
        private, loopback, link-local, multicast, reserved, unspecified, documentation,
        CGNAT, and major public DNS resolver addresses.
        """
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
        if any(addr in net for net in self._DOC_AND_CGNAT_NETS):
            return False
        if ip_str in self._PUBLIC_DNS_IPS:
            return False
        return True

    def _find_suspicious_exfil_endpoints(self, code_no_comments: str) -> Optional[str]:
        """
        Scans comment-stripped JS code for Cloud IMDS targets, OAST/webhook/tunnel/paste
        domains, and raw public IPv4 endpoints inside HTTP/WS URLs or socket calls.
        """
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
            if self._is_malicious_public_ipv4(m.group(1)):
                return m.group(0)

        sock_ip_re = re.compile(
            r"(?:(?:net\.(?:connect|createConnection)|tls\.connect|dgram\.createSocket|\.\s*connect)\s*\([^;\n]{0,140}?|"
            r"\bhost(?:name)?\s*:\s*)['\"`](\d{1,3}(?:\.\d{1,3}){3})['\"`]",
            re.IGNORECASE,
        )
        for m in sock_ip_re.finditer(code_no_comments):
            if self._is_malicious_public_ipv4(m.group(1)):
                return m.group(1)

        return None

    def _is_scannable_text_file(self, full_path: str) -> bool:
        """
        Returns True if `full_path` is an existing non-binary file (excluding JSON, native addons,
        media, fonts, archives, and files containing NUL bytes).
        """
        if not os.path.isfile(full_path):
            return False
        if full_path.lower().endswith(self._STATIC_NON_CODE_EXTENSIONS):
            return False
        try:
            with open(full_path, "rb") as f:
                sample = f.read(512)
            return b"\x00" not in sample
        except OSError:
            return False

    def _tokenize_shell_tokens(self, cmd: str) -> List[str]:
        """Minimal quote-aware tokenizer for extracting node CLI file arguments."""
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

    def _resolve_pkg_script_candidate(
        self,
        pkg_dir: str,
        raw_path: str,
        base_dir: Optional[str] = None,
    ) -> Optional[str]:
        """
        Resolves a relative/extensionless script specifier inside `pkg_dir` safely
        (trying exact path, .js/.cjs/.mjs, and /index.{js,cjs,mjs}), rejecting escapes
        above `pkg_dir`, `node_modules` targets, and non-text/binary files.
        """
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
            if not self._is_scannable_text_file(full_p):
                continue
            rel_norm = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
            if rel_norm.startswith("../") or "/node_modules/" in f"/{rel_norm}" or rel_norm.startswith("node_modules/"):
                continue
            return rel_norm
        return None

    def _extract_node_targets_from_cmd(self, cmd_str: str) -> List[str]:
        """
        Parses a shell command string with `_tokenize_shell_tokens` and returns
        Node.js preload/script targets (`-r`/`--require`/`--import`/`--loader` and
        positional entrypoints, skipping `-e`/`--eval`/`-p`/`--print` payloads and redirections).
        """
        if not cmd_str or not isinstance(cmd_str, str):
            return []
        targets: List[str] = []
        tokens = self._tokenize_shell_tokens(cmd_str)
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
            elif tokens[i].startswith(("./", "bin/", "scripts/")) and "/" in tokens[i]:
                targets.append(tokens[i])
            i += 1
        return targets

    def _extract_declared_entrypoints(self, pkg_dir: str, manifest: Dict[str, Any]) -> Set[str]:
        """
        Collects normalized relative paths of package entrypoints (`main`, `bin`, `exports`,
        bridged lifecycle scripts — including extensionless Node CLI scripts) and runs a
        2-hop BFS over local `require('./...')` / `import` statements to include internal
        targets even if they reside in `test/` or carry unusual extensions.
        """
        entrypoints: Set[str] = set()

        def add_candidate(raw_path: str, base_dir: Optional[str] = None) -> Optional[str]:
            rel_norm = self._resolve_pkg_script_candidate(pkg_dir, raw_path, base_dir=base_dir)
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
                add_candidate(node)
            elif isinstance(node, list):
                for item in node:
                    walk_exports(item)
            elif isinstance(node, dict):
                for val in node.values():
                    walk_exports(val)

        if "exports" in manifest:
            walk_exports(manifest["exports"])

        def extract_node_targets(cmd_str: str):
            for t in self._extract_node_targets_from_cmd(cmd_str):
                add_candidate(t)

        scripts = manifest.get("scripts", {})
        if isinstance(scripts, dict):
            seen_scripts: Set[str] = set()
            to_inspect: List[str] = [
                str(scripts[h]) for h in EXTENDED_SANDBOX_HOOKS if h in scripts
            ]
            while to_inspect:
                cmd = to_inspect.pop()
                extract_node_targets(cmd)
                deobf_cmd = self._deobfuscate_shell_cmd(cmd)
                if deobf_cmd != cmd:
                    extract_node_targets(deobf_cmd)
                for sub_name, sub_cmd in self._resolve_script_chain(cmd, scripts):
                    if sub_name not in seen_scripts:
                        seen_scripts.add(sub_name)
                        to_inspect.append(sub_cmd)

        # 2-hop BFS over relative require()/import() inside discovered entrypoints
        local_import_patterns = (
            re.compile(r"""\brequire\s*\(\s*['"](\.[^'"\n]+)['"]\s*\)"""),
            re.compile(r"""\bimport\s+(?:[*\w{},\s$]+\s+from\s+)?['"](\.[^'"\n]+)['"]"""),
            re.compile(r"""\bexport\s+[\w*{},\s$]+\s+from\s+['"](\.[^'"\n]+)['"]"""),
            re.compile(r"""\bimport\s*\(\s*['"](\.[^'"\n]+)['"]\s*\)"""),
        )
        visited: Set[str] = set(entrypoints)
        queue: List[Tuple[str, int]] = [(ep, 0) for ep in sorted(entrypoints)]
        max_bfs_files = 200
        while queue and len(visited) < max_bfs_files:
            rel_ep, depth = queue.pop(0)
            if depth >= 2:
                continue
            ep_full = os.path.normpath(os.path.join(pkg_dir, rel_ep))
            ep_dir = os.path.dirname(ep_full)
            try:
                with open(ep_full, "r", encoding="utf-8", errors="ignore") as f:
                    src = f.read(512 * 1024)
            except OSError:
                continue
            norm_src = self._normalize_js_for_static_scan(self._strip_js_comments_safely(src))
            for pat in local_import_patterns:
                for m in pat.finditer(norm_src):
                    added_rel = add_candidate(m.group(1), base_dir=ep_dir)
                    if added_rel and added_rel not in visited:
                        visited.add(added_rel)
                        if len(visited) < max_bfs_files:
                            queue.append((added_rel, depth + 1))

        return entrypoints

    _HARMLESS_XML_NS_RE = re.compile(
        r"https?://(?:www\.)?(?:w3\.org|schemas\.|purl\.org|apache\.org/licenses|spdx\.org)[^\s'\"<>]*",
        re.IGNORECASE,
    )

    def _verify_decoded_payload_bytes(
        self,
        decoded_bytes: bytes,
        encoding_label: str,
        has_url_risk_context: bool = False,
    ) -> Optional[str]:
        """
        Semantically verifies decoded Base64/Hex bytes: requires >= 85% printable ASCII,
        filters harmless XML/SVG namespaces, PEM certificates, and JSON sourcemaps,
        checks `DECODED_PAYLOAD_INDICATORS`, and flags URLs only when pointing to a
        suspicious exfil endpoint or paired with decode/network/exec/hook context.
        """
        if not decoded_bytes or len(decoded_bytes) < 8:
            return None
        printable = sum(
            1 for b in decoded_bytes if (0x20 <= b <= 0x7E) or b in (9, 10, 13)
        )
        if printable / len(decoded_bytes) < 0.85:
            return None

        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        if "-----BEGIN " in decoded_text and "-----END " in decoded_text:
            return None
        if '"version":3' in decoded_text and '"mappings":' in decoded_text:
            return None
        if "sourceMappingURL=" in decoded_text and "eval" not in decoded_text:
            return None

        cleaned = self._HARMLESS_XML_NS_RE.sub(" ", decoded_text)
        preview = re.sub(r"\s+", " ", decoded_text).strip()[:80]
        if DECODED_PAYLOAD_INDICATORS.search(cleaned):
            return f"Decoded {encoding_label} payload contains executable indicator: '{preview}'"
        if re.search(r"(?:https?|wss?)://[^\s'\"`<>]+", cleaned, re.IGNORECASE):
            exfil_ep = self._find_suspicious_exfil_endpoints(cleaned)
            if exfil_ep or has_url_risk_context:
                return f"Decoded {encoding_label} payload contains suspicious URL indicator: '{preview}'"
        return None

    def _inspect_encoded_strings(
        self, norm_code: str, has_url_risk_context: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Rule 2.8: Semantically verified encoded payload inspection across concatenated
        single/double/backtick literals. Supports Base64, Reversed Base64 / Base64URL
        (when `.reverse()` appears), Base64URL, and even-length Hexadecimal strings >= 40 chars.
        Never flags blind Base64 lengths without verified executable/malicious content.
        """
        if not norm_code:
            return False, None

        # Explicitly inspect JS Data URIs or split/sliced Data URIs
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
                verdict = self._verify_decoded_payload_bytes(
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

            # Ignore harmless SVG/font data URIs unless manipulated via string splitting methods
            if any(tag in prefix for tag in ("data:image/", "data:font/", "sourcemappingurl", "integrity", "sha512-")):
                ctx_window = norm_code[max(0, match.start() - 60):min(len(norm_code), match.end() + 60)]
                if not re.search(r"\.(?:split|slice|substring|replace)\s*\(", ctx_window):
                    continue

            # 1. Standard / URL-safe Base64 decode attempt (no early `/` pre-filter)
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
                        verdict = self._verify_decoded_payload_bytes(
                            raw, "Base64", has_url_risk_context=has_url_risk_context
                        )
                        if verdict:
                            return True, verdict
                except Exception:
                    pass

            # 2. Reversed Base64 / Base64URL decode attempt (when `.reverse()` is present)
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
                            verdict = self._verify_decoded_payload_bytes(
                                raw_rev, "Reversed Base64", has_url_risk_context=has_url_risk_context
                            )
                            if verdict:
                                return True, verdict
                    except Exception:
                        pass

            # 3. Hexadecimal string decode attempt (even length >= 40)
            if len(candidate) >= 40 and len(candidate) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", candidate):
                try:
                    raw_hex = bytes.fromhex(candidate)
                    verdict = self._verify_decoded_payload_bytes(
                        raw_hex, "Hexadecimal", has_url_risk_context=has_url_risk_context
                    )
                    if verdict:
                        return True, verdict
                except Exception:
                    pass

        return False, None

    def _is_benign_sequential_charcodes(self, vals: List[int]) -> bool:
        """
        Returns True if numeric charcodes represent a benign sequential lookup table
        (e.g., ASCII 0,1,2,3...) whose decoded characters contain no payload indicators.
        """
        if len(vals) < 8:
            return False
        diffs_one = sum(1 for a, b in zip(vals, vals[1:]) if b - a == 1)
        if diffs_one < max(len(vals) - 2, int(0.85 * (len(vals) - 1))):
            return False
        decoded = "".join(chr(v) for v in vals if 0 <= v <= 0x10FFFF)
        return not bool(DECODED_PAYLOAD_INDICATORS.search(decoded))

    def _detect_heavy_obfuscation(
        self, raw_content: str, no_comments: str, norm_code: Optional[str] = None
    ) -> Optional[str]:
        """
        Rule 2.6: Detects JSFuck, XOR decoding loops, `_0x` (including prefixed `a0_0x...`),
        dense/split ASCII `\\xXX` or `\\uXXXX` escapes (ignoring non-ASCII i18n escapes),
        and suspicious `fromCharCode`/`fromCodePoint` via `.apply`/spread/`.map`, while
        exempting sequential lookup tables and clean byte-to-char decoders.
        """
        # 1. JSFuck payloads (high-confidence standalone signature)
        for jsf_m in re.finditer(r"[!+()\[\]{}]{30,}", raw_content):
            if jsf_m.group(0).count("[]") >= 8:
                return "JSFuck bracket/operator obfuscation signature"

        cc_haystack = norm_code if norm_code is not None else no_comments

        # 2. XOR dynamic decoding loops around fromCharCode/fromCodePoint
        for cc_call in re.finditer(r"\bfrom(?:CharCode|CodePoint)\b", cc_haystack):
            win = cc_haystack[max(0, cc_call.start() - 350):min(len(cc_haystack), cc_call.end() + 200)]
            win_no_str = re.sub(r"(['\"`])(?:\\[\s\S]|(?!\1)[^\\])*\1", " ", win)
            win_no_regex = re.sub(
                r"(?<=[=(,:!&|?~;{\[\n])\s*/(?:\\.|[^/\\\n])+/[gimsuydv]*",
                " ",
                win_no_str,
            )
            if re.search(r"[\w$\)\]]\s*\^\s*(?:0x[0-9a-fA-F]+|\d+|[A-Za-z_$\(\[])", win_no_regex):
                if (
                    "charCodeAt" in win_no_regex
                    or "codePointAt" in win_no_regex
                    or re.search(r"\.\s*map\s*\(|\b(?:for|while)\s*\(|\[[^\]]+\]", win_no_regex)
                ):
                    return "XOR charCodeAt/array dynamic payload decoding loop"

        # 3. Obfuscator `_0x` identifiers (including prefixed `a0_0x...`)
        obf_vars = len(re.findall(r"\b[A-Za-z0-9_$]*_0x[a-fA-F0-9]{4,}\b", no_comments))
        if obf_vars >= 5:
            return "Heavy JS obfuscation (_0x identifier arrays)"

        # 4. Split-aware dense \xXX / \uXXXX sequences (exempting non-ASCII i18n/CJK escapes > 0x9F)
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
                if not self._is_benign_sequential_charcodes(vals):
                    return "Dense hex/unicode escape obfuscation sequence"

        # 5. Direct numeric `String.fromCharCode(...)` / `String.fromCodePoint(...)`
        direct_cc_re = re.compile(
            r"String\.from(?:CharCode|CodePoint)\s*\(\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){7,})\s*\)"
        )
        for cc_m in direct_cc_re.finditer(cc_haystack):
            nums = [
                int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", cc_m.group(1))
            ]
            if not self._is_benign_sequential_charcodes(nums):
                return "String.fromCharCode/fromCodePoint integer array obfuscation"

        num_arr_re = re.compile(r"\[\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){7,})\s*\]")

        # 6a. Indirect `.apply()` or `...spread` with fromCharCode/fromCodePoint
        apply_spread_re = re.compile(
            r"String\.from(?:CharCode|CodePoint)\s*\.\s*apply\s*\(|"
            r"String\.from(?:CharCode|CodePoint)\s*\(\s*\.\.\.\s*[A-Za-z_$\[]"
        )
        for ind_m in apply_spread_re.finditer(cc_haystack):
            win = cc_haystack[max(0, ind_m.start() - 300):min(len(cc_haystack), ind_m.end() + 200)]
            inline_arrays = list(num_arr_re.finditer(win))
            if inline_arrays:
                all_benign = all(
                    self._is_benign_sequential_charcodes([
                        int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                        for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", arr_m.group(1))
                    ])
                    for arr_m in inline_arrays
                )
                if all_benign:
                    continue
            return "Indirect String.fromCharCode (.apply/spread) obfuscation"

        # 6b. Indirect `.map(...)` with single/multi-param arrow or function callback
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
                    self._is_benign_sequential_charcodes([
                        int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                        for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", arr_m.group(1))
                    ])
                    for arr_m in inline_arrays
                )
                if all_benign:
                    continue
                return "Indirect String.fromCharCode (.map inline array) obfuscation"
            has_math_or_bit_op = bool(
                re.search(r"\^|<<|>>|[+\-~%]|\bcharCodeAt\b", ind_m.group(0))
            )
            if has_math_or_bit_op or has_obf_or_exec_ctx:
                return "Indirect String.fromCharCode (.map) obfuscation"

        return None

    def _classify_sensitive_host_path(self, norm_code: str) -> Tuple[int, Optional[str]]:
        """
        Rule 2.7: Detects static and dynamically constructed (`path[.posix|.win32].join`/
        `resolve`/`homedir`/`process.env.HOME`) sensitive host paths, separated into:
        - Tier 1 (SSH keys, shadow/sudoers/passwd, /proc/self/environ, history/git-credentials):
          unconditional HIGH risk (+40).
        - Tier 2 (tool configs: .npmrc, .aws/credentials, .kube/config, .docker/config.json):
          context-gated (+15 MEDIUM standalone, escalated to +40 HIGH with net/eval/obf/hook).
        """
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

    def _calculate_windowed_entropy(self, content: str) -> float:
        """
        Rule 2.9 helper: Strips JS comments and benign image/font Data URIs, then computes
        maximum Shannon entropy over 512-byte sliding windows (step 128 bytes).
        """
        if not content:
            return 0.0
        stripped = self._strip_js_comments_safely(content)
        stripped = re.sub(
            r"data:(?:image|font|audio|video)/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=\s]{24,}",
            " ",
            stripped,
            flags=re.IGNORECASE,
        )
        stripped = re.sub(r"sourceMappingURL=[^\s]+", " ", stripped)
        n = len(stripped)
        if n <= 200:
            return 0.0
        if n <= 512:
            return self.calculate_entropy(stripped)
        max_ent = 0.0
        for start in range(0, max(1, n - 512 + 1), 128):
            ent = self.calculate_entropy(stripped[start:start + 512])
            if ent > max_ent:
                max_ent = ent
        tail_ent = self.calculate_entropy(stripped[-512:])
        return max(max_ent, tail_ent)

    _SENSITIVE_ENV_KEY_NAMES = (
        "NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|"
        "AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|"
        "AZURE_CLIENT_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
        "SLACK_TOKEN|DISCORD_TOKEN|STRIPE_KEY|DATABASE_URL|CI_JOB_TOKEN|DOCKER_PASSWORD"
    )
    _SENSITIVE_OS_RECON_FUNCS = (
        "userInfo", "networkInterfaces", "hostname", "homedir",
    )
    _METADATA_OS_RECON_FUNCS = (
        "platform", "arch", "release", "cpus", "tmpdir", "endianness",
    )
    _OS_RECON_FUNCS = _SENSITIVE_OS_RECON_FUNCS
    _CP_FUNC_NAMES = (
        "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork",
    )

    def _extract_call_args_slice(self, code: str, open_idx: int, max_len: int = 400) -> str:
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

    def _has_suspicious_manifest_hook(
        self, manifest: Optional[Dict[str, Any]], pkg_dir: Optional[str] = None
    ) -> bool:
        """
        Returns True if the manifest declares a non-whitelisted lifecycle install/uninstall hook
        or an extended hook resolving to suspicious commands or inline `node -e/-p`.
        Respects both `_is_whitelisted_command` (e.g. `husky install`) and benign local node
        banner scripts (`_is_benign_local_node_script`, never applied to `preinstall`).
        """
        if not isinstance(manifest, dict):
            return False
        scripts = manifest.get("scripts", {})
        if not isinstance(scripts, dict):
            return False
        install_hooks = {
            "preinstall", "install", "postinstall",
            "preuninstall", "uninstall", "postuninstall",
        }
        for hook in EXTENDED_SANDBOX_HOOKS:
            if hook not in scripts:
                continue
            raw_cmd = str(scripts[hook]).strip()
            if not raw_cmd:
                continue
            if self._is_whitelisted_command(raw_cmd, scripts=scripts, pkg_dir=pkg_dir):
                continue
            if pkg_dir and self._is_benign_local_node_script(hook, raw_cmd, pkg_dir):
                continue
            resolved = self._resolve_script_chain(raw_cmd, scripts)
            cmds_to_check = [s for _, s in resolved] if resolved else [raw_cmd]
            if resolved and raw_cmd not in cmds_to_check:
                cmds_to_check.append(raw_cmd)
            for idx_c, sub_cmd in enumerate(cmds_to_check):
                sub_s = sub_cmd.strip()
                if not sub_s:
                    continue
                if self._is_whitelisted_command(sub_s, scripts=scripts, pkg_dir=pkg_dir):
                    continue
                if pkg_dir and self._is_benign_local_node_script(hook, sub_s, pkg_dir):
                    continue
                is_bridge_parent = bool(resolved and idx_c == len(cmds_to_check) - 1)
                if hook in install_hooks and not is_bridge_parent:
                    return True
                deobf = self._deobfuscate_shell_cmd(sub_s)
                if re.search(r"\bnode\s+(?:-[^\s]*\s+)*(?:-e|--eval|-p|--print)\b", deobf, re.IGNORECASE):
                    return True
                if any(
                    re.search(p, sub_s, re.IGNORECASE) or re.search(p, deobf, re.IGNORECASE)
                    for p, _ in SUSPICIOUS_SCRIPT_PATTERNS
                ):
                    return True
        return False

    def _extract_js_assignments(self, code: str) -> List[Tuple[str, str]]:
        """
        ASI-aware statement extractor for JS variable assignments (`lhs = rhs`) that
        stops at `;` or statement-ending newlines when delimiters are balanced, preventing
        semicolon-free lines from being swallowed into a single regex match.
        """
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

    def _parse_js_module_bindings(
        self, norm_code: str, mod_names: Tuple[str, ...]
    ) -> Tuple[Set[str], List[Tuple[str, str]]]:
        """
        Extracts module namespace aliases (`const cp = require('child_process')` /
        `import cp from 'child_process'`) and destructured/named bindings
        (`(original_export, local_identifier)`) for both CJS and ESM.
        """
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

    def _analyze_decode_eval_flows(
        self, norm_code: str, has_net_sink: bool, has_suspicious_hook: bool
    ) -> Tuple[bool, bool]:
        """
        Detects Rule 2.2 decoded-payload-to-eval flows via proximity (<= 800 chars) OR
        1-2 hop variable taint linking, and gates `vm.runIn*` / `new vm.Script` execution
        behind decode pairing, network sinks, or suspicious lifecycle hooks.
        """
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
            decode_parts.append(
                r"\b(?:unzip|gunzip|inflate|inflateRaw|brotliDecompress)(?:Sync)?\s*\("
            )
        decode_re = re.compile("|".join(decode_parts), re.IGNORECASE)

        eval_parts = [
            r"(?<!\.)\beval\s*\(",
            r"(?:globalThis|global)(?:\s*\[\s*['\"`]eval['\"`]\s*\]|\s*\.\s*eval)\s*\(",
            r"\bnew\s+Function\s*\(",
            r"(?<!\.)\bFunction\s*\(",
            r"\(\s*0\s*,\s*eval\s*\)\s*\(",
            r"\bReflect\.construct\s*\(\s*Function\b",
            r"(?:\bModule\._compile|[\w$\)\]]\s*\._compile)\s*\(",
            r"\.\s*constructor\s*\(",
        ]
        # Catch direct aliases of `eval` (`const fn = eval` / `global.eval`) and `Function` (`const F = Function`)
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
            vm_parts.append(
                r"\b(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+Script\s*\("
            )
        vm_sink_re = re.compile("|".join(vm_parts))

        decode_matches = list(decode_re.finditer(code))
        eval_matches = list(eval_sink_re.finditer(code))
        vm_matches = list(vm_sink_re.finditer(code))

        has_linked_decode_eval = False
        vm_has_decode = False

        # 1. Proximity check (<= 800 chars)
        for dm in decode_matches:
            for em in eval_matches:
                if min(abs(em.start() - dm.end()), abs(dm.start() - em.end())) <= 800:
                    has_linked_decode_eval = True
                    break
            for vm in vm_matches:
                if min(abs(vm.start() - dm.end()), abs(dm.start() - vm.end())) <= 800:
                    vm_has_decode = True
                    break

        # 2. Variable taint tracking (1-2 hops, ASI-safe) when proximity did not already match
        if decode_matches and (
            (eval_matches and not has_linked_decode_eval)
            or (vm_matches and not vm_has_decode)
        ):
            assigns = self._extract_js_assignments(code)
            tainted_vars: Set[str] = set()
            for lhs, rhs in assigns:
                if decode_re.search(rhs):
                    tainted_vars.add(lhs)
            for _ in range(2):
                if not tainted_vars:
                    break
                taint_ref_re = re.compile(
                    r"\b(?:" + "|".join(re.escape(v) for v in sorted(tainted_vars)) + r")\b"
                )
                for lhs, rhs in assigns:
                    if taint_ref_re.search(rhs):
                        tainted_vars.add(lhs)

            if tainted_vars:
                taint_ref_re = re.compile(
                    r"\b(?:" + "|".join(re.escape(v) for v in sorted(tainted_vars)) + r")\b"
                )
                for em in eval_matches:
                    open_pos = em.end() - 1 if code[em.end() - 1] == "(" else em.end()
                    args_slice = self._extract_call_args_slice(code, open_pos)
                    if taint_ref_re.search(args_slice):
                        has_linked_decode_eval = True
                        break
                for vm in vm_matches:
                    open_pos = vm.end() - 1 if code[vm.end() - 1] == "(" else vm.end()
                    args_slice = self._extract_call_args_slice(code, open_pos)
                    if taint_ref_re.search(args_slice):
                        vm_has_decode = True
                        break

        has_risky_vm_eval = bool(
            vm_matches and (vm_has_decode or has_net_sink or has_suspicious_hook)
        )
        return has_linked_decode_eval, has_risky_vm_eval

    def _analyze_recon_and_net_sinks(self, norm_code: str) -> Dict[str, Any]:
        """
        Extracts host/credential recon signals (including ES6 destructuring/aliases of `os`/`dns`,
        sensitive `process.env` access/serialization, and credential file reads) alongside outbound
        network sinks (built-in modules, `fetch`/`WebSocket`, and third-party HTTP clients).
        """
        os_funcs: Set[str] = set()
        high_risk_recon = False
        os_func_alt = "|".join(self._OS_RECON_FUNCS)

        # Direct, inline-require, & aliased `os` calls
        os_aliases, os_destr = self._parse_js_module_bindings(norm_code, ("os",))
        os_target_parts = ["os"] + sorted(re.escape(t) for t in os_aliases) + [
            r"require\s*\(\s*['\"`](?:node:)?os['\"`]\s*\)"
        ]
        os_call_re = re.compile(
            rf"(?:\b(?:{'|'.join(os_target_parts[:-1])})|{os_target_parts[-1]})\s*\.\s*({os_func_alt})\s*\("
        )
        for m in os_call_re.finditer(norm_code):
            fn = m.group(1)
            os_funcs.add(fn)
            if fn in ("userInfo", "networkInterfaces"):
                high_risk_recon = True

        for orig, local in os_destr:
            if orig in self._OS_RECON_FUNCS and re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
                os_funcs.add(orig)
                if orig in ("userInfo", "networkInterfaces"):
                    high_risk_recon = True

        # Direct, inline-require, aliased & destructured `dns` recon and lookup/resolve sinks
        has_net_sink = False
        dns_aliases, dns_destr = self._parse_js_module_bindings(norm_code, ("dns",))
        dns_ident_parts = ["dns"] + sorted(re.escape(t) for t in dns_aliases)
        dns_target_re_part = rf"(?:\b(?:{'|'.join(dns_ident_parts)})|require\s*\(\s*['\"`](?:node:)?dns['\"`]\s*\))"
        if re.search(rf"{dns_target_re_part}\s*\.\s*getServers\s*\(", norm_code):
            os_funcs.add("getServers")
            high_risk_recon = True
        if re.search(rf"{dns_target_re_part}\s*\.\s*(?:lookup|resolve\w*)\s*\(", norm_code):
            has_net_sink = True

        for orig, local in dns_destr:
            if orig == "getServers" and re.search(rf"\b{re.escape(local)}\s*\(", norm_code):
                os_funcs.add("getServers")
                high_risk_recon = True
            elif (orig == "lookup" or orig.startswith("resolve")) and re.search(
                rf"\b{re.escape(local)}\s*\(", norm_code
            ):
                has_net_sink = True

        # Sensitive `process.env` access / full-env serialization (excluding child_process `{ env: { ...process.env } }` options)
        env_aliases = ["process\\.env"]
        for em in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\.env\b", norm_code):
            env_aliases.append(re.escape(em.group(1)))
        env_alt = "|".join(env_aliases)
        if re.search(
            rf"(?:{env_alt})(?:\s*\.\s*|\s*\[\s*['\"`])(?:{self._SENSITIVE_ENV_KEY_NAMES})\b|"
            rf"\{{[^}}]*\b(?:{self._SENSITIVE_ENV_KEY_NAMES})\b[^}}]*\}}\s*=\s*(?:{env_alt})\b|"
            rf"\bJSON\.stringify\s*\(\s*(?:{env_alt})\s*[,)]|"
            rf"\b(?:headers|body|data|json|payload|params|query)\s*:\s*(?:{env_alt})\b|"
            rf"\bObject\.(?:keys|entries|values)\s*\(\s*(?:{env_alt})\s*\)|"
            rf"\bObject\.assign\s*\([^;\n]{{0,100}}?,\s*(?:{env_alt})\b",
            norm_code,
        ):
            high_risk_recon = True
        else:
            for sp_m in re.finditer(rf"\.\.\.\s*(?:{env_alt})\b", norm_code):
                prefix = norm_code[max(0, sp_m.start() - 120):sp_m.start()]
                in_env_option = bool(re.search(r"\benv\s*:\s*\{[^}]*$", prefix))
                in_exfil_wrap = bool(
                    re.search(r"(?:JSON\.stringify\s*\(|\b(?:headers|body|data|json|payload)\s*:)[^;\n]{0,100}$", prefix)
                )
                if not in_env_option or in_exfil_wrap:
                    high_risk_recon = True
                    break

        # Sensitive host/credential file read
        if (
            SENSITIVE_SOURCE_PATH_REGEX.search(norm_code)
            or self._classify_sensitive_host_path(norm_code)[0] > 0
            or re.search(
                r"\b(?:readFile|readFileSync|createReadStream|openSync|readdirSync|readdir)\s*\("
                r"[^;\n]{0,180}?(?:\.npmrc|\.ssh|id_rsa|id_ed25519|\.aws|/etc/passwd|/etc/shadow|\.docker/config\.json|\.kube/config)",
                norm_code,
            )
        ):
            high_risk_recon = True

        # Built-in / global / inline-require network sinks
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
            http_aliases, http_destr = self._parse_js_module_bindings(norm_code, ("http", "https", "http2"))
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
            sock_aliases, sock_destr = self._parse_js_module_bindings(norm_code, ("net", "tls", "dgram"))
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
            client_aliases, client_destr = self._parse_js_module_bindings(
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
            "has_net_sink": has_net_sink,
        }

    _SAFE_NON_SHELL_TOOLS = (
        "git", "tsc", "esbuild", "cmake", "make", "pkg-config",
        "npm", "npx", "yarn", "pnpm",
    )

    def _inspect_child_process_calls(self, norm_code: str) -> Tuple[bool, bool, bool, bool]:
        """
        Inspects `child_process` invocations (including `execFile`/`execFileSync`, destructured
        imports, and `process.binding('spawn_sync')` / `_linkedBinding('spawn_sync')`) and
        evaluates `DANGEROUS_SHELL_ARG_REGEX` strictly within `[-300 .. +300]` windows around calls.
        Also returns `only_safe_tool_spawn` when every invocation uses a non-shell spawn/execFile
        call targeting a safe standard CLI tool without `shell: true`.
        """
        has_spawn_sync_binding = bool(
            re.search(
                r"\bprocess\.(?:binding|_linkedBinding)\s*\(\s*['\"`]spawn_sync['\"`]\s*\)",
                norm_code,
            )
        )
        cp_aliases, cp_destr = self._parse_js_module_bindings(norm_code, ("child_process",))
        has_cp_import = bool(
            cp_aliases
            or cp_destr
            or re.search(
                r"require\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)|from\s+['\"`](?:node:)?child_process['\"`]",
                norm_code,
            )
        )

        destr_map: Dict[str, str] = {
            local: orig for orig, local in cp_destr if orig in self._CP_FUNC_NAMES
        }
        cp_call_patterns = [r"\b(?:" + "|".join(self._CP_FUNC_NAMES) + r")\s*\("]
        for orig, local in cp_destr:
            if orig in self._CP_FUNC_NAMES and local not in self._CP_FUNC_NAMES:
                cp_call_patterns.append(rf"\b{re.escape(local)}\s*\(")
        cp_call_re = re.compile("|".join(cp_call_patterns))
        cp_calls = list(cp_call_re.finditer(norm_code)) if has_cp_import else []

        in_dangerous_window = False
        safe_tool_re = re.compile(
            r"^\(\s*(['\"`])(?:" + "|".join(re.escape(t) for t in self._SAFE_NON_SHELL_TOOLS) + r")\1"
        )
        only_safe_tool_spawn = bool(cp_calls)
        for m in cp_calls:
            win_start = max(0, m.start() - 300)
            win_end = min(len(norm_code), m.end() + 300)
            if DANGEROUS_SHELL_ARG_REGEX.search(norm_code[win_start:win_end]):
                in_dangerous_window = True
                only_safe_tool_spawn = False
                break
            callee = m.group(0).rstrip("( \t\r\n")
            orig_fn = destr_map.get(callee, callee)
            call_args = self._extract_call_args_slice(norm_code, m.end() - 1, 320)
            if (
                orig_fn not in ("spawn", "spawnSync", "execFile", "execFileSync")
                or not safe_tool_re.match(call_args)
                or re.search(r"\bshell\s*:\s*(?:true|['\"`]\s*[^'\"`\s][^'\"`]*['\"`])", call_args)
            ):
                only_safe_tool_spawn = False

        return has_spawn_sync_binding, bool(cp_calls), in_dangerous_window, only_safe_tool_spawn

    def _analyze_source_code_detailed(
        self,
        pkg_dir: str,
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
    ) -> Tuple[int, List[Dict[str, Any]], Dict[str, Tuple[int, str, str, str]]]:
        """
        Layer 2: Context-Aware Static Source Code Analysis (detailed variant).
        Scans JavaScript files (and budgeted pre-bundled node_modules code/scripts when present)
        for obfuscation, multi-line encoded evaluation, malicious exfiltration endpoints,
        credential/recon-to-network flows, heavy obfuscation, Tier 1/2 host paths, and cloaking.
        Returns `(total_l2_score, findings, triggered_rules)` for Cross-Layer Gating.
        """
        findings = []
        triggered_rules: Dict[str, Tuple[int, str, str, str]] = {}
        entrypoints = self._extract_declared_entrypoints(pkg_dir, manifest or {})

        def record_l2(rule_key: str, points: int, rule_name: str, severity: str, detail: str):
            if rule_key not in triggered_rules or points > triggered_rules[rule_key][0]:
                triggered_rules[rule_key] = (points, rule_name, severity, detail)

        js_files = []
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
                if not is_js_ext and not self._is_scannable_text_file(full_p):
                    continue
                # Skip unit test files unless explicitly referenced as a declared entrypoint
                if not is_declared_ep:
                    if rel_f.startswith(("test/", "tests/", "__tests__/", "spec/")):
                        continue
                    if re.search(r"\.(test|spec)\.(js|cjs|mjs)$", rel_f, re.IGNORECASE):
                        continue
                if full_p not in seen_js_paths:
                    seen_js_paths.add(full_p)
                    js_files.append(full_p)

        nm_info = self._inspect_bundled_node_modules(pkg_dir, manifest=manifest, is_tarball=is_tarball)
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

        # Scan budgeted shell/Python scripts bundled inside node_modules/
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
            sdeobf = self._deobfuscate_shell_cmd(scontent)
            nm_exfil = self._find_suspicious_exfil_endpoints(scontent)
            if nm_exfil:
                record_l2(
                    "malicious_exfil_endpoint",
                    50,
                    "Suspicious Exfiltration Endpoint",
                    "CRITICAL",
                    f"Hardcoded external exfiltration/OAST endpoint '{nm_exfil}' in bundled {srel}"
                )
            if spath.lower().endswith(".py"):
                if (py_net_re.search(scontent) and py_exec_re.search(scontent)) or SENSITIVE_SOURCE_PATH_REGEX.search(scontent):
                    record_l2(
                        "nm_bundled_script_exec",
                        45,
                        "Obfuscation / Dynamic Exec Pattern",
                        "CRITICAL",
                        f"Suspicious bundled Python execution/exfiltration payload in {srel}"
                    )
            else:
                for pat, desc in SUSPICIOUS_SCRIPT_PATTERNS:
                    if re.search(pat, scontent, re.IGNORECASE) or re.search(pat, sdeobf, re.IGNORECASE):
                        record_l2(
                            "nm_bundled_script_exec",
                            45,
                            "Obfuscation / Dynamic Exec Pattern",
                            "CRITICAL",
                            f"{desc} in bundled {srel}"
                        )
                        break

        has_suspicious_hook = self._has_suspicious_manifest_hook(manifest, pkg_dir=pkg_dir)
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
        pending_tier2_paths: List[Tuple[str, str]] = []
        pending_entropy_alerts: List[Tuple[float, str]] = []
        self._last_l2_obf_corroborated = False

        for file_path in js_files:
            rel_path = os.path.relpath(file_path, pkg_dir)
            try:
                # Read full file up to 1 MB; for larger files read head 512 KB + tail 512 KB
                # to prevent leading whitespace/comment padding from hiding trailing payloads.
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

            if not content:
                continue

            is_minified = self._is_likely_minified_or_dist(rel_path, content)
            if not is_minified:
                non_minified_count += 1
            no_comments = self._strip_js_comments_safely(content)
            norm_code = self._normalize_js_for_static_scan(no_comments)

            # 1. Critical inline dynamic evaluation patterns on de-concatenated/de-escaped code (+45 CRITICAL)
            has_crit_exec = False
            for pattern, desc in SOURCE_CRITICAL_EXEC_PATTERNS:
                if re.search(pattern, norm_code, re.IGNORECASE):
                    has_crit_exec = True
                    record_l2(
                        "inline_encoded_eval",
                        45,
                        "Obfuscation / Dynamic Exec Pattern",
                        "CRITICAL",
                        f"{desc} detected in {rel_path}"
                    )

            # 3. Known Malicious Exfiltration / OAST / Webhook / Cloud IMDS / Public IP Endpoints (+50 CRITICAL)
            exfil_hit = self._find_suspicious_exfil_endpoints(norm_code)
            if exfil_hit:
                record_l2(
                    "malicious_exfil_endpoint",
                    50,
                    "Suspicious Exfiltration Endpoint",
                    "CRITICAL",
                    f"Hardcoded external exfiltration/OAST/IMDS endpoint '{exfil_hit}' in {rel_path}"
                )

            # 4. Recon (OS/DNS destructuring/aliases, sensitive process.env, credential paths) + Net Sinks (+45 CRITICAL)
            recon_info = self._analyze_recon_and_net_sinks(norm_code)
            file_high_risk_recon = recon_info["high_risk_recon"]
            file_os_funcs = recon_info["os_funcs"]
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
                    f"File {rel_path} combines host/credential fingerprinting with outbound network/DNS calls"
                )

            # 2. Proximity (<=800 chars) or taint-linked Decode -> Eval / Conditional VM (+45 CRITICAL)
            has_linked_decode_eval, has_risky_vm_eval = self._analyze_decode_eval_flows(
                norm_code, file_has_net_sink, has_suspicious_hook
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
                    detail_msg
                )

            # 5. Context-aware child_process inspection (windowed dangerous shell args + spawn_sync bindings)
            has_spawn_sync_binding, has_cp_calls, in_dangerous_window, only_safe_tool_spawn = (
                self._inspect_child_process_calls(norm_code)
            )
            if has_spawn_sync_binding:
                record_l2(
                    "child_process_high",
                    45,
                    "Obfuscation / Dynamic Exec Pattern",
                    "CRITICAL",
                    f"Low-level process.binding/linkedBinding('spawn_sync') evasion in {rel_path}"
                )
            elif has_cp_calls:
                if in_dangerous_window or has_linked_decode_eval or has_crit_exec:
                    record_l2(
                        "child_process_high",
                        45,
                        "Obfuscation / Dynamic Exec Pattern",
                        "CRITICAL",
                        f"High-risk OS child_process execution with shell/encoded payload in {rel_path}"
                    )
                elif not is_minified and len(js_files) <= 3 and (not only_safe_tool_spawn or has_suspicious_hook):
                    # Standalone small package directly invoking child_process (skip safe non-shell CLI tools without risky hooks)
                    record_l2(
                        "child_process_low",
                        20,
                        "Direct Child Process Invocation",
                        "MEDIUM",
                        f"Direct child_process invocation in small package file {rel_path}"
                    )

            is_unsafe_cp = bool(has_spawn_sync_binding or (has_cp_calls and not only_safe_tool_spawn))
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

            # 6. Heavy Obfuscation Signatures (Rule 2.6: +40 HIGH)
            obf_desc = self._detect_heavy_obfuscation(content, no_comments, norm_code=norm_code)
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

            # 7. Sensitive Host Path / Marker Targeting (Rule 2.7: Tier 1 +40 HIGH, Tier 2 Context-Gated)
            path_tier, path_desc = self._classify_sensitive_host_path(norm_code)
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
                    or has_suspicious_hook
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
                    pending_tier2_paths.append((rel_path, path_desc))
                    if "sensitive_host_path" not in triggered_rules:
                        record_l2(
                            "sensitive_host_path_cfg",
                            15,
                            "Config File Reference",
                            "MEDIUM",
                            f"Standalone credential/config file reference in {rel_path}: {path_desc}",
                        )

            # 8. Semantically Verified Encoded Payload Artifact (Rule 2.8: +40 HIGH, on norm_code)
            has_explicit_decode_call = bool(
                re.search(r"\b(?:Buffer\.from|atob)\s*\(|\.reverse\s*\(", norm_code)
            )
            has_b64_url_risk_ctx = bool(
                has_explicit_decode_call
                and (
                    file_has_net_sink
                    or has_crit_exec
                    or has_linked_decode_eval
                    or has_risky_vm_eval
                    or is_unsafe_cp
                    or obf_desc
                    or has_suspicious_hook
                )
            )
            b64_flagged, b64_detail = self._inspect_encoded_strings(
                norm_code, has_url_risk_context=has_b64_url_risk_ctx
            )
            if b64_flagged and b64_detail:
                cross_has_exec_or_obf = True
                record_l2(
                    "verified_b64_artifact",
                    40,
                    "Long Encoded String Artifact",
                    "HIGH",
                    f"{b64_detail} in {rel_path}",
                )

            # 9. Whitespace Padding Cloaking & Windowed Entropy (Rule 2.9: Anti-FP Gated)
            if re.search(r"[ \t]{200,}|\t{50,}", content):
                record_l2(
                    "whitespace_cloaking",
                    20,
                    "Whitespace Padding Cloaking",
                    "MEDIUM",
                    f"Suspicious horizontal whitespace padding (>=200 spaces/tabs or >=50 tabs) in {rel_path}",
                )

            win_entropy = self._calculate_windowed_entropy(content)
            if len(content) > 200 and ((not is_minified and win_entropy > 5.65) or win_entropy > 6.15):
                pending_entropy_alerts.append((win_entropy, rel_path))

        # Cross-file recon -> exfil correlation for small non-minified packages (<= 5 non-minified files)
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

        # Tier 2 cross-file correlation / deduplication
        if "sensitive_host_path" in triggered_rules:
            triggered_rules.pop("sensitive_host_path_cfg", None)
        elif pending_tier2_paths:
            small_pkg_net = (
                0 < non_minified_count <= 5
                and len(js_files) <= 15
                and cross_has_net_sink
            )
            if (
                cross_has_exec_or_obf
                or small_pkg_net
                or has_suspicious_hook
                or "static_recon_exfil_flow" in triggered_rules
            ):
                t2_rel, t2_desc = pending_tier2_paths[0]
                triggered_rules.pop("sensitive_host_path_cfg", None)
                record_l2(
                    "sensitive_host_path",
                    40,
                    "Sensitive Host Path Targeting",
                    "HIGH",
                    f"Credential/tool config path targeted alongside cross-file network/exec/obfuscation in {t2_rel}: {t2_desc}",
                )

        # Anti-FP Gating for Rule 2.9: record high entropy only when supporting exec/structural indicator exists
        has_entropy_support = bool(
            has_suspicious_hook
            or has_any_cp_call
            or any(k != "sensitive_host_path_cfg" for k in triggered_rules)
        )
        if pending_entropy_alerts and has_entropy_support:
            max_ent, max_rel = max(pending_entropy_alerts, key=lambda x: x[0])
            record_l2(
                "high_entropy_source",
                15,
                "High Entropy Code Section",
                "MEDIUM",
                f"Windowed entropy of {max_rel} reaches {max_ent:.2f} (packed/obfuscated indicator)",
            )

        self._last_l2_obf_corroborated = bool(
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

        return total_l2_score, findings, triggered_rules

    def analyze_source_code(
        self,
        pkg_dir: str,
        manifest: Optional[Dict[str, Any]] = None,
        is_tarball: bool = False,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 2 public entry point: returns `(total_l2_score, findings)`.
        """
        total_l2_score, findings, _ = self._analyze_source_code_detailed(
            pkg_dir, manifest=manifest, is_tarball=is_tarball
        )
        return total_l2_score, findings

    def _collect_sandbox_targets(
        self, pkg_dir: str, manifest: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Identifies active lifecycle hooks and entrypoint JS files to execute inside the Layer 3 sandbox.
        """
        active_hooks: Dict[str, str] = {}
        target_files: List[str] = []
        declared_entrypoints = self._extract_declared_entrypoints(pkg_dir, manifest)

        def add_file_if_valid(rel_or_abs: str, from_hook: bool = False):
            clean_rel = rel_or_abs.strip().strip("'\"")
            if not clean_rel:
                return
            full_p = os.path.normpath(os.path.join(pkg_dir, clean_rel))
            rel_norm: Optional[str] = None
            if os.path.isfile(full_p):
                rel_norm = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
            elif from_hook:
                rel_norm = self._resolve_pkg_script_candidate(pkg_dir, clean_rel)
                if rel_norm:
                    full_p = os.path.normpath(os.path.join(pkg_dir, rel_norm))
            if not rel_norm or not os.path.isfile(full_p):
                return
            # Avoid running unit test suites of benign packages unless declared as entrypoint/hook target
            if not from_hook and rel_norm not in declared_entrypoints:
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
                    if not cmd:
                        continue
                    bridged_bad = False
                    for sub_name, sub_cmd in self._resolve_script_chain(cmd, scripts):
                        deobf_sub = self._deobfuscate_shell_cmd(sub_cmd)
                        if re.search(r"\bnode\s+(?:-[^\s]*\s+)*(?:-e|--eval|-p|--print)\b", deobf_sub, re.IGNORECASE) or any(
                            re.search(p, sub_cmd, re.IGNORECASE) or re.search(p, deobf_sub, re.IGNORECASE)
                            for p, _ in SUSPICIOUS_SCRIPT_PATTERNS
                        ):
                            bridged_bad = True
                            active_hooks[f"{hook}->{sub_name}"] = sub_cmd
                            for tgt in self._extract_node_targets_from_cmd(sub_cmd) + self._extract_node_targets_from_cmd(deobf_sub):
                                add_file_if_valid(tgt, from_hook=True)
                    if not bridged_bad and self._is_whitelisted_command(cmd, scripts=scripts, pkg_dir=pkg_dir):
                        continue
                    active_hooks[hook] = cmd
                    deobf_cmd = self._deobfuscate_shell_cmd(cmd)
                    # Extract any Node preload (-r/--require/--import) or script (including extensionless) in the hook
                    for tgt in self._extract_node_targets_from_cmd(cmd) + self._extract_node_targets_from_cmd(deobf_cmd):
                        add_file_if_valid(tgt, from_hook=True)

        # Include declared entrypoints from main, bin, exports, and hooks
        for ep in sorted(declared_entrypoints):
            add_file_if_valid(ep)

        # Always check default root entrypoints
        add_file_if_valid("index.js")
        add_file_if_valid("index.mjs")
        add_file_if_valid("index.cjs")

        # If still no target files found, inspect up to 3 root/non-test JS files
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

        nm_info = self._inspect_bundled_node_modules(pkg_dir, manifest=manifest, is_tarball=is_tarball)
        if nm_info.get("needs_l2_scan"):
            added_nm = 0
            for full_p in nm_info.get("budget_code_files", []):
                if full_p.lower().endswith((".js", ".cjs", ".mjs")):
                    rel_nm = os.path.relpath(full_p, pkg_dir).replace("\\", "/")
                    add_file_if_valid(rel_nm)
                    added_nm += 1
                    if added_nm >= 3:
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

    def analyze_behavioral_sandbox(
        self, pkg_dir: str, manifest: Dict[str, Any], is_tarball: bool = False
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Layer 3: Dynamic / Behavioral Sandbox Analysis.
        Executes lifecycle hooks and package entrypoints inside an instrumented Node.js sandbox
        (scripts/sandbox_runner.js) to intercept runtime network egress, DNS exfiltration,
        child process spawning, sensitive filesystem tampering, credential harvesting, and dynamic eval.
        """
        score = 0
        findings = []

        active_hooks, target_files = self._collect_sandbox_targets(pkg_dir, manifest, is_tarball=is_tarball)
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

        # 3b. Runtime Dropper Payload Creation: FS_INTERNAL_WRITE paired with dynamic eval or child_process (+35 CRITICAL)
        internal_write_events = by_cat.get("FS_INTERNAL_WRITE", [])
        eval_events = by_cat.get("RUNTIME_DYNAMIC_EVAL", [])
        if internal_write_events and (eval_events or proc_events):
            score += 35
            sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in internal_write_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Dropper Payload Creation",
                "severity": "CRITICAL",
                "detail": f"Intercepted internal file write dropped alongside dynamic eval or process spawn ({sample_details})"
            })

        # 4. Runtime Dynamic Code Evaluation (+40 HIGH)
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

        # 5b. Runtime Environment Enumeration (+15 MEDIUM standalone; participates in Kill-Chain)
        env_enum_events = by_cat.get("ENV_ENUMERATION", [])
        if env_enum_events:
            score += 15
            sample_details = "; ".join([f"{e['api']}: {e['detail']}" for e in env_enum_events[:2]])
            findings.append({
                "layer": "Layer 3 - Behavioral Sandbox",
                "rule": "Runtime Environment Enumeration",
                "severity": "MEDIUM",
                "detail": f"Package enumerated environment keys in sandbox ({sample_details})"
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
        has_recon = bool(os_events or env_events or env_enum_events or by_cat.get("FS_SENSITIVE_READ"))
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
        is_tarball_input = os.path.isfile(pkg_dir) and pkg_dir.lower().endswith((".tgz", ".tar.gz", ".tar"))

        # Allow passing a .tgz / .tar.gz / .tar tarball directly to scan_package
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
                        if (
                            norm_m.startswith("/")
                            or bool(re.match(r"^[A-Za-z]:", norm_m))
                            or ".." in parts
                        ):
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
                    "findings": []
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
                            "detail": f"Structural exploit detected in '{tb_name}': {'; '.join(struct_anomalies[:3])}"
                        }
                        verdict = "MALICIOUS" if 50 >= self.risk_threshold else "BENIGN"
                        return {
                            "package_name": tb_name,
                            "version": "unknown",
                            "package_path": os.path.abspath(pkg_dir),
                            "verdict": verdict,
                            "risk_score": 50,
                            "threshold": self.risk_threshold,
                            "layer_scores": {
                                "layer_1_manifest": 50,
                                "layer_1_dependency_graph": 0,
                                "layer_1_integrity": 50,
                                "layer_2_source": 0,
                                "layer_3_behavioral": 0
                            },
                            "dependency_graph": {
                                "root_package": tb_name,
                                "direct_dependencies_count": 0,
                                "transitive_dependencies_count": 0,
                                "total_nodes": 1,
                                "estimated_depth": 0,
                                "has_lockfile": False,
                                "anomalies_detected": 0,
                                "edges": []
                            },
                            "integrity_check": {
                                "status": "FAIL",
                                "tarball": tarball_path,
                                "expected_hash": expected_sha512,
                                "actual_hash": None,
                                "matched": False,
                                "structural_anomalies": struct_anomalies
                            },
                            "findings_count": 1,
                            "findings": [finding]
                        }
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
            l1_manifest_score, l1_findings = self.analyze_manifest(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
            all_findings.extend(l1_findings)

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

            l1_total_score = l1_manifest_score + l1_graph_score + l1_integrity_score
            total_score += l1_total_score

            # Layer 2: Always analyze static source code, then apply Cross-Layer Gating when Layer 1
            # has no hard evidence so Trojan require() payloads still fail loudly while clean
            # libraries don't accumulate low/medium heuristics into FPs.
            nm_info = self._inspect_bundled_node_modules(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
            has_hard_l1_evidence = (
                l1_manifest_score >= 40
                or l1_integrity_score > 0
                or l1_graph_score >= 20
                or bool(nm_info.get("needs_l2_scan"))
            )
            raw_l2_score, raw_l2_findings, triggered_l2_rules = self._analyze_source_code_detailed(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
            if self.always_scan_l2 or has_hard_l1_evidence:
                l2_score, l2_findings = raw_l2_score, raw_l2_findings
            else:
                HIGH_CONFIDENCE_STANDALONE_L2_RULES = {
                    "inline_encoded_eval",
                    "malicious_exfil_endpoint",
                    "static_recon_exfil_flow",
                    "child_process_high",
                    "verified_b64_artifact",
                    "nm_bundled_script_exec",
                }
                has_obf_and_sensitive = (
                    "heavy_js_obfuscation" in triggered_l2_rules
                    and "sensitive_host_path" in triggered_l2_rules
                )
                has_corroborated_obf = (
                    "heavy_js_obfuscation" in triggered_l2_rules
                    and bool(getattr(self, "_last_l2_obf_corroborated", False))
                )
                keep_rules = set(HIGH_CONFIDENCE_STANDALONE_L2_RULES)
                if has_corroborated_obf or has_obf_and_sensitive:
                    keep_rules.add("heavy_js_obfuscation")
                if has_obf_and_sensitive:
                    keep_rules.add("sensitive_host_path")
                if "whitespace_cloaking" in triggered_l2_rules and "heavy_js_obfuscation" in triggered_l2_rules:
                    keep_rules.add("whitespace_cloaking")
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

            # Layer 3: Dynamic Behavioral Sandbox Analysis
            l3_score, l3_findings = self.analyze_behavioral_sandbox(
                actual_pkg_dir, manifest_data, is_tarball=is_tarball_input
            )
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
    parser.add_argument("--always-scan-l2", action="store_true", help="Always run Layer 2 static analysis even without hard Layer 1 evidence")
    parser.add_argument("--tarball", type=str, default=None, help="Optional path to .tgz artifact for SHA-512 integrity check")
    parser.add_argument("--expected-hash", type=str, default=None, help="Expected sha512-... integrity string for artifact verification")
    parser.add_argument("--output", type=str, default=None, help="Save telemetry output to JSON file")
    args = parser.parse_args()

    detector = SupplyChainDetector(
        enable_whitelist=(not args.no_whitelist),
        risk_threshold=args.threshold,
        always_scan_l2=args.always_scan_l2
    )

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
