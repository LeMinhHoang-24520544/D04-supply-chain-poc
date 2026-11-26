"""
scripts/detector_core/constants.py
Centralized detection constants, tool specifications, and compiled patterns.
"""

import ipaddress
import re

SUSPICIOUS_LIFECYCLE_HOOKS = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
]

AUTHOR_PUBLISH_HOOKS = [
    "prepare",
    "prepack",
    "postpack",
    "prepublish",
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
    "prepublish",
]

# Legacy whitelist regexes kept for backward compatibility
WHITELISTED_HOOK_COMMANDS = [
    r"^(?:npx\s+)?node-gyp(?:\s+(?:rebuild|clean|configure|build|install))+(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+|\s+[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?(?:@mapbox/)?node-pre-gyp\s+install(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+|\s+[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?prebuild-install(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+|\s+[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?node-gyp-build(?:\s+[A-Za-z0-9_./:-]+)*$",
    r"^(?:npx\s+)?napi-build(?:\s+--?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./:-]+|\s+[A-Za-z0-9_./:-]+)?)*$",
    r"^(?:npx\s+)?esbuild(?:\s+[A-Za-z0-9_./*=-]+)*$",
    r"^(?:npx\s+)?tsc(?:\s+(?:-[pwbv]|--[A-Za-z0-9_-]+|[A-Za-z0-9_./-]+))*$",
    r"^(?:npx\s+)?husky(?:\s+install)?$",
    r"^(?:npx\s+)?patch-package(?:\s+--?[A-Za-z0-9_-]+)*$",
    r"^(?:npx\s+)?opencollective(?:-postinstall)?(?:\s+[A-Za-z0-9_./:-]+)*$",
    r"^(?:npx\s+)?is-ci$",
    r"^(?:exit(?:\s+0)?|true)$",
    r"^echo(?:\s+[^|;&><\\$`\r\n]*)?$",
]

# Global dangerous flags (for tools where `-r` means `--require` etc.)
DANGEROUS_WHITELIST_FLAGS_RE = re.compile(
    r"(?:https?|ftp)://|"
    r"(?:^|\s)(?:--python(?:=|\s|$)|--require(?:=|\s|$)|-r\b|--import(?:=|\s|$)|"
    r"--eval(?:=|\s|$)|-e\b|--print(?:=|\s|$)|--(?:experimental-)?loader(?:=|\s|$)|"
    r"--gyp-path(?:=|\s|$)|--node_gyp(?:=|\s|$)|"
    r"--download\b|--mirror\b|--dist-?url\b|--tarball\b|--hosted_tarball\b|"
    r"--prebuild\b|--custom-binary\b|--runtime_url\b|--inject:)",
    re.IGNORECASE,
)

# Per-tool build specifications for structural token-based hook validation.
# Notice `-r` is NOT blocked on prebuild-install (where `-r napi` == `--runtime napi`).
BUILD_TOOL_SPECS = {
    "node-gyp": {
        "native": True,
        "subcommands": {"rebuild", "clean", "configure", "build", "install"},
        "require_subcommand": False,
        "dangerous_flags": {
            "--python", "--gyp-path", "--node_gyp", "--dist-url", "--disturl",
            "--tarball", "--eval", "-e", "--require", "-r", "--import", "--loader",
        },
    },
    "node-pre-gyp": {
        "native": True,
        "subcommands": {"install", "reinstall", "build", "clean", "configure", "rebuild", "package"},
        "require_subcommand": True,
        "dangerous_flags": {
            "--tarball", "--hosted_tarball", "--dist-url", "--disturl", "--mirror",
            "--python", "--eval", "-e", "--require", "-r",
        },
    },
    "@mapbox/node-pre-gyp": {
        "native": True,
        "subcommands": {"install", "reinstall", "build", "clean", "configure", "rebuild", "package"},
        "require_subcommand": True,
        "dangerous_flags": {
            "--tarball", "--hosted_tarball", "--dist-url", "--disturl", "--mirror",
            "--python", "--eval", "-e", "--require", "-r",
        },
    },
    "prebuild-install": {
        "native": True,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {
            "--download", "--mirror", "--dist-url", "--disturl", "--tarball",
            "--hosted_tarball", "--prebuild", "--custom-binary", "--runtime_url",
            "--eval", "-e", "--require", "--import",
        },
    },
    "node-gyp-build": {
        "native": True,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {
            "--prebuild", "--download", "--mirror", "--tarball",
            "--eval", "-e", "--require",
        },
    },
    "node-gyp-build-optional-packages": {
        "native": True,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {
            "--prebuild", "--download", "--mirror", "--tarball",
            "--eval", "-e", "--require",
        },
    },
    "napi-build": {
        "native": True,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {"--download", "--mirror", "--tarball", "--eval", "-e", "--require"},
    },
    "cmake-js": {
        "native": True,
        "subcommands": {"compile", "build", "reconfigure", "clean", "configure", "install", "print-configure"},
        "require_subcommand": False,
        "dangerous_flags": {"--download", "--tarball", "--eval", "-e", "--require"},
    },
    "esbuild": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {"--eval", "-e", "--require", "-r"},
        "dangerous_prefixes": ("--inject:",),
    },
    "tsc": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {"--eval", "-e", "--require", "-r"},
    },
    "husky": {
        "native": False,
        "subcommands": {"install"},
        "require_subcommand": False,
        "dangerous_flags": {"--eval", "-e", "--require", "-r"},
    },
    "patch-package": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {"--eval", "-e", "--require", "-r"},
    },
    "opencollective": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {"--eval", "-e", "--require", "-r"},
    },
    "opencollective-postinstall": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": {"--eval", "-e", "--require", "-r"},
    },
    "is-ci": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": set(),
        "max_args": 0,
    },
    "true": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": set(),
        "max_args": 0,
    },
    "exit": {
        "native": False,
        "subcommands": {"0"},
        "require_subcommand": False,
        "dangerous_flags": set(),
        "max_args": 1,
    },
    "echo": {
        "native": False,
        "subcommands": None,
        "require_subcommand": False,
        "dangerous_flags": set(),
    },
}

SCRIPT_BRIDGE_CALL_RE = re.compile(
    r"\b(?:npm\s+(?:(?:--silent|-s|--quiet|-q|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run(?:-script)?|"
    r"yarn\s+(?:(?:--silent|-s|--cwd(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run|"
    r"pnpm\s+(?:(?:--silent|-s|--dir(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run)\s+"
    r"(?:(?:--silent|-s|--quiet|-q|--if-present|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*['\"]?([A-Za-z0-9_:.-]+)['\"]?",
    re.IGNORECASE,
)

SINGLE_SCRIPT_BRIDGE_SEGMENT_RE = re.compile(
    r"^(?:npm\s+(?:(?:--silent|-s|--quiet|-q|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run(?:-script)?|"
    r"yarn\s+(?:(?:--silent|-s|--cwd(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run|"
    r"pnpm\s+(?:(?:--silent|-s|--dir(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*run)\s+"
    r"(?:(?:--silent|-s|--quiet|-q|--if-present|--prefix(?:\s+[^\s;&|]+|=[^\s;&|]+))\s+)*['\"]?([A-Za-z0-9_:.-]+)['\"]?$",
    re.IGNORECASE,
)

NATIVE_BUILD_CMD_RE = re.compile(
    r"^(?:npx\s+)?(?:node-gyp|@mapbox/node-pre-gyp|node-pre-gyp|prebuild-install|node-gyp-build|napi-build|cmake-js)\b",
    re.IGNORECASE,
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
    "openai", "langchain",
}

TRUSTED_OFFICIAL_SCOPES = {
    "@types/", "@babel/", "@angular/", "@vue/", "@nestjs/",
    "@testing-library/", "@aws-sdk/", "@rollup/", "@vitejs/",
    "@eslint/", "@typescript-eslint/",
}

SHADOWED_CORE_BINARIES = {
    "node", "npm", "npx", "yarn", "pnpm", "git", "sh", "bash", "zsh",
    "python", "python3", "curl", "wget", "ssh", "sudo", "cmd", "powershell",
    "tsc", "esbuild",
}

COMMON_ENGLISH_PACKAGE_WORDS = {
    "core", "sync", "lite", "site", "blob", "ping",
    "pass", "char", "chat", "lens", "mass", "loss",
}

TELEMETRY_PREFIX = "__D04_TELEMETRY__"

TRUSTED_DEPENDENCY_HOSTS = {
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.org",
    "yarnpkg.com",
}

# Concrete high-risk command patterns inside lifecycle scripts / referenced aux scripts
SUSPICIOUS_SCRIPT_PATTERNS = [
    (
        r"(?:(?<![A-Za-z0-9_./\\-])(?:curl|wget|netcat|ncat|socat|bitsadmin|certutil|mshta)(?![A-Za-z0-9_./\\-])(?:\s+|$)|"
        r"(?:^|[;&|]\s*)fetch\s+(?:-[A-Za-z0-9-]+\s+)*https?://|"
        r"(?:^|[;&|]\s*)nc\s+(?:-[A-Za-z0-9]+\s+)*(?:[A-Za-z0-9.-]+\s+\d{1,5}\b|-[lec]\b))",
        "Remote network egress / LOLBin tool invoked in script",
    ),
    (
        r"(?<!\|)\|\s*(?!\|)(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|python\d?(?:\.\d+)?|perl|ruby|php|node|iex)\b",
        "Piping output directly into shell/language interpreter",
    ),
    (
        r"\b(bash|sh|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\s+(?:-c|/c)\b",
        "External shell interpreter spawned",
    ),
    (
        r"\bnode\s+(?:-[^\s]*\s+)*(?:-e|--eval|-p|--print)\b",
        "Inline Node.js code evaluation (-e/--eval/-p/--print)",
    ),
    (
        r"\b(?:python\d?(?:\.\d+)?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)\b",
        "Inline scripting interpreter execution (python/perl/ruby/php)",
    ),
    (
        r"\b(?:powershell|pwsh)(?:\.exe)?\b.*?\b(?:-e|-enc|-encodedcommand|iex|invoke-webrequest|invoke-restmethod|iwr|irm|downloadstring|downloadfile)\b",
        "Suspicious PowerShell inline/encoded/web execution",
    ),
    (
        r"/dev/(?:tcp|udp)/|\bmkfifo\b|\bnc(?:at)?\s+.*?-e\b",
        "Reverse shell / raw socket / FIFO device execution",
    ),
    (
        r"\b(?:base64\s+(?:-d|--decode|-D)|openssl\s+(?:enc|base64)\b.*?-d|xxd\s+-r)\b",
        "Shell-level payload decoding (base64/openssl/xxd)",
    ),
    (
        r"eval\s*\(\s*Buffer\.from\s*\(",
        "Inline dynamic Node.js Base64 execution",
    ),
    (
        r"(?:>\s*)?(?:/tmp/|/var/tmp/|/dev/shm/|C:(?:\\+|/)Users(?:\\+|/)Public(?:\\+|/)|~/\.ssh|~/\.bashrc|~/\.profile|/etc/passwd|/etc/shadow|\.npmrc\b)",
        "Accessing or writing to sensitive/public OS paths in script",
    ),
    (
        r"\b(?:sleep\s+\d+|timeout\s+/t)\b",
        "Suspicious sleep/delay evasion technique",
    ),
    (
        r"\b(?:bun\s+(?:-e|--eval)\b|deno\s+eval\b|deno\s+run\b[^\n]*--allow-(?:all|run|net)\b[^\n]*https?://|qjs\s+-e\b)",
        "Alternative JS runtime inline/remote execution (bun/deno/qjs)",
    ),
]

INLINE_NODE_RISK_RE = re.compile(
    r"child_process|\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\b|"
    r"\beval\s*\(|\bFunction\s*\(|Buffer\.from|\batob\b|\bbase64\b|https?://|\bfetch\b|"
    r"\b(?:http|https|http2|net|dns|tls|dgram)\b|"
    r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|rmSync|chmod)\b|"
    r"\b(?:userInfo|networkInterfaces|hostname|getServers)\b|\bprocess\.env\b|"
    r"\.npmrc|\.ssh|/tmp/|/var/tmp/|/dev/shm/|/etc/passwd|/etc/shadow|C:(?:\\+|/)Users(?:\\+|/)Public",
    re.IGNORECASE,
)

INLINE_SCRIPT_RISK_RE = re.compile(
    r"https?://|\b(?:curl|wget|nc|netcat|ncat|socat|fetch|urllib|requests|http\.client|socket\.connect)\b|"
    r"\b(?:os\.system|os\.popen|subprocess|eval|exec|base64|b64decode|chmod\s+\+x|rm\s+-rf)\b|"
    r"\.npmrc|\.ssh|\.aws|/etc/passwd|/etc/shadow|/tmp/|/var/tmp/|/dev/shm/|/dev/(?:tcp|udp)/",
    re.IGNORECASE,
)

# High-confidence malware regex for unreferenced auxiliary scripts (must be unambiguous)
HIGH_CONF_AUX_MALWARE_RE = re.compile(
    r"(?<!\|)\|\s*(?!\|)(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|python\d?(?:\.\d+)?|perl|ruby|php|node|iex)\b|"
    r"/dev/(?:tcp|udp)/|\bmkfifo\b|\bnc(?:at)?\s+.*?-e\b|"
    r"\b(?:base64\s+(?:-d|--decode|-D)|openssl\s+(?:enc|base64)\b.*?-d|xxd\s+-r)\b[^|\n]{0,80}\|\s*(?:sh|bash|zsh|python|node)|"
    r"(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,160}(?:\.npmrc|\.ssh|/etc/passwd|/etc/shadow|\b(?:NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)\b)|"
    r"(?:\.npmrc|\.ssh|/etc/passwd|/etc/shadow)[^\n]{0,160}(?:curl|wget|nc|netcat|ncat)",
    re.IGNORECASE,
)

SOURCE_CRITICAL_EXEC_PATTERNS = [
    (r"eval\s*\(\s*Buffer\.from\s*\([^;]{0,300}?(?:base64|base64url|hex)", "Inline dynamic evaluation of encoded Buffer"),
    (r"eval\s*\(\s*atob\s*\(", "Inline dynamic evaluation of Base64 atob() string"),
    (r"eval\s*\(\s*unescape\s*\(", "Obfuscated unescape dynamic evaluation"),
    (r"(?:globalThis|global)\s*\[\s*['\"`]eval['\"`]\s*\]\s*\(", "Indirect global dynamic eval invocation"),
    (r"(?:filter|map|slice|constructor)\s*['\"`]?\s*\]?\s*\(\s*['\"`][^'\"`]*return\s+(?:process|global|require)", "Constructor chaining sandbox escape (return process/global)"),
    (r"\bReflect\.construct\s*\(\s*Function\b", "Dynamic code instantiation via Reflect.construct(Function, ...)"),
    (r"\bimport\s*\(\s*['\"`]data:(?:text|application)/javascript;base64,", "Dynamic ESM base64 data-URI module import"),
]

MALICIOUS_EXFIL_ENDPOINT_REGEX = re.compile(
    r"(?:(?<![A-Za-z0-9_.-])(?:"
    r"oastify\.com|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|"
    r"interact\.sh|interactsh\.com|webhook\.site|pipedream\.net|requestbin\.[A-Za-z0-9.-]+|"
    r"canarytokens\.com|dnslog\.cn|ceye\.io|ngrok\.io|ngrok-free\.app|"
    r"trycloudflare\.com|loca\.lt|serveo\.net|localhost\.run|beeceptor\.com|"
    r"mockbin\.org|hookbin\.com|pastebin\.com/raw|catbox\.moe|metadata\.google\.internal"
    r")(?![A-Za-z0-9_-])|"
    r"discord(?:app)?\.com/api/webhooks/\d{10,}/[A-Za-z0-9_-]+|"
    r"api\.telegram\.org/bot\d{5,}:[A-Za-z0-9_-]{10,}|"
    r"(?:https?|wss?)://(?:[A-Za-z0-9-]+\.)*(?:transfer\.sh|file\.io|rentry\.co|0x0\.st)(?=[/?#'\"`\s:]|$)|"
    r"\b169\.254\.169\.254\b(?!\.\d)|\b100\.100\.100\.200\b(?!\.\d))",
    re.IGNORECASE,
)

DANGEROUS_SHELL_ARG_REGEX = re.compile(
    r"(?:(?:^|[;&|'\"`\s])nc\s+(?:-[A-Za-z0-9]+\s+)*(?:[A-Za-z0-9.-]+\s+\d{1,5}\b|-[lec]\b)|"
    r"\b(?:curl|wget|netcat|ncat|bash\s+-c|sh\s+-c|cmd(?:\.exe)?\s+/c|powershell|pwsh|"
    r"whoami|uname|nslookup|dig|ping\s+-[nc]|base64\s+-d|chmod\s+\+x|/dev/tcp/|"
    r"/etc/passwd|/etc/shadow|\.npmrc|\.ssh)\b|"
    r"(?:&&|\|\||;|\|)\s*id(?:\s+-[A-Za-z]+)*\s*(?:['\"`]|&&|\|\||;|\||\n|$))",
    re.IGNORECASE,
)

SENSITIVE_SOURCE_PATH_REGEX = re.compile(
    r"(['\"`])[^'\"`\n]*(?:/etc/(?:passwd|shadow|sudoers|crontab)|/proc/self/environ|"
    r"~/\.ssh|/root/\.ssh|\.ssh/(?:id_rsa|id_ed25519|authorized_keys)|"
    r"\.(?:bash_history|zsh_history|git-credentials|netrc)|"
    r"\.npmrc|\.aws[/\\]+credentials|\.kube[/\\]+config|\.docker[/\\]+config\.json)\b",
    re.IGNORECASE,
)

DECODED_PAYLOAD_INDICATORS = re.compile(
    r"(?:\b(?:eval|Function)\s*\(|\bchild_process\b|\b(?:execSync|execFile|execFileSync|spawnSync)\b|"
    r"(?<!\.)\b(?:exec|spawn|fork)\s*\(|(?:child_process|\bcp)\s*\.\s*(?:exec|spawn|fork)\s*\(|"
    r"\bfetch\s*\(|\b(?:https?|http2)\.(?:request|get|post)\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|"
    r"\bprocess\.env\b|\buserInfo\b|\bBuffer\.from\s*\(|"
    r"/bin/sh\b|/bin/bash\b|cmd\.exe\b|powershell\b|\bcurl\s+|\bwget\s+|"
    r"/etc/passwd\b|/etc/shadow\b|/etc/sudoers\b|/proc/self/environ\b|"
    r"\.npmrc\b|\.ssh\b|/tmp/|C:\\\\?Users\\\\?Public)",
    re.IGNORECASE,
)

# High-precision decoded indicator set used for minified/bundled files to avoid FP on SDK workers
MINIFIED_STRICT_DECODED_INDICATORS = re.compile(
    r"(?:\bchild_process\b|\b(?:execSync|execFileSync|spawnSync)\b|"
    r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(|"
    r"/bin/sh\b|/bin/bash\b|cmd\.exe\b|powershell\b|\bcurl\s+|\bwget\s+|"
    r"/etc/passwd\b|/etc/shadow\b|\.ssh[/\\]|\.npmrc\b|C:\\\\?Users\\\\?Public)",
    re.IGNORECASE,
)

RUNTIME_CAPABLE_JS_TOKENS = re.compile(
    r"\b(require|import|eval|Function|process|global|globalThis|window|document|self|"
    r"fetch|XMLHttpRequest|WebSocket|Buffer|atob|setTimeout|setInterval|Atomics|"
    r"Reflect|Proxy|constructor)\b|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\[\s*['\"`]"
)

SUSPICIOUS_VERSION_THRESHOLD = 90.0

STATIC_NON_CODE_EXTENSIONS = (
    ".json", ".node", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".map", ".tar", ".tgz", ".gz", ".zip",
)

PUBLIC_DNS_IPS = frozenset({"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"})

DOC_AND_CGNAT_NETS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("100.64.0.0/10"),
)

SENSITIVE_ENV_KEY_NAMES = (
    "NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|"
    "AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|"
    "AZURE_CLIENT_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|"
    "CURSOR_API_KEY|HF_TOKEN|PYPI_TOKEN|VERCEL_TOKEN|CLOUDFLARE_API_TOKEN|"
    "SLACK_TOKEN|DISCORD_TOKEN|STRIPE_KEY|DATABASE_URL|CI_JOB_TOKEN|DOCKER_PASSWORD"
)

EXFIL_SENSITIVE_ENV_KEY_NAMES = (
    "NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|"
    "AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|"
    "AZURE_CLIENT_SECRET|CURSOR_API_KEY|HF_TOKEN|PYPI_TOKEN|VERCEL_TOKEN|CLOUDFLARE_API_TOKEN|"
    "SLACK_TOKEN|DISCORD_TOKEN|STRIPE_KEY|CI_JOB_TOKEN|DOCKER_PASSWORD"
)

SENSITIVE_OS_RECON_FUNCS = ("userInfo", "networkInterfaces", "hostname", "homedir")
INSTALL_IDENTITY_OS_RECON_FUNCS = ("userInfo", "networkInterfaces", "hostname")
METADATA_OS_RECON_FUNCS = ("platform", "arch", "release", "cpus", "tmpdir", "endianness")

CP_FUNC_NAMES = ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork")

SAFE_NON_SHELL_TOOLS = (
    "git", "tsc", "esbuild", "cmake", "cmake-js", "make", "ninja", "pkg-config",
    "npm", "npx", "yarn", "pnpm", "node", "node-gyp", "node-pre-gyp",
    "prebuild-install", "node-gyp-build", "cargo", "rustc",
    "python", "python3", "tar", "gzip", "unzip",
)

IGNORED_TEST_DOC_SEG_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|testing|test-utils|examples?|docs?|benchmarks?|fixtures|__mocks__|integration|e2e)(?:/|$)",
    re.IGNORECASE,
)

HARMLESS_XML_NS_RE = re.compile(
    r"https?://(?:www\.)?(?:w3\.org|schemas\.|purl\.org|apache\.org/licenses|spdx\.org)[^\s'\"<>]*",
    re.IGNORECASE,
)
