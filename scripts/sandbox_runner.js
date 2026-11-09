#!/usr/bin/env node
/**
 * scripts/sandbox_runner.js
 * Layer 3: Dynamic Behavioral Sandbox Harness for npm Packages
 * Course: NT230 - Topic D04: Supply Chain Compromise
 *
 * Executes package lifecycle hooks and module entrypoints inside an instrumented,
 * isolated Node.js runtime environment:
 * - Hooks Module._load to intercept and stub child_process, http, https, dns, net, tls, dgram, fs, os.
 * - Wraps process.env in an ES6 Proxy with honeypot credentials to detect secret harvesting.
 * - Hooks global.eval, Function, setTimeout, setInterval, Atomics.wait to defeat obfuscation & delay evasion.
 * - Blocks all actual outbound network traffic, shell execution, and external disk writes.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const Module = require('module');

// Save genuine references before hooking
const realStdoutWrite = process.stdout.write.bind(process.stdout);
const realExit = process.exit.bind(process);
const realFsReadFileSync = fs.readFileSync.bind(fs);
const realFsExistsSync = fs.existsSync.bind(fs);
const realFsRealpathSync = fs.realpathSync.bind(fs);
const realFsReaddirSync = fs.readdirSync.bind(fs);
const originalModuleLoad = Module._load;
const originalEval = global.eval;

const pkgDir = process.argv[2] ? path.resolve(process.argv[2]) : process.cwd();
let realPkgDir = pkgDir;
try {
    realPkgDir = realFsRealpathSync(pkgDir);
} catch (e) {
    realPkgDir = pkgDir;
}

const configRaw = process.argv[3] || '{}';
let sandboxConfig = {};
try {
    sandboxConfig = JSON.parse(configRaw);
} catch (e) {
    sandboxConfig = {};
}

const events = [];
const eventDedupe = new Set();

function recordEvent(category, api, detail, severity = 'HIGH') {
    const key = `${category}|${api}|${detail}`;
    if (eventDedupe.has(key)) return;
    eventDedupe.add(key);
    events.push({
        category,
        api,
        detail: String(detail || '').slice(0, 300),
        severity
    });
}

// ============================================================================
// 1. SHELL LIFECYCLE COMMAND BEHAVIORAL EMULATOR
// ============================================================================
function emulateLifecycleScript(hookName, commandStr) {
    if (!commandStr || typeof commandStr !== 'string') return;
    const cmd = commandStr.trim();

    // Network egress via shell utilities
    if (/\b(curl|wget|fetch|Invoke-WebRequest|Invoke-RestMethod|certutil)\b/i.test(cmd) || /\/dev\/(tcp|udp)\//i.test(cmd)) {
        recordEvent(
            'NETWORK_EGRESS',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' invokes network egress utility: ${cmd}`,
            'CRITICAL'
        );
    }

    // DNS / ICMP exfiltration in shell
    if (/\b(nslookup|dig|host|ping)\b/i.test(cmd) && /(\$\(|`|\b[a-z0-9.-]+\.(com|net|org|io|sh|cn|ru|xyz|top|site|me|info|biz|cc|tk|ml|ga|cf|gq|oastify|burpcollaborator|interactsh)\b)/i.test(cmd)) {
        recordEvent(
            'DNS_EXFILTRATION',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' performs DNS/ICMP exfiltration: ${cmd}`,
            'CRITICAL'
        );
    }

    // Reverse shell / raw socket tools
    if (/\b(nc|netcat|ncat|socat|telnet)\b/i.test(cmd)) {
        recordEvent(
            'RAW_SOCKET_CONNECT',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' invokes raw socket utility: ${cmd}`,
            'CRITICAL'
        );
    }

    // Piping into shell interpreter or spawning explicit subshell
    if (/\|\s*(sh|bash|zsh|dash|ksh|cmd|powershell|python|python3|perl|php|ruby)\b/i.test(cmd) ||
        /\b(sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?)\s+(-c|\/c|-Command|-EncodedCommand|-enc)\b/i.test(cmd)) {
        recordEvent(
            'CHILD_PROCESS_SPAWN',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' spawns subshell interpreter: ${cmd}`,
            'CRITICAL'
        );
    }

    // Shell-level Base64 decode execution
    if (/\bbase64\s+(-d|--decode|-D)\b/i.test(cmd)) {
        recordEvent(
            'RUNTIME_DYNAMIC_EVAL',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' decodes Base64 payload in shell: ${cmd}`,
            'HIGH'
        );
    }

    // Sensitive file access or writing to external temp/system directories in shell
    if (/(\/etc\/(passwd|shadow|hosts|crontab|sudoers)|\.npmrc|\.ssh\/|\.aws\/|\.kube\/|\.gitconfig|\.bash_history)/i.test(cmd)) {
        recordEvent(
            'FS_SENSITIVE_READ',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' accesses sensitive host file: ${cmd}`,
            'CRITICAL'
        );
    }
    if (/(>|>>|\btee\b)\s*['"]?(\/tmp\/|\/var\/tmp\/|C:\\Users\\Public\\|~\/|\/etc\/)/i.test(cmd)) {
        recordEvent(
            'FS_EXTERNAL_WRITE',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' writes marker/payload to external OS path: ${cmd}`,
            'CRITICAL'
        );
    }

    // Host recon via shell subcommands $(whoami), $(hostname), $(uname), $(env)
    if (/\$\(\s*(whoami|hostname|uname|id|env|printenv|ifconfig|ip\s+addr|pwd)\b/i.test(cmd) ||
        /`\s*(whoami|hostname|uname|id|env|printenv|pwd)\b/i.test(cmd)) {
        recordEvent(
            'OS_FINGERPRINTING',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' harvests OS identity via subshell: ${cmd}`,
            'HIGH'
        );
    }

    // Delay / sleep evasion
    if (/\b(sleep\s+\d+|timeout\s+\/t\s+\d+|ping\s+-[nc]\s+\d+\s+127\.0\.0\.1)\b/i.test(cmd)) {
        recordEvent(
            'SANDBOX_EVASION',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' uses delay/sleep to evade sandbox analysis: ${cmd}`,
            'HIGH'
        );
    }

    // Stealth output redirection
    if (/>\s*\/dev\/null\s*2>&1|&>\s*\/dev\/null|\b(curl|wget)\b.*?\s(-s|--silent|-q|--quiet)\b/i.test(cmd)) {
        recordEvent(
            'STEALTH_EXECUTION',
            `shell:${hookName}`,
            `Lifecycle hook '${hookName}' suppresses stdout/stderr traces: ${cmd}`,
            'MEDIUM'
        );
    }
}

// ============================================================================
// 2. RUNTIME ENVIRONMENT HONEYPOT & HARDENING
// ============================================================================

// Suppress target console output so stdout remains clean for JSON telemetry
const noop = () => {};
console.log = noop;
console.info = noop;
console.warn = noop;
console.error = noop;
console.debug = noop;
process.stdout.write = () => true;
process.stderr.write = () => true;

// Block process termination from target code
process.exit = function(code) {
    recordEvent('PROCESS_CONTROL', 'process.exit', `Target code called process.exit(${code})`, 'LOW');
    throw new Error('__SANDBOX_EXIT_INTERCEPTED__');
};
process.kill = function(pid, sig) {
    recordEvent('SANDBOX_EVASION', 'process.kill', `Target code attempted process.kill(${pid}, ${sig})`, 'HIGH');
};
process.dlopen = function() {
    recordEvent('SANDBOX_EVASION', 'process.dlopen', 'Target attempted to load native binary addon', 'HIGH');
};
process.binding = function(name) {
    recordEvent('SANDBOX_EVASION', 'process.binding', `Target attempted direct C++ binding access: ${name}`, 'HIGH');
    return {};
};
process._linkedBinding = function(name) {
    recordEvent('SANDBOX_EVASION', 'process._linkedBinding', `Target attempted linked C++ binding access: ${name}`, 'HIGH');
    return {};
};

// Environment Variable Proxy Honeypot
const HONEYPOT_ENV = {
    NODE_ENV: 'production',
    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    HOME: '/home/sandbox',
    USER: 'sandbox-user',
    USERNAME: 'sandbox-user',
    HOSTNAME: 'sandbox-node',
    NPM_TOKEN: 'npm_honeypot_secret_token_d04',
    NODE_AUTH_TOKEN: 'npm_honeypot_auth_token_d04',
    AWS_ACCESS_KEY_ID: 'AKIAHONEYPOTD04LAB',
    AWS_SECRET_ACCESS_KEY: 'honeypot_aws_secret_key_d04',
    GITHUB_TOKEN: 'ghp_honeypotGitHubTokenD04Lab',
    DATABASE_URL: 'postgres://admin:honeypot@db.internal:5432/prod'
};

const SENSITIVE_ENV_REGEX = /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|AWS_|GITHUB_|NPM_TOKEN|NODE_AUTH|COOKIE|WEBHOOK|KUBECONFIG|SSH_)/i;
const BENIGN_ENV_KEYS = new Set([
    'NODE_ENV', 'NODE_DEBUG', 'NODE_OPTIONS', 'NODE_PATH', 'DEBUG', 'DEBUG_COLORS',
    'FORCE_COLOR', 'NO_COLOR', 'COLORTERM', 'TERM', 'CI', 'PATH', 'LANG', 'LC_ALL',
    'TZ', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR'
]);

process.env = new Proxy(HONEYPOT_ENV, {
    get(target, prop) {
        if (typeof prop === 'string') {
            if (!BENIGN_ENV_KEYS.has(prop) && SENSITIVE_ENV_REGEX.test(prop)) {
                recordEvent(
                    'ENV_HARVESTING',
                    `process.env.${prop}`,
                    `Accessed sensitive credential environment variable '${prop}'`,
                    'HIGH'
                );
            }
            return prop in target ? target[prop] : '';
        }
        return target[prop];
    },
    ownKeys(target) {
        recordEvent(
            'ENV_HARVESTING',
            'Object.keys(process.env)',
            'Enumerated/serialized full process.env environment dictionary',
            'HIGH'
        );
        return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, prop) {
        return {
            enumerable: true,
            configurable: true,
            value: target[prop] || ''
        };
    }
});

// Time-bomb / Delay Evasion Interception
let timerCallbacksRun = 0;
global.setTimeout = function(fn, delay, ...args) {
    const ms = Number(delay) || 0;
    if (ms >= 1000) {
        recordEvent(
            'SANDBOX_EVASION',
            'setTimeout',
            `Deliberate execution delay (${ms}ms) detected and fast-forwarded in sandbox`,
            'HIGH'
        );
    }
    if (typeof fn === 'function' && timerCallbacksRun < 6) {
        timerCallbacksRun++;
        try { fn(...args); } catch (e) {}
    }
    return { ref: noop, unref: noop, hasRef: () => false, refresh: noop };
};

global.setInterval = function(fn, delay, ...args) {
    const ms = Number(delay) || 0;
    if (ms >= 1000) {
        recordEvent(
            'SANDBOX_EVASION',
            'setInterval',
            `Periodic execution delay (${ms}ms) detected in sandbox`,
            'HIGH'
        );
    }
    if (typeof fn === 'function' && timerCallbacksRun < 3) {
        timerCallbacksRun++;
        try { fn(...args); } catch (e) {}
    }
    return { ref: noop, unref: noop };
};

if (typeof Atomics !== 'undefined' && typeof Atomics.wait === 'function') {
    Atomics.wait = function(typedArray, index, value, timeout) {
        recordEvent(
            'SANDBOX_EVASION',
            'Atomics.wait',
            `Low-level thread sleep evasion intercepted (timeout=${timeout}ms)`,
            'HIGH'
        );
        return 'ok';
    };
}

// Dynamic Code Evaluation Interception (eval)
global.eval = function(code) {
    if (typeof code === 'string') {
        const preview = code.replace(/\s+/g, ' ').trim().slice(0, 160);
        recordEvent(
            'RUNTIME_DYNAMIC_EVAL',
            'eval()',
            `Runtime dynamic code evaluation decoded: ${preview}`,
            'HIGH'
        );
    }
    return originalEval.call(global, code);
};

// Hook global fetch (Node 18/20+)
global.fetch = function(url, options) {
    const method = (options && options.method) || 'GET';
    recordEvent(
        'NETWORK_EGRESS',
        'fetch()',
        `Outbound HTTP ${method} request via fetch() to: ${String(url)}`,
        'CRITICAL'
    );
    return Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Map(),
        text: async () => '',
        json: async () => ({}),
        arrayBuffer: async () => new ArrayBuffer(0)
    });
};

// ============================================================================
// 3. NODE.JS CORE MODULE INTERCEPTION (Module._load)
// ============================================================================

function createDummyStream() {
    const stream = {
        on: function(ev, cb) {
            if (ev === 'end' || ev === 'close' || ev === 'finish') {
                try { cb(); } catch (e) {}
            }
            return stream;
        },
        once: function(ev, cb) {
            if (ev === 'end' || ev === 'close' || ev === 'finish') {
                try { cb(); } catch (e) {}
            }
            return stream;
        },
        emit: noop,
        write: function(chunk) {
            if (chunk) {
                const str = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
                if (str.length > 0) {
                    recordEvent(
                        'NETWORK_EGRESS',
                        'http.ClientRequest.write',
                        `Exfiltrating payload body (${str.length} bytes): ${str.replace(/\s+/g, ' ').slice(0, 120)}`,
                        'CRITICAL'
                    );
                }
            }
            return true;
        },
        end: function(chunk, cb) {
            if (typeof chunk === 'function') {
                try { chunk(); } catch (e) {}
            } else if (chunk) {
                stream.write(chunk);
                if (typeof cb === 'function') {
                    try { cb(); } catch (e) {}
                }
            }
            return stream;
        },
        destroy: noop,
        abort: noop,
        setTimeout: function(ms, cb) { return stream; },
        setNoDelay: noop,
        setSocketKeepAlive: noop,
        setHeader: noop,
        getHeader: () => '',
        pipe: (dest) => dest,
        unref: noop,
        ref: noop,
        statusCode: 200,
        headers: {}
    };
    return stream;
}

function formatNetTarget(urlOrOpts) {
    if (typeof urlOrOpts === 'string') return urlOrOpts;
    if (urlOrOpts && typeof urlOrOpts === 'object') {
        const proto = urlOrOpts.protocol || 'http:';
        const host = urlOrOpts.hostname || urlOrOpts.host || 'unknown-host';
        const port = urlOrOpts.port ? `:${urlOrOpts.port}` : '';
        const p = urlOrOpts.path || urlOrOpts.pathname || '/';
        const method = urlOrOpts.method || 'GET';
        return `${method} ${proto}//${host}${port}${p}`;
    }
    return String(urlOrOpts);
}

function createMockHttpModule(protoName) {
    function handleRequest(methodName, urlOrOpts, optsOrCb, maybeCb) {
        const targetDesc = formatNetTarget(urlOrOpts);
        recordEvent(
            'NETWORK_EGRESS',
            `${protoName}.${methodName}`,
            `Outbound network request: ${targetDesc}`,
            'CRITICAL'
        );
        const req = createDummyStream();
        const cb = typeof optsOrCb === 'function' ? optsOrCb : (typeof maybeCb === 'function' ? maybeCb : null);
        if (cb) {
            const res = createDummyStream();
            try { cb(res); } catch (e) {}
        }
        return req;
    }
    return {
        request: (...args) => handleRequest('request', ...args),
        get: (...args) => handleRequest('get', ...args),
        Agent: function() {},
        globalAgent: {},
        createServer: () => ({ listen: noop, on: noop, close: noop }),
        METHODS: ['GET', 'POST', 'PUT', 'DELETE'],
        STATUS_CODES: { 200: 'OK' }
    };
}

const mockChildProcess = {
    exec: function(cmd, opts, cb) {
        recordEvent('CHILD_PROCESS_SPAWN', 'child_process.exec', `Executed shell command: ${cmd}`, 'CRITICAL');
        const callback = typeof opts === 'function' ? opts : (typeof cb === 'function' ? cb : null);
        if (callback) {
            try { callback(null, 'sandbox-output\n', ''); } catch (e) {}
        }
        const proc = createDummyStream();
        proc.stdout = createDummyStream();
        proc.stderr = createDummyStream();
        proc.stdin = createDummyStream();
        proc.pid = 9999;
        return proc;
    },
    execSync: function(cmd) {
        recordEvent('CHILD_PROCESS_SPAWN', 'child_process.execSync', `Executed synchronous shell command: ${cmd}`, 'CRITICAL');
        return Buffer.from('sandbox-output\n');
    },
    spawn: function(cmd, args) {
        const full = Array.isArray(args) ? `${cmd} ${args.join(' ')}` : String(cmd);
        recordEvent('CHILD_PROCESS_SPAWN', 'child_process.spawn', `Spawned process: ${full}`, 'CRITICAL');
        const proc = createDummyStream();
        proc.stdout = createDummyStream();
        proc.stderr = createDummyStream();
        proc.stdin = createDummyStream();
        proc.pid = 9999;
        return proc;
    },
    spawnSync: function(cmd, args) {
        const full = Array.isArray(args) ? `${cmd} ${args.join(' ')}` : String(cmd);
        recordEvent('CHILD_PROCESS_SPAWN', 'child_process.spawnSync', `Spawned synchronous process: ${full}`, 'CRITICAL');
        return { pid: 9999, output: [null, Buffer.from(''), Buffer.from('')], stdout: Buffer.from(''), stderr: Buffer.from(''), status: 0 };
    },
    execFile: function(file, args, opts, cb) {
        const full = Array.isArray(args) ? `${file} ${args.join(' ')}` : String(file);
        recordEvent('CHILD_PROCESS_SPAWN', 'child_process.execFile', `Executed binary file: ${full}`, 'CRITICAL');
        const callback = [args, opts, cb].find(x => typeof x === 'function');
        if (callback) {
            try { callback(null, 'sandbox-output\n', ''); } catch (e) {}
        }
        return createDummyStream();
    },
    execFileSync: function(file, args) {
        const full = Array.isArray(args) ? `${file} ${args.join(' ')}` : String(file);
        recordEvent('CHILD_PROCESS_SPAWN', 'child_process.execFileSync', `Executed synchronous binary file: ${full}`, 'CRITICAL');
        return Buffer.from('sandbox-output\n');
    },
    fork: function(modulePath) {
        recordEvent('CHILD_PROCESS_SPAWN', 'child_process.fork', `Forked Node.js child process: ${modulePath}`, 'CRITICAL');
        const proc = createDummyStream();
        proc.send = noop;
        proc.pid = 9999;
        return proc;
    }
};

const mockDns = {
    lookup: function(hostname, opts, cb) {
        const domain = String(hostname || '');
        if (domain && domain !== 'localhost' && domain !== '127.0.0.1') {
            recordEvent('DNS_EXFILTRATION', 'dns.lookup', `DNS resolution / potential DNS exfiltration: ${domain}`, 'CRITICAL');
        }
        const callback = typeof opts === 'function' ? opts : (typeof cb === 'function' ? cb : null);
        if (callback) {
            try { callback(null, '127.0.0.1', 4); } catch (e) {}
        }
    },
    resolve: function(hostname, rrtype, cb) {
        const domain = String(hostname || '');
        recordEvent('DNS_EXFILTRATION', 'dns.resolve', `DNS record query for: ${domain}`, 'CRITICAL');
        const callback = typeof rrtype === 'function' ? rrtype : (typeof cb === 'function' ? cb : null);
        if (callback) {
            try { callback(null, ['127.0.0.1']); } catch (e) {}
        }
    },
    resolve4: function(hostname, cb) {
        recordEvent('DNS_EXFILTRATION', 'dns.resolve4', `DNS A-record query for: ${hostname}`, 'CRITICAL');
        if (typeof cb === 'function') { try { cb(null, ['127.0.0.1']); } catch (e) {} }
    },
    resolveTxt: function(hostname, cb) {
        recordEvent('DNS_EXFILTRATION', 'dns.resolveTxt', `DNS TXT-record query for: ${hostname}`, 'CRITICAL');
        if (typeof cb === 'function') { try { cb(null, [['sandbox']]); } catch (e) {} }
    },
    getServers: function() {
        recordEvent('OS_FINGERPRINTING', 'dns.getServers', 'Queried local DNS resolver servers', 'MEDIUM');
        return ['8.8.8.8'];
    },
    promises: {
        lookup: async (hostname) => {
            recordEvent('DNS_EXFILTRATION', 'dns.promises.lookup', `Async DNS lookup for: ${hostname}`, 'CRITICAL');
            return { address: '127.0.0.1', family: 4 };
        },
        resolve: async (hostname) => {
            recordEvent('DNS_EXFILTRATION', 'dns.promises.resolve', `Async DNS resolve for: ${hostname}`, 'CRITICAL');
            return ['127.0.0.1'];
        }
    }
};

const mockNet = {
    connect: function(...args) {
        const target = typeof args[0] === 'object' ? `${args[0].host || 'localhost'}:${args[0].port || ''}` : `${args[1] || 'localhost'}:${args[0] || ''}`;
        recordEvent('RAW_SOCKET_CONNECT', 'net.connect', `Raw TCP socket connection to: ${target}`, 'CRITICAL');
        return createDummyStream();
    },
    createConnection: function(...args) {
        const target = typeof args[0] === 'object' ? `${args[0].host || 'localhost'}:${args[0].port || ''}` : `${args[1] || 'localhost'}:${args[0] || ''}`;
        recordEvent('RAW_SOCKET_CONNECT', 'net.createConnection', `Raw TCP connection to: ${target}`, 'CRITICAL');
        return createDummyStream();
    },
    Socket: function() {
        const sock = createDummyStream();
        sock.connect = function(port, host) {
            recordEvent('RAW_SOCKET_CONNECT', 'net.Socket.connect', `Raw Socket connect to: ${host || 'localhost'}:${port}`, 'CRITICAL');
            return sock;
        };
        return sock;
    },
    createServer: () => ({ listen: noop, on: noop, close: noop }),
    isIP: () => 0,
    isIPv4: () => false,
    isIPv6: () => false
};

const mockDgram = {
    createSocket: function() {
        const sock = createDummyStream();
        sock.send = function(msg, offset, length, port, address, cb) {
            recordEvent('RAW_SOCKET_CONNECT', 'dgram.Socket.send', `Raw UDP packet sent to ${address || port}`, 'CRITICAL');
            if (typeof cb === 'function') { try { cb(null); } catch (e) {} }
        };
        sock.bind = noop;
        sock.close = noop;
        return sock;
    }
};

// Sensitive filesystem path checker (supports symlinked benchmark directories)
const SENSITIVE_PATH_REGEX = /(\/etc\/(passwd|shadow|hosts|sudoers|crontab|ssh)|\.npmrc|\.yarnrc|\.pypirc|\.netrc|\.ssh|\.aws|\.kube|\.docker|\.gitconfig|\.bash_history|\.zsh_history|id_rsa|id_ed25519|\/proc\/self)/i;

function isInsidePkgDir(targetPath) {
    try {
        const resolved = path.resolve(pkgDir, String(targetPath));
        const normPkg = path.normalize(pkgDir).toLowerCase();
        const normRealPkg = path.normalize(realPkgDir).toLowerCase();
        const normRes = path.normalize(resolved).toLowerCase();
        if (normRes.startsWith(normPkg) || normRes.startsWith(normRealPkg)) {
            return true;
        }
        if (realFsExistsSync(resolved)) {
            const realTarget = path.normalize(realFsRealpathSync(resolved)).toLowerCase();
            if (realTarget.startsWith(normPkg) || realTarget.startsWith(normRealPkg)) {
                return true;
            }
        }
        return false;
    } catch (e) {
        return false;
    }
}

function checkFsRead(apiName, targetPath) {
    const pStr = String(targetPath || '');
    if (isInsidePkgDir(pStr)) {
        const base = path.basename(pStr);
        if (base === '.npmrc' || base === '.env') {
            recordEvent('FS_SENSITIVE_READ', apiName, `Attempted to read credential config file: ${base}`, 'HIGH');
            return false;
        }
        return true;
    }
    if (SENSITIVE_PATH_REGEX.test(pStr)) {
        recordEvent('FS_SENSITIVE_READ', apiName, `Attempted to read sensitive host file: ${pStr}`, 'CRITICAL');
        return false;
    }
    if (!pStr.includes('node_modules')) {
        recordEvent('FS_SENSITIVE_READ', apiName, `Attempted to read external host path outside package: ${pStr}`, 'HIGH');
        return false;
    }
    return true;
}

function handleFsWrite(apiName, targetPath) {
    const pStr = String(targetPath || '');
    if (!isInsidePkgDir(pStr) || SENSITIVE_PATH_REGEX.test(pStr)) {
        recordEvent(
            'FS_EXTERNAL_WRITE',
            apiName,
            `Attempted to write/modify file outside package boundary: ${pStr}`,
            'CRITICAL'
        );
    } else {
        recordEvent(
            'FS_INTERNAL_WRITE',
            apiName,
            `File write inside package directory intercepted: ${pStr}`,
            'MEDIUM'
        );
    }
}

const mockFs = new Proxy(fs, {
    get(target, prop) {
        if (prop === 'readFileSync') {
            return function(filePath, options) {
                if (!checkFsRead('fs.readFileSync', filePath)) {
                    return typeof options === 'string' || (options && options.encoding) ? 'sandbox-dummy-content\n' : Buffer.from('sandbox-dummy-content\n');
                }
                return realFsReadFileSync(filePath, options);
            };
        }
        if (prop === 'readFile') {
            return function(filePath, options, cb) {
                const callback = typeof options === 'function' ? options : cb;
                if (!checkFsRead('fs.readFile', filePath)) {
                    if (typeof callback === 'function') {
                        try { callback(null, Buffer.from('sandbox-dummy-content\n')); } catch (e) {}
                    }
                    return;
                }
                try {
                    const data = realFsReadFileSync(filePath, typeof options === 'function' ? undefined : options);
                    if (typeof callback === 'function') callback(null, data);
                } catch (err) {
                    if (typeof callback === 'function') callback(err);
                }
            };
        }
        if (prop === 'writeFileSync' || prop === 'appendFileSync') {
            return function(filePath) {
                handleFsWrite(`fs.${prop}`, filePath);
                return undefined;
            };
        }
        if (prop === 'writeFile' || prop === 'appendFile') {
            return function(filePath, data, opts, cb) {
                handleFsWrite(`fs.${prop}`, filePath);
                const callback = typeof opts === 'function' ? opts : cb;
                if (typeof callback === 'function') {
                    try { callback(null); } catch (e) {}
                }
            };
        }
        if (prop === 'unlinkSync' || prop === 'rmSync' || prop === 'rmdirSync' || prop === 'chmodSync' || prop === 'renameSync') {
            return function(filePath) {
                handleFsWrite(`fs.${prop}`, filePath);
                return undefined;
            };
        }
        if (prop === 'createWriteStream') {
            return function(filePath) {
                handleFsWrite('fs.createWriteStream', filePath);
                return createDummyStream();
            };
        }
        if (prop === 'readdirSync') {
            return function(dirPath, opts) {
                if (!checkFsRead('fs.readdirSync', dirPath)) return [];
                return realFsReaddirSync(dirPath, opts);
            };
        }
        if (prop === 'promises') {
            return {
                readFile: async (filePath, opts) => {
                    if (!checkFsRead('fs.promises.readFile', filePath)) return 'sandbox-dummy-content\n';
                    return realFsReadFileSync(filePath, opts);
                },
                writeFile: async (filePath) => {
                    handleFsWrite('fs.promises.writeFile', filePath);
                },
                appendFile: async (filePath) => {
                    handleFsWrite('fs.promises.appendFile', filePath);
                },
                unlink: async (filePath) => {
                    handleFsWrite('fs.promises.unlink', filePath);
                },
                readdir: async (dirPath) => {
                    if (!checkFsRead('fs.promises.readdir', dirPath)) return [];
                    return realFsReaddirSync(dirPath);
                }
            };
        }
        const val = target[prop];
        return typeof val === 'function' ? val.bind(target) : val;
    }
});

const realOs = require('os');
const mockOs = new Proxy(realOs, {
    get(target, prop) {
        if (prop === 'userInfo') {
            return function() {
                recordEvent('OS_FINGERPRINTING', 'os.userInfo', 'Harvested OS user account identity (username/uid/homedir)', 'HIGH');
                return { username: 'sandbox-user', uid: 1000, gid: 1000, shell: '/bin/bash', homedir: '/home/sandbox' };
            };
        }
        if (prop === 'hostname') {
            return function() {
                recordEvent('OS_FINGERPRINTING', 'os.hostname', 'Queried host machine name', 'LOW');
                return 'sandbox-host';
            };
        }
        if (prop === 'networkInterfaces') {
            return function() {
                recordEvent('OS_FINGERPRINTING', 'os.networkInterfaces', 'Enumerated host network interfaces / MAC / IP addresses', 'HIGH');
                return {};
            };
        }
        if (prop === 'homedir') {
            return function() {
                recordEvent('OS_FINGERPRINTING', 'os.homedir', 'Queried user home directory path', 'LOW');
                return '/home/sandbox';
            };
        }
        const val = target[prop];
        return typeof val === 'function' ? val.bind(target) : val;
    }
});

// Universal Recursive Proxy for missing third-party npm dependencies (e.g. axios, got, request, shelljs)
const NETWORK_THIRD_PARTY = new Set(['axios', 'node-fetch', 'cross-fetch', 'got', 'request', 'request-promise', 'superagent', 'undici', 'needle', 'phin', 'ws', 'socket.io-client']);
const EXEC_THIRD_PARTY = new Set(['shelljs', 'execa', 'cross-spawn', 'child-process-promise']);

function createUniversalMock(modName, depth = 0) {
    if (depth > 5) return noop;
    const fn = function(...args) {
        if (NETWORK_THIRD_PARTY.has(modName)) {
            recordEvent('NETWORK_EGRESS', `${modName}()`, `Third-party HTTP client request: ${String(args[0] || '')}`, 'CRITICAL');
        } else if (EXEC_THIRD_PARTY.has(modName)) {
            recordEvent('CHILD_PROCESS_SPAWN', `${modName}()`, `Third-party process execution: ${String(args[0] || '')}`, 'CRITICAL');
        }
        return createUniversalMock(modName, depth + 1);
    };
    return new Proxy(fn, {
        get(target, prop) {
            if (prop === Symbol.toPrimitive) return () => '';
            if (prop === Symbol.iterator) return function* () {};
            if (prop === 'toString' || prop === 'valueOf') return () => '';
            if (prop === '__esModule') return true;
            if (prop === 'default') return createUniversalMock(modName, depth + 1);
            if (prop === 'then') {
                return (resolve) => {
                    if (typeof resolve === 'function') {
                        try { resolve({ data: {}, body: '', status: 200, stdout: '' }); } catch (e) {}
                    }
                    return createUniversalMock(modName, depth + 1);
                };
            }
            if (prop === 'catch' || prop === 'finally') return () => createUniversalMock(modName, depth + 1);
            if (typeof prop === 'string') {
                if (NETWORK_THIRD_PARTY.has(modName) && ['get', 'post', 'put', 'delete', 'patch', 'head', 'request', 'send'].includes(prop)) {
                    return (...args) => {
                        recordEvent('NETWORK_EGRESS', `${modName}.${prop}`, `Third-party HTTP ${prop.toUpperCase()} request to: ${String(args[0] || '')}`, 'CRITICAL');
                        return createUniversalMock(modName, depth + 1);
                    };
                }
                if (EXEC_THIRD_PARTY.has(modName) && ['exec', 'sync', 'command', 'commandSync', 'spawn'].includes(prop)) {
                    return (...args) => {
                        recordEvent('CHILD_PROCESS_SPAWN', `${modName}.${prop}`, `Third-party shell execution: ${String(args[0] || '')}`, 'CRITICAL');
                        return createUniversalMock(modName, depth + 1);
                    };
                }
            }
            return createUniversalMock(modName, depth + 1);
        },
        construct() {
            return createUniversalMock(modName, depth + 1);
        }
    });
}

Module._load = function(request, parent, isMain) {
    const cleanReq = String(request || '').replace(/^node:/, '');
    if (cleanReq === 'child_process') return mockChildProcess;
    if (cleanReq === 'http') return createMockHttpModule('http');
    if (cleanReq === 'https') return createMockHttpModule('https');
    if (cleanReq === 'http2') return createMockHttpModule('http2');
    if (cleanReq === 'dns' || cleanReq === 'dns/promises') return cleanReq === 'dns/promises' ? mockDns.promises : mockDns;
    if (cleanReq === 'net' || cleanReq === 'tls') return mockNet;
    if (cleanReq === 'dgram') return mockDgram;
    if (cleanReq === 'fs') return mockFs;
    if (cleanReq === 'fs/promises') return mockFs.promises;
    if (cleanReq === 'os') return mockOs;

    if (NETWORK_THIRD_PARTY.has(cleanReq) || EXEC_THIRD_PARTY.has(cleanReq)) {
        return createUniversalMock(cleanReq);
    }

    try {
        return originalModuleLoad.apply(this, arguments);
    } catch (err) {
        if (err && err.code === 'MODULE_NOT_FOUND') {
            return createUniversalMock(cleanReq);
        }
        throw err;
    }
};

// Optional Browser DOM/BOM Honeypot Fallback (injected only if target throws ReferenceError for window/document)
function injectBrowserMocks() {
    const mockStorage = {
        getItem: (k) => {
            recordEvent('ENV_HARVESTING', `localStorage.getItem('${k}')`, `Browser storage harvesting: ${k}`, 'HIGH');
            return 'honeypot_storage_token';
        },
        setItem: noop
    };
    global.localStorage = mockStorage;
    global.sessionStorage = mockStorage;
    global.navigator = { userAgent: 'Mozilla/5.0 (Sandbox)', sendBeacon: (url) => {
        recordEvent('NETWORK_EGRESS', 'navigator.sendBeacon', `Beacon exfiltration to: ${url}`, 'CRITICAL');
        return true;
    }};
    global.document = {
        get cookie() {
            recordEvent('ENV_HARVESTING', 'document.cookie', 'Attempted to steal browser document.cookie', 'CRITICAL');
            return 'session_id=honeypot_cookie_d04';
        },
        set cookie(val) {},
        createElement: (tag) => ({
            set src(url) {
                recordEvent('NETWORK_EGRESS', `document.createElement(${tag}).src`, `DOM script/image exfiltration to: ${url}`, 'CRITICAL');
            }
        }),
        body: { appendChild: noop },
        head: { appendChild: noop },
        addEventListener: (ev, cb) => { if (typeof cb === 'function') { try { cb(); } catch (e) {} } }
    };
    global.XMLHttpRequest = function() {
        return {
            open: (method, url) => {
                recordEvent('NETWORK_EGRESS', 'XMLHttpRequest.open', `XHR ${method} request to: ${url}`, 'CRITICAL');
            },
            setRequestHeader: noop,
            send: noop
        };
    };
    global.WebSocket = function(url) {
        recordEvent('NETWORK_EGRESS', 'new WebSocket()', `WebSocket connection to: ${url}`, 'CRITICAL');
        return { send: noop, close: noop, onopen: null, onmessage: null };
    };
    global.window = global;
    global.self = global;
}

// ============================================================================
// 4. EXECUTE TARGET SCRIPTS & ENTRYPOINTS
// ============================================================================

function executeTargetCode(fn) {
    try {
        fn();
    } catch (err) {
        if (err && err.message === '__SANDBOX_EXIT_INTERCEPTED__') return;
        if (err && err.code === 'ERR_ACCESS_DENIED') {
            recordEvent('SANDBOX_EVASION', 'NodePermissionModel', `Blocked unauthorized OS operation: ${err.message}`, 'HIGH');
            return;
        }
        if (err instanceof ReferenceError && /\b(window|document|self|navigator|localStorage|sessionStorage|XMLHttpRequest|WebSocket)\b/.test(err.message)) {
            injectBrowserMocks();
            try { fn(); } catch (e2) {}
        }
    }
}

// Expose require and module paths on global so indirect eval() and inline `node -e` scripts work seamlessly
global.require = require;
global.__dirname = pkgDir;
global.__filename = path.join(pkgDir, 'index.js');

// Step A: Analyze and execute lifecycle hooks from package.json
const hooks = sandboxConfig.hooks || {};
for (const [hookName, cmdStr] of Object.entries(hooks)) {
    emulateLifecycleScript(hookName, cmdStr);

    // Extract inline `node -e "..."` or `node --eval "..."`
    const inlineMatch = cmdStr.match(/\bnode\s+(?:-e|--eval)\s+(['"])([\s\S]+)\1/);
    if (inlineMatch && inlineMatch[2]) {
        const inlineCode = inlineMatch[2].replace(/\\"/g, '"');
        executeTargetCode(() => {
            originalEval.call(global, inlineCode);
        });
    }
}

// Step B: Execute target JS entrypoints inside the package (install hooks & module top-level load)
const targetFiles = Array.isArray(sandboxConfig.files) ? sandboxConfig.files : [];
for (const relOrAbsFile of targetFiles) {
    const fullPath = path.resolve(pkgDir, relOrAbsFile);
    if (!realFsExistsSync(fullPath)) continue;

    executeTargetCode(() => {
        require(fullPath);
    });
}

// Output structured JSON report to stdout
realStdoutWrite(JSON.stringify({
    package_dir: pkgDir,
    events_count: events.length,
    events: events
}) + '\n');

realExit(0);
