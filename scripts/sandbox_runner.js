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
const urlModule = require('url');
const Module = require('module');

// Save genuine references before hooking
const realStdoutWrite = process.stdout.write.bind(process.stdout);
const realExit = process.exit.bind(process);
const realSetImmediate = global.setImmediate.bind(global);
const realFsReadFileSync = fs.readFileSync.bind(fs);
const realFsExistsSync = fs.existsSync.bind(fs);
const realFsRealpathSync = fs.realpathSync.bind(fs);
const realFsReaddirSync = fs.readdirSync.bind(fs);
const realFsOpenSync = fs.openSync.bind(fs);
const realFsOpen = fs.open.bind(fs);
const realFsCreateReadStream = fs.createReadStream.bind(fs);
const realFsStatSync = fs.statSync.bind(fs);
const realFsLstatSync = fs.lstatSync.bind(fs);
const realFsAccessSync = fs.accessSync.bind(fs);
const realFsWriteSync = fs.writeSync.bind(fs);
const realFsWrite = fs.write.bind(fs);
const originalModuleLoad = Module._load;
const originalModuleCompile = Module.prototype._compile;
const originalEval = global.eval;
const OriginalFunction = global.Function;
const realDate = global.Date;
const realDateNow = realDate.now.bind(realDate);
const sandboxStartRealMs = realDateNow();
const realProcessUptime = process.uptime.bind(process);
const realHrtime = process.hrtime.bind(process);
const realHrtimeBigint = typeof process.hrtime.bigint === 'function'
    ? process.hrtime.bigint.bind(process.hrtime)
    : null;
let realPerfHooks = null;
try {
    realPerfHooks = require('perf_hooks');
} catch (e) {}
const realPerf = typeof global.performance !== 'undefined'
    ? global.performance
    : (realPerfHooks && realPerfHooks.performance ? realPerfHooks.performance : null);
const realPerfNow = realPerf && typeof realPerf.now === 'function' ? realPerf.now.bind(realPerf) : () => realDateNow();
let virtualTimeOffset = 0;
let isSandboxInternalCompile = false;
const TELEMETRY_PREFIX = '__D04_TELEMETRY__';
let inExportFuzzing = false;
let currentPhase = 'install';

function maskAsNative(fn, name) {
    try {
        Object.defineProperty(fn, 'toString', {
            value: () => `function ${name}() { [native code] }`,
            configurable: true
        });
    } catch (e) {}
    return fn;
}

function isDegenerateFuzzTarget(val) {
    const s = String(val === undefined || val === null ? '' : val).trim();
    if (!s || s === 'undefined' || s === 'null' || s === '[object Object]') return true;
    return /^(?:[A-Z]+\s+)?(?:https?:\/\/)?(?:unknown-host|localhost|127\.0\.0\.1|undefined|null|\[object Object\])(?::\d*)?\/?$/i.test(s);
}

const pkgDir = process.argv[2] ? path.resolve(process.argv[2]) : process.cwd();
let realPkgDir = pkgDir;
try {
    realPkgDir = realFsRealpathSync(pkgDir);
} catch (e) {
    realPkgDir = pkgDir;
}
try {
    process.chdir(pkgDir);
} catch (e) {}

const configRaw = process.argv[3] || '{}';
let sandboxConfig = {};
try {
    sandboxConfig = JSON.parse(configRaw);
} catch (e) {
    sandboxConfig = {};
}

// Mask sandbox CLI identity before target code runs
const maskedEntryPath = path.join(pkgDir, 'index.js');
try {
    Object.defineProperty(process, 'argv', {
        value: [process.execPath, maskedEntryPath],
        writable: true,
        enumerable: true,
        configurable: true
    });
} catch (e) {
    try { process.argv = [process.execPath, maskedEntryPath]; } catch (e2) {}
}
try {
    Object.defineProperty(process, 'execArgv', {
        value: [],
        writable: true,
        enumerable: true,
        configurable: true
    });
} catch (e) {
    try { process.execArgv = []; } catch (e2) {}
}

const events = [];
const eventDedupe = new Set();

function recordEvent(category, api, detail, severity = 'HIGH') {
    const phase = inExportFuzzing ? 'export_fuzz' : currentPhase;
    const key = `${category}|${api}|${detail}|${phase}`;
    if (eventDedupe.has(key)) return;
    eventDedupe.add(key);
    events.push({
        category,
        api,
        detail: String(detail || '').slice(0, 300),
        severity,
        phase
    });
}

function buildBehavioralSummary(evList) {
    const phases = { install: 0, import: 0, export_fuzz: 0 };
    const axes = {
        commands: [],
        files: { read: [], write: [], sensitive: [] },
        network: [],
        env: []
    };
    const pushUniq = (arr, item) => {
        if (arr.length < 50 && !arr.includes(item)) arr.push(item);
    };
    for (const ev of evList || []) {
        const ph = ev.phase === 'install' || ev.phase === 'import' || ev.phase === 'export_fuzz'
            ? ev.phase
            : 'import';
        phases[ph] = (phases[ph] || 0) + 1;
        const entry = `${ev.api}: ${ev.detail}`;
        if (ev.category === 'CHILD_PROCESS_SPAWN') {
            pushUniq(axes.commands, entry);
        } else if (ev.category === 'FS_SENSITIVE_READ') {
            pushUniq(axes.files.sensitive, entry);
            pushUniq(axes.files.read, entry);
        } else if (ev.category === 'FS_EXTERNAL_WRITE' || ev.category === 'FS_INTERNAL_WRITE') {
            pushUniq(axes.files.write, entry);
        } else if (
            ev.category === 'NETWORK_EGRESS' ||
            ev.category === 'DNS_EXFILTRATION' ||
            ev.category === 'RAW_SOCKET_CONNECT'
        ) {
            pushUniq(axes.network, entry);
        } else if (ev.category === 'ENV_HARVESTING' || ev.category === 'ENV_ENUMERATION') {
            pushUniq(axes.env, entry);
        }
    }
    return { phases, axes };
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
    HOME: '/home/ubuntu',
    USER: 'ubuntu',
    USERNAME: 'ubuntu',
    HOSTNAME: 'build-runner-prod-01',
    NPM_TOKEN: 'npm_4f8a9b2c1d7e6f5a3b2c1d0e9f8a7b6c5d4e',
    NODE_AUTH_TOKEN: 'npm_7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d',
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    GITHUB_TOKEN: 'ghp_7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a',
    DATABASE_URL: 'postgres://app_user:p9a8s7s6w5o4r3d2@db.internal:5432/production'
};

const SENSITIVE_ENV_REGEX = /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|AWS_|GITHUB_|NPM_TOKEN|NODE_AUTH|COOKIE|WEBHOOK|KUBECONFIG|SSH_)/i;
const BENIGN_ENV_KEYS = new Set([
    'NODE_ENV', 'NODE_DEBUG', 'NODE_OPTIONS', 'NODE_PATH', 'DEBUG', 'DEBUG_COLORS',
    'FORCE_COLOR', 'NO_COLOR', 'COLORTERM', 'TERM', 'CI', 'PATH', 'LANG', 'LC_ALL',
    'TZ', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR'
]);

let envOwnKeysSeq = null;
let envOwnKeysIdx = 0;

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
        const keys = Reflect.ownKeys(target);
        envOwnKeysSeq = keys;
        envOwnKeysIdx = 0;
        recordEvent(
            'ENV_ENUMERATION',
            'Object.keys(process.env)',
            'Enumerated/serialized full process.env environment dictionary',
            'MEDIUM'
        );
        return keys;
    },
    getOwnPropertyDescriptor(target, prop) {
        const inOwnKeysSeq = Boolean(
            envOwnKeysSeq &&
            envOwnKeysIdx < envOwnKeysSeq.length &&
            envOwnKeysSeq[envOwnKeysIdx] === prop
        );
        if (inOwnKeysSeq) {
            envOwnKeysIdx++;
            if (envOwnKeysIdx >= envOwnKeysSeq.length) {
                envOwnKeysSeq = null;
            }
        } else {
            envOwnKeysSeq = null;
        }
        if (!inOwnKeysSeq && typeof prop === 'string' && !BENIGN_ENV_KEYS.has(prop) && SENSITIVE_ENV_REGEX.test(prop)) {
            recordEvent(
                'ENV_HARVESTING',
                `process.env.${prop}`,
                `Accessed sensitive credential environment variable '${prop}'`,
                'HIGH'
            );
        }
        if (!(prop in target)) {
            return undefined;
        }
        return {
            enumerable: true,
            configurable: true,
            writable: true,
            value: target[prop] || ''
        };
    }
});

if (typeof Object.getOwnPropertyDescriptors === 'function') {
    const realGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors.bind(Object);
    Object.getOwnPropertyDescriptors = maskAsNative(function(obj) {
        if (obj === process.env) {
            recordEvent(
                'ENV_HARVESTING',
                'Object.getOwnPropertyDescriptors(process.env)',
                'Extracted property descriptors (values) of process.env via Object.getOwnPropertyDescriptors',
                'HIGH'
            );
        }
        return realGetOwnPropertyDescriptors(obj);
    }, 'getOwnPropertyDescriptors');
}

// Virtual Time Warping (Date, performance.now, process.uptime) to defeat delta-time checks
const warpedDateNow = maskAsNative(() => realDateNow() + virtualTimeOffset, 'now');
const WrappedDate = new Proxy(realDate, {
    get(target, prop) {
        if (prop === 'now') return warpedDateNow;
        return Reflect.get(target, prop, target);
    },
    construct(target, args, newTarget) {
        if (args.length === 0) {
            return Reflect.construct(target, [realDateNow() + virtualTimeOffset], realDate);
        }
        return Reflect.construct(target, args, newTarget);
    },
    apply(target, thisArg, args) {
        if (args.length === 0) {
            return new realDate(realDateNow() + virtualTimeOffset).toString();
        }
        return Reflect.apply(target, thisArg, args);
    }
});
global.Date = WrappedDate;

const warpedPerfNow = maskAsNative(() => realPerfNow() + virtualTimeOffset, 'now');
if (realPerf) {
    try {
        Object.defineProperty(realPerf, 'now', {
            value: warpedPerfNow,
            writable: true,
            configurable: true
        });
    } catch (e) {
        try {
            Object.defineProperty(global, 'performance', {
                value: new Proxy(realPerf, {
                    get(target, prop) {
                        if (prop === 'now') return warpedPerfNow;
                        const val = target[prop];
                        return typeof val === 'function' ? val.bind(target) : val;
                    }
                }),
                writable: true,
                configurable: true
            });
        } catch (e2) {}
    }
}
const mockPerfHooks = realPerfHooks
    ? new Proxy(realPerfHooks, {
        get(target, prop) {
            if (prop === 'performance' && realPerf) {
                return new Proxy(realPerf, {
                    get(pTarget, pProp) {
                        if (pProp === 'now') return warpedPerfNow;
                        const val = pTarget[pProp];
                        return typeof val === 'function' ? val.bind(pTarget) : val;
                    }
                });
            }
            const val = target[prop];
            return typeof val === 'function' ? val.bind(target) : val;
        }
    })
    : { performance: { now: warpedPerfNow, timeOrigin: realDateNow() } };

process.uptime = maskAsNative(() => realProcessUptime() + (virtualTimeOffset / 1000), 'uptime');

function normalizeHrtimeTuple(totalSec, totalNs) {
    const extraSec = Math.floor(totalNs / 1e9);
    return [totalSec + extraSec, totalNs - extraSec * 1e9];
}

const hookedHrtime = maskAsNative(function hrtime(prev) {
    const [baseSec, baseNs] = realHrtime();
    const offsetMsInt = Math.trunc(virtualTimeOffset);
    const offsetSec = Math.trunc(offsetMsInt / 1000);
    const offsetNs = (offsetMsInt % 1000) * 1000000;
    const [curSec, curNs] = normalizeHrtimeTuple(baseSec + offsetSec, baseNs + offsetNs);
    if (!Array.isArray(prev)) {
        return [curSec, curNs];
    }
    let diffSec = curSec - Number(prev[0] || 0);
    let diffNs = curNs - Number(prev[1] || 0);
    if (diffNs < 0) {
        diffSec -= 1;
        diffNs += 1e9;
    }
    return [diffSec, diffNs];
}, 'hrtime');

if (realHrtimeBigint) {
    hookedHrtime.bigint = maskAsNative(
        () => realHrtimeBigint() + (BigInt(Math.trunc(virtualTimeOffset)) * 1000000n),
        'bigint'
    );
}
try {
    Object.defineProperty(process, 'hrtime', {
        value: hookedHrtime,
        writable: true,
        configurable: true
    });
} catch (e) {
    try { process.hrtime = hookedHrtime; } catch (e2) {}
}

const TIMER_SUSPICIOUS_CATEGORIES = new Set([
    'NETWORK_EGRESS',
    'DNS_EXFILTRATION',
    'RAW_SOCKET_CONNECT',
    'CHILD_PROCESS_SPAWN',
    'FS_EXTERNAL_WRITE',
    'FS_SENSITIVE_READ',
    'ENV_HARVESTING',
    'RUNTIME_DYNAMIC_EVAL',
    'SANDBOX_EVASION'
]);
const TIME_BOMB_THRESHOLD_MS = 300000;
const MAX_TIMEOUT_CALLBACKS = 28;
const MAX_INTERVAL_CALLBACKS = 12;
const MAX_IMMEDIATE_CALLBACKS = 24;
const MAX_NOOP_TIMERS = 500;
const MAX_TIMER_REAL_BUDGET_MS = 600;
const fnToStringRef = OriginalFunction.prototype.toString;

function isEmptyNoopCallback(fn) {
    if (typeof fn !== 'function') return false;
    if (fn === noop) return true;
    try {
        const src = fnToStringRef.call(fn)
            .replace(/\/\*[\s\S]*?\*\//g, '')
            .replace(/\/\/[^\n]*/g, '')
            .trim();
        return /^(?:async\s+)?(?:function(?:\s*\*|\s+[A-Za-z_$][\w$]*)?\s*\([^)]*\)\s*\{\s*;*\s*\}|\(?[^=)]*\)?\s*=>\s*\{\s*;*\s*\})$/.test(src);
    } catch (e) {
        return false;
    }
}

function runTimerCallbackAndCheckEvasion(apiName, fn, ms, args) {
    const eventsBefore = events.length;
    if (typeof fn === 'string') {
        const preview = fn.replace(/\s+/g, ' ').trim().slice(0, 160);
        recordEvent(
            'RUNTIME_DYNAMIC_EVAL',
            `${apiName}(string)`,
            `Timer dynamic string evaluation: ${preview}`,
            'HIGH'
        );
        executeTargetCode(() => {
            originalEval.call(global, fn);
        });
    } else if (typeof fn === 'function') {
        executeTargetCode(() => fn(...args));
    }
    const triggeredSuspicious = events
        .slice(eventsBefore)
        .some(ev => TIMER_SUSPICIOUS_CATEGORIES.has(ev.category));
    if (ms >= TIME_BOMB_THRESHOLD_MS || (ms >= 1000 && triggeredSuspicious)) {
        recordEvent(
            'SANDBOX_EVASION',
            apiName,
            `Deliberate execution delay (${ms}ms) paired with time-bomb / sensitive payload`,
            'HIGH'
        );
    }
}

// Time-bomb / Delay Evasion Interception (separated quotas & noop budget immunity)
let timeoutCallbacksRun = 0;
let intervalCallbacksRun = 0;
let immediateCallbacksRun = 0;
let noopTimerCallbacksSeen = 0;

function hasTimerRealBudget() {
    return (realDateNow() - sandboxStartRealMs) < MAX_TIMER_REAL_BUDGET_MS;
}

global.setTimeout = maskAsNative(function(fn, delay, ...args) {
    const rawMs = Number(delay);
    const ms = Number.isFinite(rawMs) && rawMs > 0 ? Math.min(rawMs, 86400000 * 30) : 0;
    if (ms > 0) {
        virtualTimeOffset += ms;
    }
    const isStringOrFn = typeof fn === 'function' || typeof fn === 'string';
    const isNoopFn = isEmptyNoopCallback(fn);
    const withinBudget = hasTimerRealBudget() && (isNoopFn ? noopTimerCallbacksSeen < MAX_NOOP_TIMERS : timeoutCallbacksRun < MAX_TIMEOUT_CALLBACKS);
    if (isStringOrFn && withinBudget) {
        if (isNoopFn) {
            noopTimerCallbacksSeen++;
        } else {
            timeoutCallbacksRun++;
        }
        runTimerCallbackAndCheckEvasion('setTimeout', fn, ms, args);
    } else if (ms >= TIME_BOMB_THRESHOLD_MS) {
        recordEvent(
            'SANDBOX_EVASION',
            'setTimeout',
            `Deliberate long execution delay (${ms}ms) detected in sandbox`,
            'HIGH'
        );
    }
    return { ref: noop, unref: noop, hasRef: () => false, refresh: noop };
}, 'setTimeout');

global.setInterval = maskAsNative(function(fn, delay, ...args) {
    const rawMs = Number(delay);
    const ms = Number.isFinite(rawMs) && rawMs > 0 ? Math.min(rawMs, 86400000 * 30) : 0;
    if (ms > 0) {
        virtualTimeOffset += ms;
    }
    const isStringOrFn = typeof fn === 'function' || typeof fn === 'string';
    const isNoopFn = isEmptyNoopCallback(fn);
    const withinBudget = hasTimerRealBudget() && (isNoopFn ? noopTimerCallbacksSeen < MAX_NOOP_TIMERS : intervalCallbacksRun < MAX_INTERVAL_CALLBACKS);
    if (isStringOrFn && withinBudget) {
        if (isNoopFn) {
            noopTimerCallbacksSeen++;
        } else {
            intervalCallbacksRun++;
        }
        runTimerCallbackAndCheckEvasion('setInterval', fn, ms, args);
    } else if (ms >= TIME_BOMB_THRESHOLD_MS) {
        recordEvent(
            'SANDBOX_EVASION',
            'setInterval',
            `Periodic long execution delay (${ms}ms) detected in sandbox`,
            'HIGH'
        );
    }
    return { ref: noop, unref: noop };
}, 'setInterval');

global.setImmediate = maskAsNative(function(fn, ...args) {
    if (typeof fn === 'function' && immediateCallbacksRun < MAX_IMMEDIATE_CALLBACKS) {
        immediateCallbacksRun++;
        realSetImmediate(() => {
            executeTargetCode(() => fn(...args));
        });
    }
    return { ref: noop, unref: noop, hasRef: () => false };
}, 'setImmediate');

if (typeof Atomics !== 'undefined' && typeof Atomics.wait === 'function') {
    Atomics.wait = maskAsNative(function(typedArray, index, value, timeout) {
        const rawTimeout = Number(timeout);
        if (Number.isFinite(rawTimeout) && rawTimeout > 0) {
            virtualTimeOffset += Math.min(rawTimeout, 86400000 * 30);
        }
        recordEvent(
            'SANDBOX_EVASION',
            'Atomics.wait',
            `Low-level thread sleep evasion intercepted (timeout=${timeout}ms)`,
            'HIGH'
        );
        return 'ok';
    }, 'wait');
}

// Dynamic Code Evaluation Interception (eval, Function/Async/Generator constructors, Module._compile)
global.eval = maskAsNative(function(code) {
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
}, 'eval');

const SAFE_FUNCTION_IDIOM_RE = /^(?:'use strict';?\s*|"use strict";?\s*)?(?:return\s+this|return\s+globalThis)\s*;?$/i;
function recordDynamicFunctionCall(args, apiLabel = 'Function()') {
    if (!args || args.length === 0) return;
    const body = String(args[args.length - 1] || '').trim();
    if (!body || SAFE_FUNCTION_IDIOM_RE.test(body)) return;
    const preview = args.map(a => String(a)).join(', ').replace(/\s+/g, ' ').trim().slice(0, 160);
    recordEvent(
        'RUNTIME_DYNAMIC_EVAL',
        apiLabel,
        `Dynamic ${apiLabel} constructor invocation: ${preview}`,
        'HIGH'
    );
}

function hookFunctionConstructor(proto, origCtor, apiLabel) {
    if (!proto || !origCtor) return origCtor;
    const hooked = new Proxy(origCtor, {
        apply(target, thisArg, args) {
            recordDynamicFunctionCall(args, apiLabel);
            return Reflect.apply(target, thisArg, args);
        },
        construct(target, args, newTarget) {
            recordDynamicFunctionCall(args, apiLabel);
            return Reflect.construct(target, args, newTarget);
        }
    });
    try {
        Object.defineProperty(proto, 'constructor', {
            value: hooked,
            writable: true,
            configurable: true
        });
    } catch (e) {
        try { proto.constructor = hooked; } catch (e2) {}
    }
    return hooked;
}

const AsyncFunctionProto = Object.getPrototypeOf(async function() {});
const GeneratorFunctionProto = Object.getPrototypeOf(function*() {});
const AsyncGeneratorFunctionProto = Object.getPrototypeOf(async function*() {});

const HookedFunction = hookFunctionConstructor(Function.prototype, OriginalFunction, 'Function()');
hookFunctionConstructor(AsyncFunctionProto, AsyncFunctionProto && AsyncFunctionProto.constructor, 'AsyncFunction()');
hookFunctionConstructor(GeneratorFunctionProto, GeneratorFunctionProto && GeneratorFunctionProto.constructor, 'GeneratorFunction()');
hookFunctionConstructor(AsyncGeneratorFunctionProto, AsyncGeneratorFunctionProto && AsyncGeneratorFunctionProto.constructor, 'AsyncGeneratorFunction()');
global.Function = HookedFunction;

function normalizeCompileSource(src) {
    let s = typeof src === 'string' ? src : String(src || '');
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    return s.replace(/\r\n/g, '\n');
}

function stripLeadingShebang(src) {
    return src.startsWith('#!') ? src.replace(/^#![^\n]*\n?/, '') : src;
}

Module.prototype._compile = function(content, filename) {
    if (!isSandboxInternalCompile) {
        const fname = typeof filename === 'string' ? filename.trim() : '';
        let isDynamicCompile = !fname;
        if (!isDynamicCompile) {
            try {
                if (!realFsExistsSync(fname) || !realFsStatSync(fname).isFile()) {
                    isDynamicCompile = true;
                } else {
                    const normContent = normalizeCompileSource(content);
                    const normDisk = normalizeCompileSource(realFsReadFileSync(fname, 'utf8'));
                    if (normContent !== normDisk && normContent !== stripLeadingShebang(normDisk)) {
                        isDynamicCompile = true;
                    }
                }
            } catch (e) {
                isDynamicCompile = true;
            }
        }
        if (isDynamicCompile) {
            const preview = String(content || '').replace(/\s+/g, ' ').trim().slice(0, 160);
            recordEvent(
                'RUNTIME_DYNAMIC_EVAL',
                'Module._compile',
                `In-memory Module._compile(${fname || '<anonymous>'}): ${preview}`,
                'HIGH'
            );
        }
    }
    return originalModuleCompile.apply(this, arguments);
};

// Hook global fetch (Node 18/20+)
global.fetch = maskAsNative(function(url, options) {
    const method = (options && options.method) || 'GET';
    if (!inExportFuzzing || !isDegenerateFuzzTarget(url)) {
        recordEvent(
            'NETWORK_EGRESS',
            'fetch()',
            `Outbound HTTP ${method} request via fetch() to: ${String(url)}`,
            'CRITICAL'
        );
    }
    return Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Map(),
        text: async () => '',
        json: async () => ({}),
        arrayBuffer: async () => new ArrayBuffer(0)
    });
}, 'fetch');

// ============================================================================
// 3. NODE.JS CORE MODULE INTERCEPTION (Module._load)
// ============================================================================

function createDummyStream(suppressWriteEvents = false) {
    const scheduleSocketCb = (cb) => {
        if (typeof cb !== 'function') return;
        realSetImmediate(() => {
            executeTargetCode(() => cb.call(stream, stream));
        });
    };
    const stream = {
        on: function(ev, cb) {
            if (ev === 'end' || ev === 'close' || ev === 'finish') {
                if (typeof cb === 'function') { try { cb.call(stream); } catch (e) {} }
            } else if (ev === 'connect' || ev === 'secureConnect' || ev === 'ready') {
                scheduleSocketCb(cb);
            }
            return stream;
        },
        once: function(ev, cb) {
            return stream.on(ev, cb);
        },
        addListener: function(ev, cb) {
            return stream.on(ev, cb);
        },
        emit: noop,
        write: function(chunk) {
            if (chunk && !suppressWriteEvents) {
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
        setEncoding: noop,
        resume: () => stream,
        pause: () => stream,
        setHeader: noop,
        getHeader: () => '',
        pipe: (dest) => dest,
        unref: noop,
        ref: noop,
        getPeerCertificate: () => ({}),
        address: () => ({ port: 443, family: 'IPv4', address: '127.0.0.1' }),
        encrypted: true,
        authorized: true,
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
        const degenerate = inExportFuzzing && isDegenerateFuzzTarget(targetDesc);
        if (!degenerate) {
            recordEvent(
                'NETWORK_EGRESS',
                `${protoName}.${methodName}`,
                `Outbound network request: ${targetDesc}`,
                'CRITICAL'
            );
        }
        const req = createDummyStream(degenerate);
        const cb = typeof optsOrCb === 'function' ? optsOrCb : (typeof maybeCb === 'function' ? maybeCb : null);
        if (cb) {
            const res = createDummyStream(degenerate);
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

function shouldRecordFuzzTarget(targetVal) {
    return !inExportFuzzing || !isDegenerateFuzzTarget(targetVal);
}

const mockChildProcess = {
    exec: function(cmd, opts, cb) {
        if (shouldRecordFuzzTarget(cmd)) {
            recordEvent('CHILD_PROCESS_SPAWN', 'child_process.exec', `Executed shell command: ${cmd}`, 'CRITICAL');
        }
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
        if (shouldRecordFuzzTarget(cmd)) {
            recordEvent('CHILD_PROCESS_SPAWN', 'child_process.execSync', `Executed synchronous shell command: ${cmd}`, 'CRITICAL');
        }
        return Buffer.from('sandbox-output\n');
    },
    spawn: function(cmd, args) {
        const full = Array.isArray(args) ? `${cmd} ${args.join(' ')}` : String(cmd);
        if (shouldRecordFuzzTarget(cmd)) {
            recordEvent('CHILD_PROCESS_SPAWN', 'child_process.spawn', `Spawned process: ${full}`, 'CRITICAL');
        }
        const proc = createDummyStream();
        proc.stdout = createDummyStream();
        proc.stderr = createDummyStream();
        proc.stdin = createDummyStream();
        proc.pid = 9999;
        return proc;
    },
    spawnSync: function(cmd, args) {
        const full = Array.isArray(args) ? `${cmd} ${args.join(' ')}` : String(cmd);
        if (shouldRecordFuzzTarget(cmd)) {
            recordEvent('CHILD_PROCESS_SPAWN', 'child_process.spawnSync', `Spawned synchronous process: ${full}`, 'CRITICAL');
        }
        return { pid: 9999, output: [null, Buffer.from(''), Buffer.from('')], stdout: Buffer.from(''), stderr: Buffer.from(''), status: 0 };
    },
    execFile: function(file, args, opts, cb) {
        const full = Array.isArray(args) ? `${file} ${args.join(' ')}` : String(file);
        if (shouldRecordFuzzTarget(file)) {
            recordEvent('CHILD_PROCESS_SPAWN', 'child_process.execFile', `Executed binary file: ${full}`, 'CRITICAL');
        }
        const callback = [args, opts, cb].find(x => typeof x === 'function');
        if (callback) {
            try { callback(null, 'sandbox-output\n', ''); } catch (e) {}
        }
        return createDummyStream();
    },
    execFileSync: function(file, args) {
        const full = Array.isArray(args) ? `${file} ${args.join(' ')}` : String(file);
        if (shouldRecordFuzzTarget(file)) {
            recordEvent('CHILD_PROCESS_SPAWN', 'child_process.execFileSync', `Executed synchronous binary file: ${full}`, 'CRITICAL');
        }
        return Buffer.from('sandbox-output\n');
    },
    fork: function(modulePath) {
        if (shouldRecordFuzzTarget(modulePath)) {
            recordEvent('CHILD_PROCESS_SPAWN', 'child_process.fork', `Forked Node.js child process: ${modulePath}`, 'CRITICAL');
        }
        const proc = createDummyStream();
        proc.send = noop;
        proc.pid = 9999;
        return proc;
    }
};

const DNS_RECORD_METHODS = [
    ['resolve4', 'A-record', ['127.0.0.1']],
    ['resolve6', 'AAAA-record', ['::1']],
    ['resolveMx', 'MX-record', [{ exchange: 'mail.example.com', priority: 10 }]],
    ['resolveTxt', 'TXT-record', [['v=spf1']]],
    ['resolveNs', 'NS-record', ['ns1.example.com']],
    ['resolveCname', 'CNAME-record', ['alias.example.com']],
    ['resolveSrv', 'SRV-record', [{ name: 'srv.example.com', port: 443, priority: 1, weight: 1 }]],
    ['resolvePtr', 'PTR-record', ['ptr.example.com']],
    ['resolveSoa', 'SOA-record', { nsname: 'ns1.example.com', hostmaster: 'hostmaster.example.com', serial: 1, refresh: 3600, retry: 600, expire: 86400, minttl: 60 }],
    ['resolveAny', 'ANY-record', [{ type: 'A', address: '127.0.0.1', ttl: 60 }]],
    ['reverse', 'PTR-reverse', ['localhost']]
];

function createDnsCallbackApi(prefix) {
    const api = {
        lookup: function(hostname, opts, cb) {
            const domain = String(hostname || '');
            if (shouldRecordFuzzTarget(domain) && domain && domain !== 'localhost' && domain !== '127.0.0.1') {
                recordEvent('DNS_EXFILTRATION', `${prefix}.lookup`, `DNS resolution / potential DNS exfiltration: ${domain}`, 'CRITICAL');
            }
            const callback = typeof opts === 'function' ? opts : (typeof cb === 'function' ? cb : null);
            if (callback) {
                try { callback(null, '127.0.0.1', 4); } catch (e) {}
            }
        },
        resolve: function(hostname, rrtype, cb) {
            const domain = String(hostname || '');
            if (shouldRecordFuzzTarget(domain)) {
                recordEvent('DNS_EXFILTRATION', `${prefix}.resolve`, `DNS record query for: ${domain}`, 'CRITICAL');
            }
            const callback = typeof rrtype === 'function' ? rrtype : (typeof cb === 'function' ? cb : null);
            if (callback) {
                try { callback(null, ['127.0.0.1']); } catch (e) {}
            }
        },
        getServers: function() {
            recordEvent('OS_FINGERPRINTING', `${prefix}.getServers`, 'Queried local DNS resolver servers', 'MEDIUM');
            return ['8.8.8.8'];
        },
        setServers: noop
    };
    for (const [methodName, label, sampleResp] of DNS_RECORD_METHODS) {
        api[methodName] = function(hostname, optsOrCb, cb) {
            const targetStr = String(hostname || '');
            if (shouldRecordFuzzTarget(targetStr)) {
                recordEvent('DNS_EXFILTRATION', `${prefix}.${methodName}`, `DNS ${label} query for: ${targetStr}`, 'CRITICAL');
            }
            const callback = typeof optsOrCb === 'function' ? optsOrCb : (typeof cb === 'function' ? cb : null);
            if (callback) {
                try { callback(null, sampleResp); } catch (e) {}
            }
        };
    }
    return api;
}

function createDnsPromisesApi(prefix) {
    const api = {
        lookup: async (hostname) => {
            if (shouldRecordFuzzTarget(hostname)) {
                recordEvent('DNS_EXFILTRATION', `${prefix}.lookup`, `Async DNS lookup for: ${hostname}`, 'CRITICAL');
            }
            return { address: '127.0.0.1', family: 4 };
        },
        resolve: async (hostname) => {
            if (shouldRecordFuzzTarget(hostname)) {
                recordEvent('DNS_EXFILTRATION', `${prefix}.resolve`, `Async DNS resolve for: ${hostname}`, 'CRITICAL');
            }
            return ['127.0.0.1'];
        },
        getServers: () => {
            recordEvent('OS_FINGERPRINTING', `${prefix}.getServers`, 'Queried local DNS resolver servers', 'MEDIUM');
            return ['8.8.8.8'];
        },
        setServers: noop
    };
    for (const [methodName, label, sampleResp] of DNS_RECORD_METHODS) {
        api[methodName] = async (hostname) => {
            const targetStr = String(hostname || '');
            if (shouldRecordFuzzTarget(targetStr)) {
                recordEvent('DNS_EXFILTRATION', `${prefix}.${methodName}`, `Async DNS ${label} query for: ${targetStr}`, 'CRITICAL');
            }
            return sampleResp;
        };
    }
    return api;
}

function DnsResolver() {
    Object.assign(this, createDnsCallbackApi('dns.Resolver'));
    this.cancel = noop;
}
function DnsPromisesResolver() {
    Object.assign(this, createDnsPromisesApi('dns.promises.Resolver'));
    this.cancel = noop;
}

const mockDns = Object.assign(createDnsCallbackApi('dns'), {
    Resolver: DnsResolver,
    promises: Object.assign(createDnsPromisesApi('dns.promises'), {
        Resolver: DnsPromisesResolver
    })
});

function formatSocketTarget(args) {
    const first = args[0];
    if (first && typeof first === 'object') {
        if (first.path) return String(first.path);
        const host = first.host || first.hostname || first.servername || 'localhost';
        const port = first.port || '';
        return `${host}:${port}`;
    }
    const port = first || '';
    const host = typeof args[1] === 'string' ? args[1] : 'localhost';
    return `${host}:${port}`;
}

function handleSocketConnect(apiName, args, sockOverride) {
    const target = formatSocketTarget(args);
    if (shouldRecordFuzzTarget(target)) {
        recordEvent('RAW_SOCKET_CONNECT', apiName, `Raw socket connection to: ${target}`, 'CRITICAL');
    }
    const sock = sockOverride || createDummyStream();
    const cb = args.find(x => typeof x === 'function');
    if (typeof cb === 'function') {
        realSetImmediate(() => {
            executeTargetCode(() => cb.call(sock, sock));
        });
    }
    return sock;
}

const mockNet = {
    connect: function(...args) {
        return handleSocketConnect('net.connect', args);
    },
    createConnection: function(...args) {
        return handleSocketConnect('net.createConnection', args);
    },
    Socket: function() {
        const sock = createDummyStream();
        sock.connect = function(...args) {
            return handleSocketConnect('net.Socket.connect', args, sock);
        };
        return sock;
    },
    createServer: () => ({ listen: noop, on: noop, close: noop }),
    isIP: () => 0,
    isIPv4: () => false,
    isIPv6: () => false
};

const mockTls = {
    connect: function(...args) {
        return handleSocketConnect('tls.connect', args);
    },
    createConnection: function(...args) {
        return handleSocketConnect('tls.createConnection', args);
    },
    TLSSocket: function() {
        return createDummyStream();
    },
    createSecureContext: () => ({}),
    createServer: () => ({ listen: noop, on: noop, close: noop }),
    DEFAULT_ECDH_CURVE: 'auto',
    rootCertificates: []
};

const mockDgram = {
    createSocket: function() {
        const sock = createDummyStream();
        sock.send = function(msg, offset, length, port, address, cb) {
            if (!inExportFuzzing || !isDegenerateFuzzTarget(address)) {
                recordEvent('RAW_SOCKET_CONNECT', 'dgram.Socket.send', `Raw UDP packet sent to ${address || port}`, 'CRITICAL');
            }
            if (typeof cb === 'function') { try { cb(null); } catch (e) {} }
        };
        sock.bind = noop;
        sock.close = noop;
        return sock;
    }
};

// Sensitive filesystem path checker (supports symlinked benchmark directories)
const SENSITIVE_PATH_REGEX = /(\/etc\/(passwd|shadow|hosts|sudoers|crontab|ssh)|\.npmrc|\.yarnrc|\.pypirc|\.netrc|\.ssh|\.aws|\.kube|\.docker|\.gitconfig|\.bash_history|\.zsh_history|id_rsa|id_ed25519|\/proc\/self)/i;

function parseFileUrlToFsPath(urlOrStr) {
    try {
        return urlModule.fileURLToPath(urlOrStr);
    } catch (e) {
        try {
            const u = (typeof URL !== 'undefined' && urlOrStr instanceof URL)
                ? urlOrStr
                : new URL(String(urlOrStr));
            if (u.protocol === 'file:') {
                let p = decodeURIComponent(u.pathname || '');
                if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1);
                return p || String(urlOrStr);
            }
        } catch (e2) {}
        return String(urlOrStr);
    }
}

function normalizeFsPathInput(targetPath) {
    if (targetPath === undefined || targetPath === null) return '';
    if (Buffer.isBuffer(targetPath)) {
        return targetPath.toString('utf8');
    }
    if (typeof targetPath === 'string') {
        const trimmed = targetPath.trim();
        if (/^file:\/\//i.test(trimmed)) {
            return parseFileUrlToFsPath(trimmed);
        }
        return targetPath;
    }
    if (typeof targetPath === 'object') {
        const isUrlObj = (typeof URL !== 'undefined' && targetPath instanceof URL) ||
            (typeof targetPath.href === 'string' && /^file:\/\//i.test(targetPath.href));
        if (isUrlObj) {
            return parseFileUrlToFsPath(targetPath);
        }
        if (typeof targetPath.toString === 'function' && targetPath.toString !== Object.prototype.toString) {
            return String(targetPath);
        }
    }
    return String(targetPath);
}

function isInsidePkgDir(targetPath) {
    try {
        const pStr = normalizeFsPathInput(targetPath);
        if (!pStr || /^file:\/\//i.test(pStr.trim())) return false;
        const resolved = path.resolve(pkgDir, pStr);
        const normPkg = path.normalize(pkgDir).toLowerCase();
        const normRealPkg = path.normalize(realPkgDir).toLowerCase();
        const normRes = path.normalize(resolved).toLowerCase();
        const withSep = (p) => p.endsWith(path.sep) ? p : p + path.sep;
        if (normRes === normPkg || normRes.startsWith(withSep(normPkg)) ||
            normRes === normRealPkg || normRes.startsWith(withSep(normRealPkg))) {
            return true;
        }
        if (realFsExistsSync(resolved)) {
            const realTarget = path.normalize(realFsRealpathSync(resolved)).toLowerCase();
            if (realTarget === normPkg || realTarget.startsWith(withSep(normPkg)) ||
                realTarget === normRealPkg || realTarget.startsWith(withSep(normRealPkg))) {
                return true;
            }
        }
        return false;
    } catch (e) {
        return false;
    }
}

function checkFsRead(apiName, targetPath, opts = {}) {
    const metadataOnly = Boolean(opts && opts.metadataOnly);
    const pStr = normalizeFsPathInput(targetPath);
    if (inExportFuzzing && (!pStr.trim() || pStr === 'undefined' || pStr === 'null' || pStr === '[object Object]')) {
        return false;
    }
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
        if (metadataOnly) {
            return false;
        }
        recordEvent('FS_SENSITIVE_READ', apiName, `Attempted to read external host path outside package: ${pStr}`, 'HIGH');
        return false;
    }
    return true;
}

function handleFsWrite(apiName, targetPath) {
    const pStr = normalizeFsPathInput(targetPath);
    if (inExportFuzzing && (!pStr.trim() || pStr === 'undefined' || pStr === 'null' || pStr === '[object Object]')) {
        return;
    }
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
                    return typeof options === 'string' || (options && options.encoding) ? 'dummy-content\n' : Buffer.from('dummy-content\n');
                }
                return realFsReadFileSync(filePath, options);
            };
        }
        if (prop === 'readFile') {
            return function(filePath, options, cb) {
                const callback = typeof options === 'function' ? options : cb;
                if (!checkFsRead('fs.readFile', filePath)) {
                    if (typeof callback === 'function') {
                        try { callback(null, Buffer.from('dummy-content\n')); } catch (e) {}
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
        if (prop === 'openSync') {
            return function(filePath, flags, mode) {
                const isWriteFlag = typeof flags === 'string' && /[wa+]/.test(flags);
                if (isWriteFlag) {
                    handleFsWrite('fs.openSync', filePath);
                    return 42;
                }
                if (!checkFsRead('fs.openSync', filePath)) return 42;
                return realFsOpenSync(filePath, flags, mode);
            };
        }
        if (prop === 'open') {
            return function(filePath, flags, mode, cb) {
                const callback = [flags, mode, cb].find(x => typeof x === 'function');
                const isWriteFlag = typeof flags === 'string' && /[wa+]/.test(flags);
                if (isWriteFlag) {
                    handleFsWrite('fs.open', filePath);
                    if (callback) { try { callback(null, 42); } catch (e) {} }
                    return;
                }
                if (!checkFsRead('fs.open', filePath)) {
                    if (callback) { try { callback(null, 42); } catch (e) {} }
                    return;
                }
                return realFsOpen(filePath, flags, mode, cb);
            };
        }
        if (prop === 'createReadStream') {
            return function(filePath, opts) {
                if (!checkFsRead('fs.createReadStream', filePath)) return createDummyStream(true);
                return realFsCreateReadStream(filePath, opts);
            };
        }
        if (prop === 'statSync' || prop === 'lstatSync') {
            return function(filePath, opts) {
                if (!checkFsRead(`fs.${prop}`, filePath, { metadataOnly: true })) {
                    return { isFile: () => false, isDirectory: () => false, isSymbolicLink: () => false, size: 0 };
                }
                return prop === 'statSync' ? realFsStatSync(filePath, opts) : realFsLstatSync(filePath, opts);
            };
        }
        if (prop === 'existsSync') {
            return function(filePath) {
                if (!checkFsRead('fs.existsSync', filePath, { metadataOnly: true })) {
                    return false;
                }
                return realFsExistsSync(filePath);
            };
        }
        if (prop === 'accessSync') {
            return function(filePath, mode) {
                if (!checkFsRead('fs.accessSync', filePath, { metadataOnly: true })) {
                    const err = new Error('ENOENT');
                    err.code = 'ENOENT';
                    throw err;
                }
                return realFsAccessSync(filePath, mode);
            };
        }
        if (prop === 'realpathSync') {
            return function(filePath, opts) {
                if (!checkFsRead('fs.realpathSync', filePath, { metadataOnly: true })) {
                    return normalizeFsPathInput(filePath);
                }
                return realFsRealpathSync(filePath, opts);
            };
        }
        if (prop === 'writeSync') {
            return function(fd, buf) {
                if (fd === 1 || fd === 2) return 0;
                handleFsWrite('fs.writeSync', `fd:${fd}`);
                return Buffer.isBuffer(buf) ? buf.length : String(buf || '').length;
            };
        }
        if (prop === 'write') {
            return function(fd, ...args) {
                const cb = args.find(x => typeof x === 'function');
                if (fd === 1 || fd === 2) {
                    if (cb) { try { cb(null, 0); } catch (e) {} }
                    return;
                }
                handleFsWrite('fs.write', `fd:${fd}`);
                if (cb) { try { cb(null, 0); } catch (e) {} }
            };
        }
        if (prop === 'writeFileSync' || prop === 'appendFileSync' || prop === 'truncateSync' || prop === 'ftruncateSync' || prop === 'mkdirSync') {
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
        if (prop === 'cpSync' || prop === 'copyFileSync' || prop === 'symlinkSync' || prop === 'linkSync') {
            return function(src, dest) {
                checkFsRead(`fs.${prop}`, src);
                handleFsWrite(`fs.${prop}`, dest);
                return undefined;
            };
        }
        if (prop === 'cp' || prop === 'copyFile') {
            return function(src, dest, opts, cb) {
                checkFsRead(`fs.${prop}`, src);
                handleFsWrite(`fs.${prop}`, dest);
                const callback = typeof opts === 'function' ? opts : cb;
                if (typeof callback === 'function') {
                    try { callback(null); } catch (e) {}
                }
            };
        }
        if (prop === 'renameSync') {
            return function(oldPath, newPath) {
                handleFsWrite('fs.renameSync', oldPath);
                handleFsWrite('fs.renameSync', newPath);
                return undefined;
            };
        }
        if (prop === 'unlinkSync' || prop === 'rmSync' || prop === 'rmdirSync' || prop === 'chmodSync') {
            return function(filePath) {
                handleFsWrite(`fs.${prop}`, filePath);
                return undefined;
            };
        }
        if (prop === 'rename') {
            return function(oldPath, newPath, cb) {
                handleFsWrite('fs.rename', oldPath);
                handleFsWrite('fs.rename', newPath);
                if (typeof cb === 'function') {
                    try { cb(null); } catch (e) {}
                }
            };
        }
        if (prop === 'unlink' || prop === 'rm' || prop === 'rmdir' || prop === 'mkdir' || prop === 'chmod' || prop === 'truncate') {
            return function(filePath, opts, cb) {
                handleFsWrite(`fs.${prop}`, filePath);
                const callback = typeof opts === 'function' ? opts : cb;
                if (typeof callback === 'function') {
                    try { callback(null); } catch (e) {}
                }
            };
        }
        if (prop === 'createWriteStream') {
            return function(filePath) {
                handleFsWrite('fs.createWriteStream', filePath);
                return createDummyStream(true);
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
                    if (!checkFsRead('fs.promises.readFile', filePath)) return 'dummy-content\n';
                    return realFsReadFileSync(filePath, opts);
                },
                open: async (filePath, flags) => {
                    if (typeof flags === 'string' && /[wa+]/.test(flags)) {
                        handleFsWrite('fs.promises.open', filePath);
                    } else {
                        checkFsRead('fs.promises.open', filePath);
                    }
                    return { read: async () => ({ bytesRead: 0 }), write: async () => ({ bytesWritten: 0 }), close: async () => {} };
                },
                writeFile: async (filePath) => {
                    handleFsWrite('fs.promises.writeFile', filePath);
                },
                appendFile: async (filePath) => {
                    handleFsWrite('fs.promises.appendFile', filePath);
                },
                cp: async (src, dest) => {
                    checkFsRead('fs.promises.cp', src);
                    handleFsWrite('fs.promises.cp', dest);
                },
                copyFile: async (src, dest) => {
                    checkFsRead('fs.promises.copyFile', src);
                    handleFsWrite('fs.promises.copyFile', dest);
                },
                unlink: async (filePath) => {
                    handleFsWrite('fs.promises.unlink', filePath);
                },
                rm: async (filePath) => {
                    handleFsWrite('fs.promises.rm', filePath);
                },
                rmdir: async (dirPath) => {
                    handleFsWrite('fs.promises.rmdir', dirPath);
                },
                mkdir: async (dirPath) => {
                    handleFsWrite('fs.promises.mkdir', dirPath);
                },
                rename: async (oldPath, newPath) => {
                    handleFsWrite('fs.promises.rename', oldPath);
                    handleFsWrite('fs.promises.rename', newPath);
                },
                chmod: async (filePath) => {
                    handleFsWrite('fs.promises.chmod', filePath);
                },
                truncate: async (filePath) => {
                    handleFsWrite('fs.promises.truncate', filePath);
                },
                readdir: async (dirPath) => {
                    if (!checkFsRead('fs.promises.readdir', dirPath)) return [];
                    return realFsReaddirSync(dirPath);
                },
                stat: async (filePath, opts) => {
                    if (!checkFsRead('fs.promises.stat', filePath, { metadataOnly: true })) {
                        return { isFile: () => false, isDirectory: () => false, isSymbolicLink: () => false, size: 0 };
                    }
                    return realFsStatSync(filePath, opts);
                },
                lstat: async (filePath, opts) => {
                    if (!checkFsRead('fs.promises.lstat', filePath, { metadataOnly: true })) {
                        return { isFile: () => false, isDirectory: () => false, isSymbolicLink: () => false, size: 0 };
                    }
                    return realFsLstatSync(filePath, opts);
                },
                access: async (filePath, mode) => {
                    if (!checkFsRead('fs.promises.access', filePath, { metadataOnly: true })) {
                        const err = new Error('ENOENT');
                        err.code = 'ENOENT';
                        throw err;
                    }
                    return realFsAccessSync(filePath, mode);
                },
                realpath: async (filePath, opts) => {
                    if (!checkFsRead('fs.promises.realpath', filePath, { metadataOnly: true })) {
                        return normalizeFsPathInput(filePath);
                    }
                    return realFsRealpathSync(filePath, opts);
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
                return { username: 'ubuntu', uid: 1000, gid: 1000, shell: '/bin/bash', homedir: '/home/ubuntu' };
            };
        }
        if (prop === 'hostname') {
            return function() {
                recordEvent('OS_FINGERPRINTING', 'os.hostname', 'Queried host machine name', 'LOW');
                return 'build-runner-prod-01';
            };
        }
        if (prop === 'networkInterfaces') {
            return function() {
                recordEvent('OS_FINGERPRINTING', 'os.networkInterfaces', 'Enumerated host network interfaces / MAC / IP addresses', 'HIGH');
                return {
                    eth0: [{
                        address: '10.0.2.15',
                        netmask: '255.255.255.0',
                        family: 'IPv4',
                        mac: '02:42:ac:11:00:02',
                        internal: false,
                        cidr: '10.0.2.15/24'
                    }],
                    lo: [{
                        address: '127.0.0.1',
                        netmask: '255.0.0.0',
                        family: 'IPv4',
                        mac: '00:00:00:00:00:00',
                        internal: true,
                        cidr: '127.0.0.1/8'
                    }]
                };
            };
        }
        if (prop === 'cpus') {
            return function() {
                const realCpus = target.cpus();
                if (Array.isArray(realCpus) && realCpus.length >= 4) {
                    return realCpus;
                }
                const list = Array.isArray(realCpus) ? realCpus.slice() : [];
                while (list.length < 4) {
                    list.push({
                        model: 'Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz',
                        speed: 2400,
                        times: { user: 120000, nice: 0, sys: 30000, idle: 900000, irq: 0 }
                    });
                }
                return list;
            };
        }
        if (prop === 'totalmem') {
            return function() {
                return Math.max(target.totalmem(), 8 * 1024 * 1024 * 1024);
            };
        }
        if (prop === 'homedir') {
            return function() {
                recordEvent('OS_FINGERPRINTING', 'os.homedir', 'Queried user home directory path', 'LOW');
                return '/home/ubuntu';
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
            if (!inExportFuzzing || !isDegenerateFuzzTarget(args[0])) {
                recordEvent('NETWORK_EGRESS', `${modName}()`, `Third-party HTTP client request: ${String(args[0] || '')}`, 'CRITICAL');
            }
        } else if (EXEC_THIRD_PARTY.has(modName)) {
            if (!inExportFuzzing || !isDegenerateFuzzTarget(args[0])) {
                recordEvent('CHILD_PROCESS_SPAWN', `${modName}()`, `Third-party process execution: ${String(args[0] || '')}`, 'CRITICAL');
            }
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
                        if (!inExportFuzzing || !isDegenerateFuzzTarget(args[0])) {
                            recordEvent('NETWORK_EGRESS', `${modName}.${prop}`, `Third-party HTTP ${prop.toUpperCase()} request to: ${String(args[0] || '')}`, 'CRITICAL');
                        }
                        return createUniversalMock(modName, depth + 1);
                    };
                }
                if (EXEC_THIRD_PARTY.has(modName) && ['exec', 'sync', 'command', 'commandSync', 'spawn'].includes(prop)) {
                    return (...args) => {
                        if (!inExportFuzzing || !isDegenerateFuzzTarget(args[0])) {
                            recordEvent('CHILD_PROCESS_SPAWN', `${modName}.${prop}`, `Third-party shell execution: ${String(args[0] || '')}`, 'CRITICAL');
                        }
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

function runVmCode(apiName, code) {
    const codeStr = String(code || '');
    recordEvent('RUNTIME_DYNAMIC_EVAL', apiName, `VM dynamic execution: ${codeStr.replace(/\s+/g, ' ').trim().slice(0, 160)}`, 'HIGH');
    let result;
    executeTargetCode(() => {
        result = originalEval.call(global, codeStr);
    });
    return result;
}

const mockVm = {
    runInNewContext: (code) => runVmCode('vm.runInNewContext', code),
    runInThisContext: (code) => runVmCode('vm.runInThisContext', code),
    runInContext: (code) => runVmCode('vm.runInContext', code),
    createContext: (ctx) => ctx || {},
    isContext: () => true,
    compileFunction: (code) => {
        recordEvent('RUNTIME_DYNAMIC_EVAL', 'vm.compileFunction', `VM compiled function: ${String(code || '').slice(0, 120)}`, 'HIGH');
        return noop;
    },
    Script: function(code) {
        return {
            runInNewContext: () => runVmCode('vm.Script.runInNewContext', code),
            runInThisContext: () => runVmCode('vm.Script.runInThisContext', code),
            runInContext: () => runVmCode('vm.Script.runInContext', code),
        };
    }
};

const mockWorkerThreads = {
    Worker: function(filename) {
        recordEvent('SANDBOX_EVASION', 'worker_threads.Worker', `Attempted to spawn Worker thread: ${String(filename || '')}`, 'HIGH');
        return { on: noop, once: noop, postMessage: noop, terminate: async () => 0 };
    },
    isMainThread: true,
    parentPort: null,
    workerData: null
};

const mockInspector = {
    open: function() {
        recordEvent('SANDBOX_EVASION', 'inspector.open', 'Attempted to open V8 inspector interface', 'HIGH');
    },
    close: noop,
    url: () => undefined
};

function replaceDynamicImports(src) {
    let out = '';
    let i = 0;
    const n = src.length;
    while (i < n) {
        const ch = src[i];
        if (ch === '/' && src[i + 1] === '/') {
            const end = src.indexOf('\n', i);
            if (end === -1) { out += src.slice(i); break; }
            out += src.slice(i, end);
            i = end;
            continue;
        }
        if (ch === '/' && src[i + 1] === '*') {
            const end = src.indexOf('*/', i + 2);
            if (end === -1) { out += src.slice(i); break; }
            out += src.slice(i, end + 2);
            i = end + 2;
            continue;
        }
        if (ch === "'" || ch === '"') {
            const q = ch;
            let j = i + 1;
            while (j < n) {
                if (src[j] === '\\') { j += 2; continue; }
                if (src[j] === q) { j++; break; }
                j++;
            }
            out += src.slice(i, j);
            i = j;
            continue;
        }
        if (src.startsWith('import', i)) {
            const prev = i > 0 ? src[i - 1] : '';
            if (!/[.\w$]/.test(prev)) {
                let k = i + 6;
                while (k < n && /\s/.test(src[k])) k++;
                if (src[k] === '(') {
                    let depth = 1;
                    let p = k + 1;
                    while (p < n && depth > 0) {
                        const c = src[p];
                        if (c === "'" || c === '"' || c === '`') {
                            const q = c;
                            p++;
                            while (p < n) {
                                if (src[p] === '\\') { p += 2; continue; }
                                if (src[p] === q) { p++; break; }
                                p++;
                            }
                            continue;
                        }
                        if (c === '/' && src[p + 1] === '/') {
                            const nl = src.indexOf('\n', p);
                            p = nl === -1 ? n : nl + 1;
                            continue;
                        }
                        if (c === '/' && src[p + 1] === '*') {
                            const ce = src.indexOf('*/', p + 2);
                            p = ce === -1 ? n : ce + 2;
                            continue;
                        }
                        if (c === '(') depth++;
                        else if (c === ')') depth--;
                        p++;
                    }
                    if (depth === 0) {
                        const inner = src.slice(k + 1, p - 1).trim();
                        if (inner) {
                            out += `Promise.resolve(require(${inner}))`;
                            i = p;
                            continue;
                        }
                    }
                }
            }
        }
        out += ch;
        i++;
    }
    return out;
}

function convertNamedEsmBindings(spec) {
    return String(spec || '').replace(/\b([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)\b/g, '$1: $2');
}

function transpileEsmLightweight(rawCode, filePath, opts = {}) {
    let code = normalizeCompileSource(rawCode);
    code = stripLeadingShebang(code);
    const metaUrlExpr = `require('url').pathToFileURL(${JSON.stringify(filePath)}).href`;
    const metaDirExpr = JSON.stringify(path.dirname(filePath));
    const metaFileExpr = JSON.stringify(filePath);
    code = code
        .replace(/\bimport\.meta\.url\b/g, metaUrlExpr)
        .replace(/\bimport\.meta\.dirname\b/g, metaDirExpr)
        .replace(/\bimport\.meta\.filename\b/g, metaFileExpr);

    let tmpIdx = 0;
    const defaultFromMod = (defName, modLit) => {
        const v = `_esmM${tmpIdx++}`;
        return `const ${v} = require(${modLit}); const ${defName} = (${v} && ${v}.__esModule && ${v}.default !== undefined) ? ${v}.default : ${v};`;
    };

    // Static import transformations (preserve line breaks conservatively)
    code = code.replace(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*(['"][^'"]+['"])\s*;?/gm,
        (_, defId, nsId, modLit) => `const ${nsId} = require(${modLit}); const ${defId} = (${nsId} && ${nsId}.__esModule && ${nsId}.default !== undefined) ? ${nsId}.default : ${nsId};`
    );
    code = code.replace(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([^}]+)\}\s*from\s*(['"][^'"]+['"])\s*;?/gm,
        (_, defId, named, modLit) => {
            const v = `_esmM${tmpIdx++}`;
            return `const ${v} = require(${modLit}); const ${defId} = (${v} && ${v}.__esModule && ${v}.default !== undefined) ? ${v}.default : ${v}; const { ${convertNamedEsmBindings(named)} } = ${v};`;
        }
    );
    code = code.replace(
        /^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*(['"][^'"]+['"])\s*;?/gm,
        (_, nsId, modLit) => `const ${nsId} = require(${modLit});`
    );
    code = code.replace(
        /^\s*import\s+\{([^}]+)\}\s*from\s*(['"][^'"]+['"])\s*;?/gm,
        (_, named, modLit) => `const { ${convertNamedEsmBindings(named)} } = require(${modLit});`
    );
    code = code.replace(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s*(['"][^'"]+['"])\s*;?/gm,
        (_, defId, modLit) => defaultFromMod(defId, modLit)
    );
    code = code.replace(
        /^\s*import\s+(['"][^'"]+['"])\s*;?/gm,
        (_, modLit) => `require(${modLit});`
    );
    // Dynamic import(specifier) including template literals, concatenation, and expressions
    code = replaceDynamicImports(code);

    // Export transformations
    const exportedDecls = [];
    code = code.replace(
        /^\s*export\s+\*\s*(?:as\s+([A-Za-z_$][\w$]*)\s+)?from\s*(['"][^'"]+['"])\s*;?/gm,
        (_, nsId, modLit) => nsId ? `exports.${nsId} = require(${modLit});` : `Object.assign(exports, require(${modLit}));`
    );
    code = code.replace(
        /^\s*export\s+\{([^}]+)\}\s*from\s*(['"][^'"]+['"])\s*;?/gm,
        (_, named, modLit) => {
            const v = `_esmRe${tmpIdx++}`;
            const assigns = named.split(',').map(part => {
                const p = part.trim();
                if (!p) return '';
                const m = p.match(/^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/);
                return m ? `exports.${m[2]} = ${v}.${m[1]};` : `exports.${p} = ${v}.${p};`;
            }).filter(Boolean).join(' ');
            return `const ${v} = require(${modLit}); ${assigns}`;
        }
    );
    code = code.replace(
        /^\s*export\s+\{([^}]+)\}\s*;?/gm,
        (_, named) => `Object.assign(exports, { ${convertNamedEsmBindings(named)} });`
    );
    code = code.replace(/^\s*export\s+default\s+/gm, 'exports.default = ');
    code = code.replace(
        /^\s*export\s+(const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/gm,
        (_, kind, id) => `${kind} ${id} = exports.${id} =`
    );
    code = code.replace(
        /^\s*export\s+((?:async\s+)?function\b\s*(?:\*\s*)?([A-Za-z_$][\w$]*)|class\b\s*([A-Za-z_$][\w$]*))/gm,
        (_, decl, fnName, clsName) => {
            const name = fnName || clsName;
            if (name) exportedDecls.push(name);
            return decl;
        }
    );

    const trailer = exportedDecls.map(n => `if (typeof ${n} !== 'undefined') exports.${n} = ${n};`).join('\n');
    const body = opts && opts.wrapAsync
        ? `(async () => {\n${code}\n${trailer}\n})().catch(() => {});`
        : `${code}\n${trailer}`;
    return `'use strict';\nObject.defineProperty(exports, '__esModule', { value: true });\n${body}\n`;
}

function isEsmLoadError(err) {
    if (!err) return false;
    if (err.code === 'ERR_REQUIRE_ESM') return true;
    const msg = String(err.message || '');
    return (
        err instanceof SyntaxError &&
        (
            msg.includes('Cannot use import statement outside a module') ||
            msg.includes("Unexpected token 'export'") ||
            msg.includes("Cannot use 'import.meta' outside a module") ||
            msg.includes('Cannot use import.meta outside a module')
        )
    );
}

function resolvePackageScript(baseDir, spec) {
    if (!spec || typeof spec !== 'string') return '';
    const trimmed = spec.trim();
    if (!trimmed) return '';
    const baseTarget = path.isAbsolute(trimmed) ? trimmed : path.resolve(baseDir, trimmed);
    const candidates = [
        baseTarget,
        `${baseTarget}.js`,
        `${baseTarget}.cjs`,
        `${baseTarget}.mjs`,
        path.join(baseTarget, 'index.js'),
        path.join(baseTarget, 'index.cjs'),
        path.join(baseTarget, 'index.mjs')
    ];
    for (const c of candidates) {
        try {
            if (isInsidePkgDir(c) && realFsExistsSync(c) && realFsStatSync(c).isFile()) {
                return c;
            }
        } catch (e) {}
    }
    return '';
}

function compileEsmFile(filePath, parentModule) {
    if (Module._cache[filePath] && Module._cache[filePath].loaded) {
        return Module._cache[filePath].exports;
    }
    const raw = realFsReadFileSync(filePath, 'utf8');
    const cjsCode = transpileEsmLightweight(raw, filePath);
    const m = new Module(filePath, parentModule || module);
    m.filename = filePath;
    m.paths = Module._nodeModulePaths(path.dirname(filePath));
    Module._cache[filePath] = m;
    isSandboxInternalCompile = true;
    try {
        try {
            originalModuleCompile.call(m, cjsCode, filePath);
        } catch (compileErr) {
            const msg = String((compileErr && compileErr.message) || '');
            if (compileErr instanceof SyntaxError && /\bawait\b|async function/i.test(msg)) {
                const asyncCjsCode = transpileEsmLightweight(raw, filePath, { wrapAsync: true });
                originalModuleCompile.call(m, asyncCjsCode, filePath);
            } else {
                throw compileErr;
            }
        }
    } finally {
        isSandboxInternalCompile = false;
    }
    m.loaded = true;
    return m.exports;
}

function loadTargetModule(filePath) {
    try {
        return require(filePath);
    } catch (err) {
        if (isEsmLoadError(err) && realFsExistsSync(filePath) && isInsidePkgDir(filePath)) {
            return compileEsmFile(filePath, module);
        }
        throw err;
    }
}

Module._load = function(request, parent, isMain) {
    const cleanReq = String(request || '').replace(/^node:/, '');
    if (cleanReq === 'child_process') return mockChildProcess;
    if (cleanReq === 'http') return createMockHttpModule('http');
    if (cleanReq === 'https') return createMockHttpModule('https');
    if (cleanReq === 'http2') return createMockHttpModule('http2');
    if (cleanReq === 'dns' || cleanReq === 'dns/promises') return cleanReq === 'dns/promises' ? mockDns.promises : mockDns;
    if (cleanReq === 'net') return mockNet;
    if (cleanReq === 'tls') return mockTls;
    if (cleanReq === 'dgram') return mockDgram;
    if (cleanReq === 'fs') return mockFs;
    if (cleanReq === 'fs/promises') return mockFs.promises;
    if (cleanReq === 'os') return mockOs;
    if (cleanReq === 'vm') return mockVm;
    if (cleanReq === 'worker_threads') return mockWorkerThreads;
    if (cleanReq === 'inspector' || cleanReq === 'inspector/promises') return mockInspector;
    if (cleanReq === 'perf_hooks') return mockPerfHooks;

    if (NETWORK_THIRD_PARTY.has(cleanReq) || EXEC_THIRD_PARTY.has(cleanReq)) {
        return createUniversalMock(cleanReq);
    }

    try {
        return originalModuleLoad.apply(this, arguments);
    } catch (err) {
        const parentDir = parent && parent.filename ? path.dirname(parent.filename) : pkgDir;
        if (isEsmLoadError(err)) {
            let resolved = '';
            try {
                resolved = Module._resolveFilename(request, parent, isMain);
            } catch (resolveErr) {
                resolved = resolvePackageScript(parentDir, String(request || ''));
            }
            if (resolved && realFsExistsSync(resolved) && isInsidePkgDir(resolved)) {
                return compileEsmFile(resolved, parent);
            }
        }
        if (err && err.code === 'MODULE_NOT_FOUND') {
            if (String(request || '').startsWith('.')) {
                const localResolved = resolvePackageScript(parentDir, String(request || ''));
                if (localResolved) {
                    return loadTargetModule(localResolved);
                }
            }
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

function splitShellSubcommands(cmdStr) {
    const subs = [];
    let cur = '';
    let quote = null;
    let i = 0;
    const s = String(cmdStr || '');
    while (i < s.length) {
        const ch = s[i];
        if (quote) {
            if (ch === '\\' && quote === '"' && i + 1 < s.length) {
                cur += ch + s[i + 1];
                i += 2;
                continue;
            }
            if (ch === quote) {
                quote = null;
            }
            cur += ch;
            i++;
        } else {
            if (ch === "'" || ch === '"') {
                quote = ch;
                cur += ch;
                i++;
            } else if (s.startsWith('&&', i) || s.startsWith('||', i)) {
                if (cur.trim()) subs.push(cur.trim());
                cur = '';
                i += 2;
            } else if (ch === ';' || ch === '|' || ch === '\n') {
                if (cur.trim()) subs.push(cur.trim());
                cur = '';
                i++;
            } else {
                cur += ch;
                i++;
            }
        }
    }
    if (cur.trim()) subs.push(cur.trim());
    return subs;
}

function tokenizeShellSubcommand(sub) {
    const tokens = [];
    let cur = '';
    let quote = null;
    let hasToken = false;
    let i = 0;
    const s = String(sub || '');
    while (i < s.length) {
        const ch = s[i];
        if (quote) {
            if (ch === '\\' && quote === '"' && i + 1 < s.length && s[i + 1] === '"') {
                cur += '"';
                i += 2;
                continue;
            }
            if (ch === quote) {
                quote = null;
            } else {
                cur += ch;
            }
            hasToken = true;
            i++;
        } else {
            if (ch === "'" || ch === '"') {
                quote = ch;
                hasToken = true;
                i++;
            } else if (/\s/.test(ch)) {
                if (hasToken) {
                    tokens.push(cur);
                    cur = '';
                    hasToken = false;
                }
                i++;
            } else if (ch === '>' || ch === '<' || (!hasToken && (ch === '1' || ch === '2') && s[i + 1] === '>')) {
                if (hasToken) {
                    tokens.push(cur);
                    cur = '';
                    hasToken = false;
                }
                break;
            } else {
                cur += ch;
                hasToken = true;
                i++;
            }
        }
    }
    if (hasToken) tokens.push(cur);
    return tokens;
}

const NODE_VALUE_FLAGS = new Set([
    '-e', '--eval', '-p', '--print',
    '-r', '--require', '--import', '--loader', '--experimental-loader',
    '-C', '--conditions', '--input-type', '--max-old-space-size',
    '--inspect', '--inspect-brk', '--env-file', '--title'
]);

function executeNodeFromHook(cmdStr, depth = 0) {
    if (!cmdStr || typeof cmdStr !== 'string' || depth > 2) return;
    for (const sub of splitShellSubcommands(cmdStr)) {
        const tokens = tokenizeShellSubcommand(sub);
        if (tokens.length === 0) continue;

        let idx = 0;
        while (idx < tokens.length) {
            const base = path.basename(tokens[idx]).toLowerCase();
            if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx]) || base === 'env' || base === 'cross-env' || base === 'npx') {
                idx++;
                continue;
            }
            break;
        }
        if (idx >= tokens.length) continue;

        const cmdBase = path.basename(tokens[idx]).toLowerCase();
        if ((cmdBase === 'sh' || cmdBase === 'bash' || cmdBase === 'zsh') && tokens[idx + 1] === '-c' && tokens[idx + 2]) {
            executeNodeFromHook(tokens.slice(idx + 2).join(' '), depth + 1);
            continue;
        }
        if ((cmdBase === 'cmd' || cmdBase === 'cmd.exe') && /^\/c$/i.test(tokens[idx + 1] || '') && tokens[idx + 2]) {
            executeNodeFromHook(tokens.slice(idx + 2).join(' '), depth + 1);
            continue;
        }
        if (cmdBase !== 'node' && cmdBase !== 'node.exe' && cmdBase !== 'nodejs') continue;

        idx++;
        const inlineCodes = [];
        const preloadSpecs = [];
        let scriptSpec = '';
        let endOfFlags = false;

        while (idx < tokens.length) {
            const tok = tokens[idx];
            if (!endOfFlags && tok === '--') {
                endOfFlags = true;
                idx++;
                continue;
            }
            if (!endOfFlags && tok.startsWith('-')) {
                const eqPos = tok.indexOf('=');
                const flagName = eqPos > 0 ? tok.slice(0, eqPos) : tok;
                if (NODE_VALUE_FLAGS.has(flagName)) {
                    let flagVal = '';
                    if (eqPos > 0) {
                        flagVal = tok.slice(eqPos + 1);
                    } else if (idx + 1 < tokens.length) {
                        flagVal = tokens[++idx];
                    }
                    if (flagName === '-e' || flagName === '--eval' || flagName === '-p' || flagName === '--print') {
                        if (flagVal) inlineCodes.push(flagVal);
                    } else if (flagName === '-r' || flagName === '--require' || flagName === '--import' || flagName === '--loader' || flagName === '--experimental-loader') {
                        if (flagVal) preloadSpecs.push(flagVal);
                    }
                }
                idx++;
                continue;
            }
            scriptSpec = tok;
            break;
        }

        for (const spec of preloadSpecs) {
            const resolved = resolvePackageScript(pkgDir, spec);
            if (resolved) {
                executeTargetCode(() => { loadTargetModule(resolved); });
            }
        }
        for (const code of inlineCodes) {
            executeTargetCode(() => {
                originalEval.call(global, code);
            });
        }
        if (scriptSpec && inlineCodes.length === 0) {
            const resolved = resolvePackageScript(pkgDir, scriptSpec);
            if (resolved) {
                executeTargetCode(() => { loadTargetModule(resolved); });
            }
        }
    }
}

function invokeExportedCallable(fn) {
    if (typeof fn !== 'function') return;
    let desc = null;
    try {
        desc = Object.getOwnPropertyDescriptor(fn, 'prototype');
    } catch (e) {}
    // OSSF package-analysis ES6 class heuristic: constructor if prototype.writable === false
    if (fn.prototype && desc && desc.writable === false) {
        let inst = null;
        executeTargetCode(() => {
            inst = new fn({}, '', noop);
        });
        if (inst) {
            let calledMethods = 0;
            try {
                for (const mName of Object.getOwnPropertyNames(fn.prototype)) {
                    if (mName === 'constructor' || calledMethods >= 3) continue;
                    if (typeof inst[mName] === 'function') {
                        calledMethods++;
                        executeTargetCode(() => { inst[mName]({}, '', noop); });
                    }
                }
            } catch (e) {}
        }
        return;
    }
    executeTargetCode(() => { fn({}, '', noop); });
}

// Step A: Analyze and execute lifecycle hooks from package.json
currentPhase = 'install';
const hooks = sandboxConfig.hooks || {};
for (const [hookName, cmdStr] of Object.entries(hooks)) {
    emulateLifecycleScript(hookName, cmdStr);
    executeNodeFromHook(cmdStr);
}

// Step B: Execute target JS entrypoints inside the package & fuzz up to 5 exported functions/classes
const targetFiles = Array.isArray(sandboxConfig.files) ? sandboxConfig.files : [];
for (const relOrAbsFile of targetFiles) {
    const fullPath = path.resolve(pkgDir, relOrAbsFile);
    if (!realFsExistsSync(fullPath)) continue;

    currentPhase = 'import';
    let exported;
    executeTargetCode(() => {
        exported = loadTargetModule(fullPath);
    });

    inExportFuzzing = true;
    try {
        if (typeof exported === 'function') {
            invokeExportedCallable(exported);
        }
        if (exported && (typeof exported === 'object' || typeof exported === 'function')) {
            let fuzzed = 0;
            for (const key of Object.keys(exported)) {
                if (fuzzed >= 5) break;
                try {
                    if (typeof exported[key] === 'function') {
                        fuzzed++;
                        invokeExportedCallable(exported[key]);
                    }
                } catch (e) {}
            }
        }
    } finally {
        inExportFuzzing = false;
        currentPhase = 'import';
    }
}

// Step C: Drain pending microtasks / Promises / nextTick / setImmediate (4 ticks, <20ms) before exit
function finalizeTelemetry() {
    realStdoutWrite(TELEMETRY_PREFIX + JSON.stringify({
        package_dir: pkgDir,
        events_count: events.length,
        events: events,
        behavioral_summary: buildBehavioralSummary(events)
    }) + '\n');
    realExit(0);
}

realSetImmediate(() => {
    realSetImmediate(() => {
        realSetImmediate(() => {
            realSetImmediate(finalizeTelemetry);
        });
    });
});
