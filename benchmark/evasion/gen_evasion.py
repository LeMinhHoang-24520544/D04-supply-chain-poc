#!/usr/bin/env python3
"""
benchmark/evasion/gen_evasion.py
Generates a controlled evasion experiment dataset (SAFE payloads only).

Every "malicious" variant hides the SAME harmless payload
    require('child_process').execSync('echo EVASION_MARKER')
using a different technique, so differences in detection are caused by the hiding
technique alone. Benign controls reuse constructs that look like evasion
(base64 assets, hex tables, fromCharCode, dynamic require, child_process, install hooks)
to measure false positives.

Output: <out>/<pkg_id>/{package.json,index.js,...} and <out>/ground_truth.json
(compatible with scripts/evaluate.py).
"""

import argparse
import base64
import json
import os
import random
import shutil
import string

PAYLOAD = "require('child_process').execSync('echo EVASION_MARKER')"
HOOK = {"postinstall": "node index.js"}

# id -> (description, has_hook, builder)
def b64(s): return base64.b64encode(s.encode()).decode()

def e0(): return PAYLOAD + ";\nmodule.exports = {};"
def e1(): return "eval(Buffer.from('%s', 'base64').toString('utf-8'));\nmodule.exports = {};" % b64(PAYLOAD)
def e2(): return "eval(Buffer.from('%s', 'hex').toString());\nmodule.exports = {};" % PAYLOAD.encode().hex()
def e3(): return "eval(String.fromCharCode(%s));\nmodule.exports = {};" % ",".join(str(ord(c)) for c in PAYLOAD)
def e4(): return ("const a = 'child_'; const b = 'process';\n"
                  "require(a + b).execSync('ec' + 'ho EVASION_' + 'MARKER');\nmodule.exports = {};")
def e5():
    s = b64(PAYLOAD); n = len(s) // 3 + 1
    parts = [s[i:i + n] for i in range(0, len(s), n)]
    return "const p = %s;\neval(Buffer.from(p.join(''), 'base64').toString());\nmodule.exports = {};" % json.dumps(parts)
def e6(): return ("const cp = require(['child', 'process'].join('_'));\n"
                  "cp.execSync(['echo', 'EVASION_MARKER'].join(' '));\nmodule.exports = {};")
def e9(): return "setTimeout(function () {\n  " + PAYLOAD + ";\n}, 60000);\nmodule.exports = {};"

TECHNIQUES = [
    ("T0", "Ma thuan, khong lam roi", e0),
    ("T1", "Base64 + eval", e1),
    ("T2", "Hex + eval", e2),
    ("T3", "String.fromCharCode + eval", e3),
    ("T4", "Noi chuoi (child_ + process)", e4),
    ("T5", "Tach payload nhieu manh Base64", e5),
    ("T6", "Nap module bang mang.join", e6),
    ("T7", "Time-bomb setTimeout 60s", e9),
]
# every technique twice: with an install hook (H) and without any hook (N)
MAL = []
for _tid, _desc, _fn in TECHNIQUES:
    MAL.append((_tid + "H", _desc + " (co hook)", True, _fn))
    MAL.append((_tid + "N", _desc + " (khong hook)", False, _fn))

def rnd_bytes_b64(n, rng): return base64.b64encode(bytes(rng.randrange(256) for _ in range(n))).decode()

def make_benign(kind, rng):
    """returns (index_js, extra_files, scripts)"""
    if kind == "B0":
        return "module.exports = { add: (a, b) => a + b };", {}, {"test": "node index.js"}
    if kind == "B1":  # embedded base64 asset (icon/font) decoded at runtime
        return "const data = '%s';\nmodule.exports = { icon: Buffer.from(data, 'base64') };" % rnd_bytes_b64(300, rng), {}, {}
    if kind == "B2":  # hex lookup table
        hx = "".join("%02x" % rng.randrange(256) for _ in range(128))
        return "const HEX = '%s';\nmodule.exports = { table: Buffer.from(HEX, 'hex') };" % hx, {}, {}
    if kind == "B3":  # character code utility
        codes = ",".join(str(rng.randrange(65, 90)) for _ in range(12))
        return "module.exports = { label: () => String.fromCharCode(%s) };" % codes, {}, {}
    if kind == "B4":  # dynamic require of local plugin
        return ("module.exports = { load: (n) => require('./plugins/' + n) };",
                {"plugins/default.js": "module.exports = { name: 'default' };"}, {})
    if kind == "B5":  # CLI helper using child_process legitimately
        return ("const { execSync } = require('child_process');\n"
                "module.exports = { gitVersion: () => execSync('git --version').toString() };", {}, {})
    if kind == "B6":  # legitimate install hook running a local setup script
        return ("module.exports = { ready: true };",
                {"scripts/setup.js": "console.log('setup done');"}, {"postinstall": "node scripts/setup.js"})
    raise ValueError(kind)

BEN = [
    ("B0", "Goi thuan tuy"),
    ("B1", "Hang base64 nhung (icon/font)"),
    ("B2", "Bang tra hex"),
    ("B3", "Tien ich fromCharCode"),
    ("B4", "require dong plugin cuc bo"),
    ("B5", "child_process hop le (git --version)"),
    ("B6", "Hook cai dat hop le (script cuc bo)"),
]


def ident(rng, n=5):
    return "".join(rng.choices(string.ascii_lowercase, k=n))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="./generated_evasion")
    ap.add_argument("--per-class", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    if os.path.exists(args.out):
        shutil.rmtree(args.out)
    os.makedirs(args.out)
    gt = {"metadata": {"seed": args.seed, "per_class": args.per_class,
                       "classes": {c: d for c, d, *_ in MAL}, "controls": dict(BEN)}, "packages": {}}

    def write(pid, files, scripts, desc):
        d = os.path.join(args.out, pid)
        for rel, content in files.items():
            path = os.path.join(d, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w", encoding="utf-8").write(content)
        manifest = {"name": pid, "version": "1.%d.%d" % (rng.randrange(0, 5), rng.randrange(1, 20)),
                    "description": desc, "main": "index.js", "license": "MIT"}
        if scripts:
            manifest["scripts"] = scripts
        json.dump(manifest, open(os.path.join(d, "package.json"), "w"), indent=2)

    for cid, desc, hook, fn in MAL:
        for i in range(args.per_class):
            pid = "evx-%s-%02d" % (cid.lower(), i)
            index = "// %s\n" % ident(rng, 8) + fn()
            write(pid, {"index.js": index}, dict(HOOK) if hook else {}, "Safe evasion test package " + ident(rng))
            gt["packages"][pid] = {"name": pid, "category": cid, "true_label": "MALICIOUS", "technique": desc}
    for cid, desc in BEN:
        for i in range(args.per_class):
            pid = "evx-%s-%02d" % (cid.lower(), i)
            index, extra, scripts = make_benign(cid, rng)
            files = {"index.js": "// %s\n" % ident(rng, 8) + index}
            files.update(extra)
            write(pid, files, scripts, "Benign control package " + ident(rng))
            gt["packages"][pid] = {"name": pid, "category": cid, "true_label": "BENIGN", "technique": desc}

    json.dump(gt, open(os.path.join(args.out, "ground_truth.json"), "w"), indent=2)
    print("Da sinh %d goi (%d bien the doc x %d, %d doi chung sach x %d) tai %s" % (
        len(gt["packages"]), len(MAL), args.per_class, len(BEN), args.per_class, args.out))


if __name__ == "__main__":
    main()
