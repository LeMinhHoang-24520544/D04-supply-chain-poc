#!/usr/bin/env python3
"""
benchmark/graph_whatif.py
DEV-only what-if for refined dependency-graph rules, plus a split-leakage check.
Reads package.json files and static_dev.json only. Nothing is executed.

Usage: python3 benchmark/graph_whatif.py
"""

import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from whatif_dev import parts, wl_hooks, wilson_upper  # noqa: E402

HOME = os.path.expanduser("~/d04_real")
CODE_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "registry.npmjs.org", "www.npmjs.com"}
URL_RE = re.compile(r"^(?:git\+)?(?:https?|ssh|git)://(?:[^@/]*@)?([^/:#]+)", re.I)
SHORTHAND_RE = re.compile(r"^(?:github|gitlab|bitbucket):|^file:|^link:|^workspace:|^portal:|^[\w.-]+/[\w.-]+(?:#.*)?$", re.I)


def classify(spec):
    s = str(spec).strip()
    m = URL_RE.match(s)
    if m:
        return "weak" if m.group(1).lower() in CODE_HOSTS else "strong"
    if SHORTHAND_RE.match(s) or s.endswith((".tgz", ".tar.gz")):
        return "weak"
    return None


def graph_features(pkg_json_path):
    f = {"strong_url": False, "weak_url": False, "self_runtime": False, "self_dev": False, "name": None}
    try:
        m = json.load(open(pkg_json_path, encoding="utf-8"))
    except Exception:
        return f
    name = str(m.get("name", "")).strip()
    f["name"] = name
    runtime = {}
    for k in ("dependencies", "optionalDependencies"):
        if isinstance(m.get(k), dict):
            runtime.update(m[k])
    for spec in runtime.values():
        c = classify(spec)
        if c == "strong":
            f["strong_url"] = True
        elif c == "weak":
            f["weak_url"] = True
    f["self_runtime"] = bool(name) and name in runtime
    for k in ("devDependencies", "peerDependencies"):
        if isinstance(m.get(k), dict) and name in m[k]:
            f["self_dev"] = True
    return f


def main():
    gt = json.load(open(HOME + "/combined/ground_truth.json"))["packages"]
    split = json.load(open(HOME + "/logs/split.json"))
    recs = {r["pkg_id"]: r for r in json.load(open(HOME + "/logs/static_dev.json"))}
    if any(r.get("split") != "dev" for r in recs.values()):
        sys.exit("static_dev.json chua ban ghi TEST.")

    feats = {p: graph_features("%s/combined/%s/package.json" % (HOME, p)) for p in gt}

    # --- 1) Leakage check: structure only (names + split), no detector results on test ---
    mal_names = defaultdict(set)
    for p, info in gt.items():
        if info["true_label"] == "MALICIOUS" and feats[p]["name"]:
            mal_names[feats[p]["name"]].add(split[p])
    mal_pkgs = [p for p, i in gt.items() if i["true_label"] == "MALICIOUS"]
    dup_names = sum(1 for n in mal_names.values() if len(n) >= 1)
    both = sum(1 for s in mal_names.values() if s == {"dev", "test"})
    name_count = Counter(feats[p]["name"] for p in mal_pkgs)
    in_dup_group = sum(1 for p in mal_pkgs if name_count[feats[p]["name"]] > 1)
    print("== Kiem tra ro ri dev/test (chi dung ten goi va nhan chia) ==")
    print("  goi doc: %d, ten khac nhau: %d, ten xuat hien > 1 lan: %d goi" % (len(mal_pkgs), len(mal_names), in_dup_group))
    print("  ten goi doc nam o CA HAI nua dev va test: %d / %d ten" % (both, len(mal_names)))

    # --- 2) Feature counts on dev ---
    dev = [p for p in recs]
    print("\n== Dac trung do thi tren DEV (doc / sach) ==")
    for key in ("strong_url", "weak_url", "self_runtime", "self_dev"):
        mal = sum(1 for p in dev if feats[p][key] and recs[p]["ground_truth"] == "MALICIOUS")
        ben = sum(1 for p in dev if feats[p][key] and recs[p]["ground_truth"] == "BENIGN")
        print("  %-14s doc %3d | sach %3d" % (key, mal, ben))

    # --- 3) Policies ---
    def wl(r):
        m, g, i, l2 = parts(r)
        return max(0, m - 40 * wl_hooks(r)), i, l2

    def v5(r):
        m, i, l2 = wl(r)
        return m + i + (l2 if (m >= 40 or i > 0) else 0)

    def v8(r, self_pts):
        f = feats[r["pkg_id"]]
        m, i, l2 = wl(r)
        extra = (40 if f["strong_url"] else 0) + (self_pts if f["self_runtime"] else 0)
        gate = m >= 40 or i > 0 or f["strong_url"]
        return m + i + extra + (l2 if gate else 0)

    pol = [
        ("V0 hien tai", lambda r: sum(parts(r))),
        ("V5 (bo do thi, L2 co cong)", v5),
        ("V8 = V5 + URL la(+40) + tu-phu-thuoc runtime(+20)", lambda r: v8(r, 20)),
        ("V9 = V5 + URL la(+40)", lambda r: v8(r, 0)),
    ]
    print("\n== Chinh sach tren DEV, nguong 35 ==")
    print("%-52s %5s %5s %5s %5s %4s %4s  %s" % ("chinh sach", "P", "R", "F1", "FPR", "TP", "FP", "FPR tren 95%"))
    for name, fn in pol:
        tp = fp = tn = fn_ = 0
        for r in recs.values():
            mal = r["ground_truth"] == "MALICIOUS"
            f = fn(r) >= 35
            tp += mal and f
            fp += (not mal) and f
            tn += (not mal) and (not f)
            fn_ += mal and (not f)
        p = tp / (tp + fp) if tp + fp else 0
        rc = tp / (tp + fn_) if tp + fn_ else 0
        f1 = 2 * p * rc / (p + rc) if p + rc else 0
        print("%-52s %5.1f %5.1f %5.1f %5.1f %4d %4d  %.1f%%" % (
            name, p * 100, rc * 100, f1 * 100, fp / (fp + tn) * 100, tp, fp, wilson_upper(fp, fp + tn) * 100))


if __name__ == "__main__":
    main()
