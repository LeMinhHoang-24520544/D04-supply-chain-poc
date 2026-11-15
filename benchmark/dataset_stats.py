#!/usr/bin/env python3
"""
benchmark/dataset_stats.py
Descriptive statistics of the real dataset (metadata, install scripts, dependency graph)
for the report. Read-only: parses package.json and walks files, never executes anything.

Usage:
  python3 benchmark/dataset_stats.py            # text table
  python3 benchmark/dataset_stats.py --latex    # also print a LaTeX tabular
"""

import argparse
import json
import os
import re
import statistics

URL_RE = re.compile(r"^(https?://|git\+|git://|ssh://|github:|bitbucket:|gitlab:)", re.I)
HOOKS = ("preinstall", "install", "postinstall")


def pkg_features(d):
    f = {"hook": False, "n_deps": 0, "url_dep": False, "high_ver": False,
         "empty_desc": False, "no_js": True, "n_files": 0, "size": 0, "ok": True}
    try:
        m = json.load(open(os.path.join(d, "package.json"), encoding="utf-8"))
    except Exception:
        f["ok"] = False
        m = {}
    scripts = m.get("scripts") if isinstance(m.get("scripts"), dict) else {}
    f["hook"] = any(h in scripts for h in HOOKS)
    deps = {}
    for k in ("dependencies", "optionalDependencies"):
        if isinstance(m.get(k), dict):
            deps.update(m[k])
    f["n_deps"] = len(deps)
    f["url_dep"] = any(isinstance(v, str) and URL_RE.match(v) for v in deps.values())
    try:
        f["high_ver"] = float(re.split(r"[.-]", str(m.get("version", "0")))[0]) >= 90
    except ValueError:
        pass
    f["empty_desc"] = not str(m.get("description") or "").strip()
    for root, _, files in os.walk(d):
        if "node_modules" in root:
            continue
        for name in files:
            f["n_files"] += 1
            try:
                f["size"] += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
            if name.endswith((".js", ".cjs", ".mjs")):
                f["no_js"] = False
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.expanduser("~/d04_real/combined"))
    ap.add_argument("--latex", action="store_true")
    args = ap.parse_args()

    gt = json.load(open(os.path.join(args.dataset, "ground_truth.json")))["packages"]
    groups = {}
    for pid, info in sorted(gt.items()):
        groups.setdefault(info["category"], []).append(pkg_features(os.path.join(args.dataset, pid)))

    def pct(fs, key):
        return 100.0 * sum(1 for x in fs if x[key]) / len(fs)

    rows = []
    for cat in sorted(groups, key=lambda c: (c != "benign", c)):
        fs = groups[cat]
        rows.append((
            cat, len(fs), pct(fs, "hook"), statistics.mean(x["n_deps"] for x in fs),
            statistics.median(x["n_deps"] for x in fs), pct(fs, "url_dep"), pct(fs, "high_ver"),
            pct(fs, "empty_desc"), pct(fs, "no_js"), statistics.median(x["n_files"] for x in fs),
            statistics.median(x["size"] for x in fs) / 1024.0, sum(1 for x in fs if not x["ok"])))

    head = ["loai", "so goi", "%hook", "dep TB", "dep TV", "%dep URL", "%ver>=90",
            "%mo ta trong", "%khong JS", "file TV", "KB TV", "loi JSON"]
    print("  ".join("%-12s" % h for h in head))
    for r in rows:
        print("  ".join("%-12s" % (("%.1f" % v) if isinstance(v, float) else v) for v in r))

    if args.latex:
        print("\n% --- LaTeX ---")
        print("\\begin{tabular}{lrrrrrrr}\n\\toprule")
        print("Loại & Số gói & Có hook & Phụ thuộc TB & Phụ thuộc URL & Không có JS & Mô tả trống & Số tệp TV \\\\\n\\midrule")
        for r in rows:
            print("\\texttt{%s} & %d & %.1f\\%% & %.1f & %.1f\\%% & %.1f\\%% & %.1f\\%% & %d \\\\" % (
                r[0].replace("_", "\\_"), r[1], r[2], r[3], r[5], r[8], r[7], r[9]))
        print("\\bottomrule\n\\end{tabular}")


if __name__ == "__main__":
    main()
