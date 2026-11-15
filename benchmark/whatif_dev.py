#!/usr/bin/env python3
"""
benchmark/whatif_dev.py
What-if analysis on the DEV half only: re-score existing telemetry (static_dev.json)
under alternative policies, WITHOUT rescanning. Nothing is executed.

Refuses to run if the telemetry contains TEST records.

Usage: python3 benchmark/whatif_dev.py [--file ~/d04_real/logs/static_dev.json]
"""

import argparse
import json
import math
import os
import re
import sys

# Generic, well-known benign hook conventions (candidate whitelist extensions).
WL_EXTRA = [
    re.compile(r"^(npx\s+)?opencollective(-postinstall)?\b", re.I),   # donation-banner hooks
    re.compile(r"^echo\s+[^|;&><`$]*$", re.I),                         # plain echo, no shell metachar
]
HOOK_RE = re.compile(r"Detected active '[^']+' hook with command: (.*)", re.S)


def ls(r, k):
    return r.get("layer_scores", {}).get(k, 0)


def parts(r):
    graph, integ = ls(r, "layer_1_dependency_graph"), ls(r, "layer_1_integrity")
    manifest = ls(r, "layer_1_manifest") - graph - integ
    return manifest, graph, integ, ls(r, "layer_2_source")


def wl_hooks(r):
    n = 0
    for x in r["rules"]:
        if x["rule"].startswith("Suspicious Lifecycle Hook"):
            m = HOOK_RE.search(x["detail"])
            if m and any(p.search(m.group(1).strip()) for p in WL_EXTRA):
                n += 1
    return n


def wilson_upper(k, n, z=1.96):
    if not n:
        return 0.0
    ph = k / n
    d = 1 + z * z / n
    return (ph + z * z / (2 * n) + z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n))) / d


def policies():
    def base(r):
        m, g, i, l2 = parts(r)
        return m + g + i + l2

    def wl(r):
        m, g, i, l2 = parts(r)
        m = max(0, m - 40 * wl_hooks(r))
        return m, g, i, l2

    def p_wl(r):
        m, g, i, l2 = wl(r); return m + g + i + l2

    def p_l1(r):
        m, g, i, l2 = wl(r); return m + g + i

    def p_nograph(r):
        m, g, i, l2 = wl(r); return m + i

    def gate(r, need):
        m, g, i, l2 = wl(r)
        l1 = m + g + i
        return l1 + (l2 if l1 >= need else 0)

    def p_gate_hook(r):
        m, g, i, l2 = wl(r)
        return m + i + (l2 if (m >= 40 or i > 0) else 0)

    def p_l2strong(r, t2):
        m, g, i, l2 = wl(r)
        return m + i + (l2 if l2 >= t2 else 0)

    return [
        ("V0 hien tai (L1+L2)", base),
        ("V1 + 2 whitelist moi", p_wl),
        ("V2 chi L1 (+whitelist)", p_l1),
        ("V3 bo luat do thi (manifest+toan ven)", p_nograph),
        ("V4 L2 chi tinh khi L1>=25", lambda r: gate(r, 25)),
        ("V5 L2 chi tinh khi co hook that/toan ven", p_gate_hook),
        ("V6 L2 chi tinh khi L2>=90 (nhieu luat)", lambda r: p_l2strong(r, 90)),
        ("V7 L2 chi tinh khi L2>=110", lambda r: p_l2strong(r, 110)),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=os.path.expanduser("~/d04_real/logs/static_dev.json"))
    ap.add_argument("--threshold", type=int, default=35)
    args = ap.parse_args()
    recs = json.load(open(args.file))
    if any(r.get("split") != "dev" for r in recs):
        sys.exit("File chua ban ghi TEST. Script nay chi cho phep phan tich nua DEV.")
    nb = sum(1 for r in recs if r["ground_truth"] == "BENIGN")
    nm = len(recs) - nb
    print("DEV: %d goi (doc %d, sach %d), nguong %d\n" % (len(recs), nm, nb, args.threshold))
    print("%-42s %5s %5s %5s %5s  %4s %4s  %s" % ("chinh sach", "P", "R", "F1", "FPR", "TP", "FP", "FPR can tren 95%"))
    for name, fn in policies():
        tp = fp = tn = fn_ = 0
        for r in recs:
            mal = r["ground_truth"] == "MALICIOUS"
            f = fn(r) >= args.threshold
            tp += mal and f
            fp += (not mal) and f
            tn += (not mal) and (not f)
            fn_ += mal and (not f)
        p = tp / (tp + fp) if tp + fp else 0
        rc = tp / (tp + fn_) if tp + fn_ else 0
        f1 = 2 * p * rc / (p + rc) if p + rc else 0
        fpr = fp / (fp + tn) if fp + tn else 0
        print("%-42s %5.1f %5.1f %5.1f %5.1f  %4d %4d  %.1f%%" % (
            name, p * 100, rc * 100, f1 * 100, fpr * 100, tp, fp, wilson_upper(fp, fp + tn) * 100))


if __name__ == "__main__":
    main()
