#!/usr/bin/env python3
"""
benchmark/evasion/run_evasion.py
Runs scripts/detector.py on the controlled evasion dataset (SAFE payloads only) and prints,
per variant: detection rate with static layers (L1+L2) and with all layers (L1+L2+L3),
and which layers observed the sample. Benign controls report the false-positive rate.

Layer 3 executes the packages inside the sandbox harness: ONLY use it on this synthetic safe
dataset, never on real malware. Use --static-only to disable Layer 3.

Usage:
  python benchmark/evasion/gen_evasion.py --out ./generated_evasion
  python benchmark/evasion/run_evasion.py --dataset ./generated_evasion --label v1
  python benchmark/evasion/run_evasion.py --compare logs/evasion_before.json logs/evasion_after.json
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "scripts"))
import detector as D  # noqa: E402


def l3_of(r):
    return r.get("layer_scores", {}).get("layer_3_behavioral", 0)


def layers_seen(r):
    ls = r.get("layer_scores", {})
    seen = []
    if ls.get("layer_1_manifest", 0) > 0:
        seen.append("L1")
    if ls.get("layer_2_source", 0) > 0:
        seen.append("L2")
    if ls.get("layer_3_behavioral", 0) > 0:
        seen.append("L3")
    return "+".join(seen) or "-"


def run(args):
    gt = json.load(open(os.path.join(args.dataset, "ground_truth.json")))
    pk = gt["packages"]
    if args.static_only:
        D.SupplyChainDetector.analyze_behavioral_sandbox = lambda self, *args, **kwargs: (0, [])
    det = D.SupplyChainDetector(enable_whitelist=True, risk_threshold=args.threshold)
    rows = []
    t0 = time.perf_counter()
    for i, pid in enumerate(sorted(pk), 1):
        ts = time.perf_counter()
        r = det.scan_package(os.path.join(args.dataset, pid))
        risk = r.get("risk_score", 0)
        rows.append({"pkg_id": pid, "category": pk[pid]["category"], "label": pk[pid]["true_label"],
                     "technique": pk[pid]["technique"], "risk": risk, "static_score": risk - l3_of(r),
                     "layers": layers_seen(r), "latency_ms": (time.perf_counter() - ts) * 1000})
        if i % 50 == 0:
            print("  %d/%d (%.0fs)" % (i, len(pk), time.perf_counter() - t0), flush=True)
    out = {"label": args.label, "threshold": args.threshold, "static_only": args.static_only, "rows": rows}
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    json.dump(out, open(args.out, "w"), indent=1)
    print("Da ghi", args.out)
    return out


def summarize(out):
    thr = out["threshold"]
    by = defaultdict(list)
    for r in out["rows"]:
        by[r["category"]].append(r)
    table = []
    for cat in sorted(by):
        rs = by[cat]
        n = len(rs)
        st = sum(1 for r in rs if r["static_score"] >= thr)
        fu = sum(1 for r in rs if r["risk"] >= thr)
        layers = defaultdict(int)
        for r in rs:
            layers[r["layers"]] += 1
        top = max(layers.items(), key=lambda kv: kv[1])[0]
        table.append({"cat": cat, "label": rs[0]["label"], "tech": rs[0]["technique"], "n": n,
                      "static": st / n * 100, "full": fu / n * 100, "layers": top,
                      "lat": sum(r["latency_ms"] for r in rs) / n})
    return table


def print_table(out):
    print("\n== %s (nguong %d, static_only=%s) ==" % (out["label"], out["threshold"], out["static_only"]))
    print("%-4s %-9s %-38s %3s %9s %9s  %-8s %7s" % ("ma", "nhan", "ky thuat", "n", "tinh L1+2", "ca 3 lop", "lop thay", "ms/goi"))
    for t in summarize(out):
        tag = "DOC: bi bat" if t["label"] == "MALICIOUS" else "SACH: bi bao"
        print("%-4s %-9s %-38s %3d %8.0f%% %8.0f%%  %-8s %7.0f   <- %s" % (
            t["cat"], t["label"][:3], t["tech"][:38], t["n"], t["static"], t["full"], t["layers"], t["lat"], tag))


def compare(a_path, b_path):
    a, b = json.load(open(a_path)), json.load(open(b_path))
    ta = {t["cat"]: t for t in summarize(a)}
    tb = {t["cat"]: t for t in summarize(b)}
    print("\n== SO SANH: %s -> %s (ty le bi bat/bao, %%) ==" % (a["label"], b["label"]))
    print("%-4s %-9s %-38s %12s %12s" % ("ma", "nhan", "ky thuat", "tinh truoc>sau", "ca3 truoc>sau"))
    for cat in sorted(ta):
        x, y = ta[cat], tb.get(cat)
        if not y:
            continue
        print("%-4s %-9s %-38s %5.0f -> %-4.0f %5.0f -> %-4.0f" % (
            cat, x["label"][:3], x["tech"][:38], x["static"], y["static"], x["full"], y["full"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="./generated_evasion")
    ap.add_argument("--label", default="run")
    ap.add_argument("--out", default=None)
    ap.add_argument("--threshold", type=int, default=35)
    ap.add_argument("--static-only", action="store_true")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    args = ap.parse_args()
    if args.compare:
        compare(*args.compare)
        return
    args.out = args.out or "./logs/evasion_%s.json" % args.label
    print_table(run(args))


if __name__ == "__main__":
    main()
