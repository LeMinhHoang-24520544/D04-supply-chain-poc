#!/usr/bin/env python3
"""
benchmark/bench_real.py
Static-only benchmark of scripts/detector.py on the real npm corpus (dev/test split).

SAFETY: Layer 3 (sandbox) is disabled on purpose. The corpus contains real malware
samples, which must only be read, never executed. Any attempt to spawn a process
from the detector raises an error.

Discipline: the TEST half is scanned and reported only with --final.
Tune rules on dev, then run --final once.

Usage (inside the isolated VM):
  python3 benchmark/bench_real.py --part dev
  python3 benchmark/bench_real.py --part all --final
"""

import argparse
import csv
import json
import math
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import detector as D  # noqa: E402


def _blocked(*args, **kwargs):
    raise RuntimeError("bench_real.py: spawning processes is blocked (static-only benchmark)")


# Disable Layer 3 and block any process creation from the detector.
D.SupplyChainDetector.analyze_behavioral_sandbox = lambda self, pkg_dir, manifest: (0, [])
D.SupplyChainDetector._run_node_sandbox = _blocked
D.subprocess.run = _blocked
D.subprocess.Popen = _blocked


def metrics(records, score_fn, thr):
    tp = fp = tn = fn = 0
    for r in records:
        mal = r["ground_truth"] == "MALICIOUS"
        flag = score_fn(r) >= thr
        tp += mal and flag
        fp += (not mal) and flag
        tn += (not mal) and (not flag)
        fn += mal and (not flag)
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": p, "recall": rc, "f1": f1, "fpr": fpr}


def wilson_upper(k, n, z=1.96):
    if n == 0:
        return 0.0
    ph = k / n
    denom = 1 + z * z / n
    center = ph + z * z / (2 * n)
    margin = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n))
    return (center + margin) / denom


def ls(r, key):
    return r.get("layer_scores", {}).get(key, 0)


CONFIGS = [
    ("Ca hai lop tinh (L1+L2)", lambda r: r.get("risk_score", 0)),
    ("Chi Layer 1 (tong)", lambda r: ls(r, "layer_1_manifest")),
    ("  L1 manifest", lambda r: ls(r, "layer_1_manifest") - ls(r, "layer_1_dependency_graph") - ls(r, "layer_1_integrity")),
    ("  L1 do thi phu thuoc", lambda r: ls(r, "layer_1_dependency_graph")),
    ("Chi Layer 2", lambda r: ls(r, "layer_2_source")),
]


def fmt(m):
    return "P=%5.1f R=%5.1f F1=%5.1f FPR=%5.1f  TP%3d FP%3d TN%3d FN%3d" % (
        m["precision"] * 100, m["recall"] * 100, m["f1"] * 100, m["fpr"] * 100, m["tp"], m["fp"], m["tn"], m["fn"])


def report(name, recs, thr):
    nb = sum(1 for r in recs if r["ground_truth"] == "BENIGN")
    nm = len(recs) - nb
    print("\n" + "=" * 78)
    print(" %s: %d goi (doc %d, sach %d), nguong %d, ERROR %d" % (
        name, len(recs), nm, nb, thr, sum(1 for r in recs if r.get("verdict") == "ERROR")))
    print("=" * 78)
    for label, fn in CONFIGS:
        print("  %-26s %s" % (label, fmt(metrics(recs, fn, thr))))
    full = metrics(recs, CONFIGS[0][1], thr)
    print("  FPR 95%% can tren (Wilson): %.2f%%  (FP=%d tren %d goi sach)" % (
        wilson_upper(full["fp"], full["fp"] + full["tn"]) * 100, full["fp"], full["fp"] + full["tn"]))
    print("\n  Quet nguong (ca hai lop tinh):")
    for t in (15, 25, 35, 45, 60, 80):
        print("   thr=%3d  %s" % (t, fmt(metrics(recs, CONFIGS[0][1], t))))
    print("\n  Ty le theo loai (nguong %d):" % thr)
    cats = sorted({r["category"] for r in recs})
    for c in cats:
        rs = [r for r in recs if r["category"] == c]
        flagged = sum(1 for r in rs if r.get("risk_score", 0) >= thr)
        label = "bi bao" if c != "benign" else "bi bao NHAM"
        print("   %-20s %4d goi, %s: %d (%.1f%%)" % (c, len(rs), label, flagged, flagged / len(rs) * 100))
    lat = [r["latency_ms"] for r in recs if "latency_ms" in r]
    if lat:
        lat_sorted = sorted(lat)
        print("\n  Do tre quet: trung binh %.0f ms, trung vi %.0f ms, p95 %.0f ms/goi" % (
            statistics.mean(lat), statistics.median(lat), lat_sorted[int(0.95 * (len(lat) - 1))]))


def export_lists(recs, outdir, tag):
    for kind, want_mal in (("fp", False), ("fn", True)):
        path = os.path.join(outdir, "%s_%s.csv" % (kind, tag))
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["pkg_id", "name", "version", "category", "score", "L1", "L2", "rules", "hook_cmd"])
            for r in recs:
                mal = r["ground_truth"] == "MALICIOUS"
                flag = r.get("risk_score", 0) >= r["threshold"]
                if (kind == "fp" and not mal and flag) or (kind == "fn" and mal and not flag):
                    hook = ""
                    if kind == "fp":  # only clean packages: safe to share hook commands
                        for x in r["rules"]:
                            if x["rule"].startswith("Suspicious Lifecycle Hook"):
                                hook = x["detail"].split("command:", 1)[-1].strip()[:200]
                    w.writerow([r["pkg_id"], r.get("package_name"), r.get("version"), r["category"],
                                r.get("risk_score", 0), ls(r, "layer_1_manifest"), ls(r, "layer_2_source"),
                                ";".join(sorted({x["rule"] for x in r["rules"]})), hook])
        print("  Da ghi", path)


def main():
    ap = argparse.ArgumentParser(description="Static-only benchmark on real dataset (dev/test)")
    home = os.path.expanduser("~/d04_real")
    ap.add_argument("--dataset", default=home + "/combined")
    ap.add_argument("--split", default=home + "/logs/split.json")
    ap.add_argument("--out-dir", default=home + "/logs")
    ap.add_argument("--part", choices=["dev", "test", "all"], default="dev")
    ap.add_argument("--final", action="store_true", help="allow scanning/reporting the TEST half")
    ap.add_argument("--threshold", type=int, default=35)
    ap.add_argument("--limit", type=int, default=0, help="scan only the first N packages (smoke test)")
    ap.add_argument("--keep-test-dupes", action="store_true",
                    help="do NOT drop malicious test packages that share a name with a dev package")
    ap.add_argument("--tag", default="static")
    args = ap.parse_args()

    if args.part in ("test", "all") and not args.final:
        sys.exit("Refusing to touch the TEST half without --final. Tune on dev first.")

    gt = json.load(open(os.path.join(args.dataset, "ground_truth.json")))["packages"]
    split = json.load(open(args.split))
    pids = sorted(p for p in gt if p in split and (args.part == "all" or split[p] == args.part))
    if args.part in ("test", "all") and not args.keep_test_dupes:
        # Leakage control: drop malicious TEST packages whose name also occurs in DEV
        # (other versions of the same package are near-duplicates of what was tuned on).
        def pkg_name(pid):
            try:
                return json.load(open(os.path.join(args.dataset, pid, "package.json"), encoding="utf-8")).get("name")
            except Exception:
                return None
        dev_mal_names = {pkg_name(p) for p in gt if split.get(p) == "dev" and gt[p]["true_label"] == "MALICIOUS"}
        dev_mal_names.discard(None)
        dropped = [p for p in pids if split[p] == "test" and gt[p]["true_label"] == "MALICIOUS"
                   and pkg_name(p) in dev_mal_names]
        pids = [p for p in pids if p not in set(dropped)]
        print("Loai %d goi doc o TEST trung ten voi goi o DEV (chong ro ri)." % len(dropped), flush=True)
    if args.limit:
        pids = pids[:args.limit]
    os.makedirs(args.out_dir, exist_ok=True)

    det = D.SupplyChainDetector(enable_whitelist=True, risk_threshold=args.threshold)
    print("Quet %d goi (part=%s, tinh, KHONG Layer 3) ..." % (len(pids), args.part), flush=True)
    recs = []
    t0 = time.perf_counter()
    for i, pid in enumerate(pids, 1):
        ts = time.perf_counter()
        try:
            res = det.scan_package(os.path.join(args.dataset, pid))
        except Exception as e:  # keep going; count as ERROR
            res = {"verdict": "ERROR", "risk_score": 0, "error": str(e), "findings": []}
        rec = {
            "pkg_id": pid, "split": split[pid], "ground_truth": gt[pid]["true_label"],
            "category": gt[pid]["category"], "threshold": args.threshold,
            "package_name": res.get("package_name"), "version": res.get("version"),
            "verdict": res.get("verdict"), "risk_score": res.get("risk_score", 0),
            "layer_scores": res.get("layer_scores", {}),
            "latency_ms": round((time.perf_counter() - ts) * 1000, 1),
            "rules": [{"rule": f["rule"], "sev": f["severity"], "detail": f["detail"][:200]}
                      for f in res.get("findings", []) if f["severity"] != "INFO"],
        }
        recs.append(rec)
        if i % 100 == 0 or i == len(pids):
            el = time.perf_counter() - t0
            print("  %d/%d  da %.0fs, con ~%.0fs" % (i, len(pids), el, el / i * (len(pids) - i)), flush=True)

    out = os.path.join(args.out_dir, "%s_%s.json" % (args.tag, args.part))
    json.dump(recs, open(out, "w"))
    print("Da ghi", out)

    dev = [r for r in recs if r["split"] == "dev"]
    test = [r for r in recs if r["split"] == "test"]
    if dev:
        report("DEV", dev, args.threshold)
        export_lists(dev, args.out_dir, args.tag + "_dev")
    if test:
        report("TEST (bao cao cuoi)", test, args.threshold)


if __name__ == "__main__":
    main()
