#!/usr/bin/env python3
"""
benchmark/bench_hook_benign.py
Independent stress-test ("Test 2") measuring False Positive Rate (FPR) of the frozen
detector (scripts/detector.py) on popular npm packages that ACTUALLY declare an
install lifecycle hook (preinstall / install / postinstall).

Motivation: Only 1.4% (7/500) of the original popularity-sampled benign corpus has
an install hook, whereas Layer 1's primary high-weight rule targets lifecycle hooks.
This script collects a fresh, unseen set of popular hook-bearing packages (native
addons, prebuilt binary wrappers, CLI tools) and evaluates the frozen detector ONCE
in static-only mode (Layer 3 and all subprocess creation are hard-blocked).

Usage:
  python benchmark/bench_hook_benign.py --target 100
"""

import argparse
import csv
import io
import json
import math
import os
import shutil
import statistics
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import detector as D  # noqa: E402

HOOK_KEYS = ("preinstall", "install", "postinstall")
SEARCH_KEYWORDS = [
    "node-gyp",
    "prebuild",
    "prebuild-install",
    "node-pre-gyp",
    "napi",
    "node-addon-api",
    "native-addon",
    "bindings",
    "sqlite",
    "canvas",
    "ffi",
    "binary",
    "postinstall",
    "electron",
    "puppeteer",
    "esbuild",
    "sharp",
    "rust",
    "gyp",
    "c++",
    "cmake",
    "addon",
    "openssl",
    "zlib",
    "audio",
    "usb",
    "serialport",
    "crypto",
    "wasm",
    "cli",
]
MAX_TARBALL_BYTES = 20 * 1024 * 1024


def _blocked(*args, **kwargs):
    raise RuntimeError("bench_hook_benign.py: spawning processes is blocked (static-only)")


def _disable_l3():
    D.SupplyChainDetector.analyze_behavioral_sandbox = lambda self, *args, **kwargs: (0, [])
    D.SupplyChainDetector._run_node_sandbox = _blocked
    D.subprocess.run = _blocked
    D.subprocess.Popen = _blocked


def wilson_ci(k: int, n: int, z: float = 1.96):
    if n == 0:
        return 0.0, 0.0
    ph = k / n
    denom = 1 + z * z / n
    center = ph + z * z / (2 * n)
    margin = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n))
    return max(0.0, (center - margin) / denom), min(1.0, (center + margin) / denom)


def http_get(url: str, tries: int = 3, timeout: int = 20):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nt230-d04-hook-stress/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(MAX_TARBALL_BYTES + 1)
        except Exception:
            time.sleep(1.5 * (i + 1))
    return None


def gather_candidates(max_candidates: int = 1200):
    cands = {}
    for kw in SEARCH_KEYWORDS:
        q = urllib.parse.urlencode({
            "text": kw,
            "popularity": "1.0",
            "quality": "0.2",
            "maintenance": "0.0",
            "size": 100,
            "from": 0,
        })
        raw = http_get("https://registry.npmjs.org/-/v1/search?" + q)
        if raw:
            try:
                for obj in json.loads(raw).get("objects", []):
                    pkg = obj.get("package", {})
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    if name and ver and name not in cands:
                        cands[name] = ver
            except Exception:
                pass
        if len(cands) >= max_candidates:
            break
    return list(cands.items())


def check_has_hook_via_metadata(item):
    """Lightweight metadata check via npm registry packument for latest version."""
    name, ver = item
    encoded = name.replace("/", "%2f")
    # Fetch specific version metadata (much smaller than full packument)
    raw = http_get(f"https://registry.npmjs.org/{encoded}/{urllib.parse.quote(ver, safe='')}", tries=2, timeout=12)
    if not raw:
        return None
    try:
        meta = json.loads(raw)
        scripts = meta.get("scripts")
        if not isinstance(scripts, dict):
            return None
        active = {h: str(scripts[h]).strip() for h in HOOK_KEYS if h in scripts and str(scripts[h]).strip()}
        if not active:
            return None
        tarball_url = (meta.get("dist") or {}).get("tarball")
        if not tarball_url:
            return None
        return (name, ver, tarball_url, active)
    except Exception:
        return None


def download_and_extract(entry, work_dir):
    name, ver, tarball_url, active_hooks = entry
    data = http_get(tarball_url, tries=2, timeout=25)
    if not data or len(data) > MAX_TARBALL_BYTES:
        return None
    safe_dir = name.replace("@", "").replace("/", "__") + "__" + ver.replace("/", "_")
    out_dir = os.path.join(work_dir, safe_dir)
    os.makedirs(out_dir, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = []
            for m in tf.getmembers():
                if not (m.isfile() or m.isdir()):
                    continue
                norm = (m.name or "").replace("\\", "/")
                if norm.startswith("/") or ".." in norm.split("/"):
                    continue
                members.append(m)
            tf.extractall(out_dir, members=members)
        pkg_root = os.path.join(out_dir, "package")
        if not os.path.isfile(os.path.join(pkg_root, "package.json")):
            shutil.rmtree(out_dir, ignore_errors=True)
            return None
        return (name, ver, pkg_root, active_hooks)
    except Exception:
        shutil.rmtree(out_dir, ignore_errors=True)
        return None


def main():
    ap = argparse.ArgumentParser(description="Static-only FPR stress test on hook-bearing popular npm packages")
    ap.add_argument("--target", type=int, default=120, help="Number of hook-bearing benign packages to collect")
    ap.add_argument("--threshold", type=int, default=35)
    ap.add_argument("--out-dir", default=os.path.join(HERE, "..", "logs"))
    ap.add_argument("--tag", default="hook_benign_stress", help="Output filename prefix")
    ap.add_argument("--exclude-from", default=None, help="Path to previous JSON whose package names must be excluded (for unseen Test 3)")
    args = ap.parse_args()

    _disable_l3()

    excluded = set()
    if args.exclude_from:
        for path in [p.strip() for p in args.exclude_from.split(",") if p.strip()]:
            if os.path.isfile(path):
                prev = json.load(open(path, encoding="utf-8"))
                excluded.update(r["name"] for r in prev.get("records", []) if "name" in r)
        print(f"[*] Excluding {len(excluded)} previously seen packages", flush=True)

    print(f"[*] Gathering popular npm candidates across {len(SEARCH_KEYWORDS)} native/CLI keywords...", flush=True)
    cands = [(n, v) for n, v in gather_candidates(max_candidates=max(2600, args.target * 26)) if n not in excluded]
    print(f"[+] Candidate pool (after exclusions): {len(cands)} unique packages. Filtering for active install hooks...", flush=True)

    hook_entries = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(check_has_hook_via_metadata, cands):
            if res is not None:
                hook_entries.append(res)
                if len(hook_entries) >= int(args.target * 1.25):
                    break

    print(f"[+] Found {len(hook_entries)} packages with active preinstall/install/postinstall hooks.", flush=True)

    work_dir = tempfile.mkdtemp(prefix="d04_hook_benign_")
    os.makedirs(args.out_dir, exist_ok=True)

    try:
        extracted = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            for res in ex.map(lambda e: download_and_extract(e, work_dir), hook_entries):
                if res is not None:
                    extracted.append(res)
                    if len(extracted) >= args.target:
                        break

        print(f"[+] Successfully downloaded & extracted {len(extracted)} hook-bearing benign packages.", flush=True)
        print("[*] Scanning with frozen SupplyChainDetector (static-only, gated mode, thr=35)...", flush=True)

        det = D.SupplyChainDetector(enable_whitelist=True, risk_threshold=args.threshold, always_scan_l2=False)
        recs = []
        t0 = time.perf_counter()
        for idx, (name, ver, pkg_root, active_hooks) in enumerate(extracted, 1):
            ts = time.perf_counter()
            try:
                res = det.scan_package(pkg_root)
            except Exception as exc:
                res = {"verdict": "ERROR", "risk_score": 0, "error": str(exc), "findings": [], "layer_scores": {}}
            lat_ms = round((time.perf_counter() - ts) * 1000, 1)
            ls = res.get("layer_scores", {})
            findings = res.get("findings", [])
            whitelisted = any(f.get("rule", "").startswith("Whitelisted Hook:") for f in findings)
            banner_low = any(
                f.get("rule", "").startswith("Suspicious Lifecycle Hook:") and f.get("severity") == "LOW"
                for f in findings
            )
            gh_rel_med = any(
                f.get("rule", "").startswith("Suspicious Lifecycle Hook:") and f.get("severity") == "MEDIUM"
                for f in findings
            )
            recs.append({
                "name": name,
                "version": ver,
                "hooks": active_hooks,
                "verdict": res.get("verdict"),
                "risk_score": res.get("risk_score", 0),
                "l1_total": ls.get("layer_1_manifest", 0),
                "l1_graph": ls.get("layer_1_dependency_graph", 0),
                "l2_source": ls.get("layer_2_source", 0),
                "whitelisted": whitelisted,
                "banner_low": banner_low,
                "gh_release_med": gh_rel_med,
                "latency_ms": lat_ms,
                "rules": sorted({f["rule"] for f in findings if f.get("severity") != "INFO"}),
            })
            if idx % 25 == 0 or idx == len(extracted):
                print(f"    {idx}/{len(extracted)} ({time.perf_counter() - t0:.1f}s)", flush=True)

        n = len(recs)
        print("\n" + "=" * 78)
        print(f" HOOK-BEARING BENIGN STRESS TEST (Test 2): {n} packages (100% have install hook)")
        print("=" * 78)

        wl_cnt = sum(1 for r in recs if r["whitelisted"])
        ban_cnt = sum(1 for r in recs if r["banner_low"])
        gh_cnt = sum(1 for r in recs if r["gh_release_med"])
        print(f"  Hook disposition : Whitelisted={wl_cnt} ({wl_cnt/n*100:.1f}%), "
              f"Benign-banner(+15)={ban_cnt} ({ban_cnt/n*100:.1f}%), "
              f"GitHub-release(+15)={gh_cnt} ({gh_cnt/n*100:.1f}%)")

        for thr in (15, 25, 35, 45, 60, 80):
            fp = sum(1 for r in recs if r["risk_score"] >= thr)
            lo, hi = wilson_ci(fp, n)
            print(f"  thr={thr:3d}  FP={fp:3d}/{n}  FPR={fp/n*100:5.1f}%  (Wilson 95% CI: {lo*100:4.1f}% - {hi*100:4.1f}%)")

        fp35 = [r for r in recs if r["risk_score"] >= args.threshold]
        l1_only_fp = sum(1 for r in recs if r["l1_total"] >= args.threshold)
        l2_only_fp = sum(1 for r in recs if r["l2_source"] >= args.threshold)
        print(f"\n  Layer breakdown at thr={args.threshold}: L1>=35: {l1_only_fp}/{n} ({l1_only_fp/n*100:.1f}%), "
              f"L2(post-gate)>=35: {l2_only_fp}/{n} ({l2_only_fp/n*100:.1f}%)")

        rule_counts = Counter(rule for r in fp35 for rule in r["rules"])
        print(f"\n  Top rules on {len(fp35)} FPs (thr={args.threshold}):")
        for rule, cnt in rule_counts.most_common(12):
            print(f"    {cnt:4d}  {rule}")

        hook_cmd_counts = Counter()
        for r in fp35:
            for h, cmd in r["hooks"].items():
                tok = cmd.strip().split()[0] if cmd.strip() else ""
                hook_cmd_counts[f"{h}: {tok}"] += 1
        print("\n  Top hook command prefixes among FPs:")
        for k, cnt in hook_cmd_counts.most_common(10):
            print(f"    {cnt:4d}  {k}")

        lats = sorted(r["latency_ms"] for r in recs)
        if lats:
            print(f"\n  Latency: mean {statistics.mean(lats):.0f} ms, median {statistics.median(lats):.0f} ms, "
                  f"p95 {lats[int(0.95*(len(lats)-1))]:.0f} ms/pkg")

        json_out = os.path.join(args.out_dir, f"{args.tag}.json")
        with open(json_out, "w", encoding="utf-8") as jf:
            json.dump({"n": n, "threshold": args.threshold, "records": recs}, jf, indent=2)

        csv_out = os.path.join(args.out_dir, f"{args.tag}_fp.csv")
        with open(csv_out, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            w.writerow(["name", "version", "risk_score", "l1_total", "l1_graph", "l2_source", "hooks", "rules"])
            for r in fp35:
                w.writerow([
                    r["name"], r["version"], r["risk_score"], r["l1_total"], r["l1_graph"], r["l2_source"],
                    "; ".join(f"{k}={v[:100]}" for k, v in r["hooks"].items()),
                    ";".join(r["rules"]),
                ])
        print(f"\n  Saved: {json_out}")
        print(f"  Saved: {csv_out}")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
