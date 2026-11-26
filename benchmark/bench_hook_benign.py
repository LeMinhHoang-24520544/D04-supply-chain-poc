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
import glob
import io
import json
import math
import os
import random
import shutil
import statistics
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import detector as D  # noqa: E402

HOOK_KEYS = ("preinstall", "install", "postinstall")
HOOK_SEARCH_KEYWORDS = [
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
    "preinstall",
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
    "native",
    "swc",
    "playwright",
    "chromium",
    "ffmpeg",
    "imagemagick",
    "leveldb",
    "rocksdb",
    "lmdb",
    "duckdb",
    "libpq",
    "grpc",
    "protobuf",
    "tree-sitter",
    "bcrypt",
    "argon2",
    "kerberos",
    "ldap",
    "pkcs11",
    "smartcard",
    "hid",
    "bluetooth",
    "gpu",
    "webgl",
    "vulkan",
    "llvm",
    "clang",
    "neon",
    "napi-rs",
]
# Backward-compatible alias for any external callers referencing SEARCH_KEYWORDS
SEARCH_KEYWORDS = HOOK_SEARCH_KEYWORDS
GENERAL_SEARCH_KEYWORDS = [
    "framework",
    "cli",
    "typescript",
    "react",
    "vue",
    "svelte",
    "angular",
    "express",
    "fastify",
    "utility",
    "plugin",
    "database",
    "testing",
    "http",
    "async",
    "parser",
    "logger",
    "build",
    "crypto",
    "date",
    "validation",
    "schema",
    "markdown",
    "graphql",
    "webpack",
    "vite",
    "eslint",
    "prettier",
    "css",
    "tailwind",
    "animation",
    "chart",
    "table",
    "form",
    "router",
    "state",
    "cache",
    "queue",
    "stream",
    "file",
    "email",
    "auth",
    "oauth",
    "jwt",
    "metrics",
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
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            delay = 3.0 * (i + 1) if e.code == 429 else 1.5 * (i + 1)
            time.sleep(delay)
        except Exception:
            time.sleep(1.5 * (i + 1))
    return None


def gather_candidates(
    max_candidates: int = 1200,
    keywords=None,
    excluded=None,
    rng=None,
    pages=(0, 250, 500),
):
    """Collect unique package (name, version) pairs across keyword search pages."""
    kw_list = list(keywords) if keywords is not None else list(HOOK_SEARCH_KEYWORDS)
    excluded_set = excluded or set()

    early_queries = [(kw, frm) for frm in pages if frm < 500 for kw in kw_list]
    late_queries = [(kw, frm) for frm in pages if frm >= 500 for kw in kw_list]
    if rng is not None:
        rng.shuffle(early_queries)
        rng.shuffle(late_queries)
    queries = early_queries + late_queries

    cands = {}
    for idx, (kw, frm) in enumerate(queries, 1):
        q = urllib.parse.urlencode({
            "text": kw,
            "popularity": "1.0",
            "quality": "0.2",
            "maintenance": "0.0",
            "size": 250,
            "from": frm,
        })
        raw = http_get("https://registry.npmjs.org/-/v1/search?" + q)
        if raw:
            try:
                for obj in json.loads(raw).get("objects", []):
                    pkg = obj.get("package", {})
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    if name and ver and name not in excluded_set and name not in cands:
                        cands[name] = ver
            except Exception:
                pass
        if idx % 15 == 0:
            print(f"    Search queries: {idx}/{len(queries)} -> {len(cands)} unseen candidates", flush=True)
        if len(cands) >= max_candidates:
            break
        time.sleep(0.2)

    items = list(cands.items())
    if rng is not None:
        rng.shuffle(items)
    return items


def check_has_hook_via_metadata(item, require_hook: bool = True):
    """Lightweight metadata check via npm registry packument for a specific version."""
    name, ver = item
    encoded = name.replace("/", "%2f")
    # Fetch specific version metadata (much smaller than full packument)
    raw = http_get(f"https://registry.npmjs.org/{encoded}/{urllib.parse.quote(ver, safe='')}", tries=2, timeout=12)
    if not raw:
        return None
    try:
        meta = json.loads(raw)
        scripts = meta.get("scripts")
        active = (
            {h: str(scripts[h]).strip() for h in HOOK_KEYS if h in scripts and str(scripts[h]).strip()}
            if isinstance(scripts, dict)
            else {}
        )
        if require_hook and not active:
            return None
        tarball_url = (meta.get("dist") or {}).get("tarball")
        if not tarball_url:
            return None
        return (name, ver, tarball_url, active)
    except Exception:
        return None


def _load_excluded_names(exclude_spec: str) -> set[str]:
    """Load previously seen package names from comma-separated CSV/JSON paths or globs."""
    excluded = set()
    if not exclude_spec:
        return excluded
    for raw_tok in exclude_spec.split(","):
        tok = raw_tok.strip()
        if not tok:
            continue
        expanded = os.path.expanduser(tok)
        matched = sorted(glob.glob(expanded))
        paths = matched if matched else [expanded]
        for path in paths:
            if not os.path.isfile(path):
                continue
            if path.lower().endswith(".csv"):
                try:
                    with open(path, encoding="utf-8", errors="replace", newline="") as cf:
                        for row in csv.DictReader(cf):
                            name = (row.get("name") or "").strip()
                            if name:
                                excluded.add(name)
                except OSError:
                    pass
            else:
                try:
                    with open(path, encoding="utf-8") as jf:
                        prev = json.load(jf)
                    for r in prev.get("records", []):
                        if isinstance(r, dict) and r.get("name"):
                            excluded.add(str(r["name"]))
                except (OSError, ValueError):
                    pass
    return excluded


def download_and_extract(entry, work_dir, cache_dir=None):
    name, ver, tarball_url, active_hooks = entry
    safe_dir = name.replace("@", "").replace("/", "__") + "__" + ver.replace("/", "_")
    data = None
    tgz_cache_path = os.path.join(cache_dir, safe_dir + ".tgz") if cache_dir else None
    meta_cache_path = os.path.join(cache_dir, safe_dir + ".meta.json") if cache_dir else None
    if tgz_cache_path and os.path.isfile(tgz_cache_path):
        try:
            with open(tgz_cache_path, "rb") as cf:
                data = cf.read(MAX_TARBALL_BYTES + 1)
        except OSError:
            data = None
    if data is None and tarball_url:
        data = http_get(tarball_url, tries=2, timeout=25)
        if data and len(data) <= MAX_TARBALL_BYTES and tgz_cache_path and meta_cache_path:
            os.makedirs(cache_dir, exist_ok=True)
            try:
                with open(tgz_cache_path, "wb") as tf_out:
                    tf_out.write(data)
                with open(meta_cache_path, "w", encoding="utf-8") as mf_out:
                    json.dump({"name": name, "version": ver, "tarball": tarball_url, "hooks": active_hooks}, mf_out)
            except OSError:
                pass
    if not data or len(data) > MAX_TARBALL_BYTES:
        return None
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
    ap = argparse.ArgumentParser(description="Static-only FPR benchmark on popular/random benign npm packages")
    ap.add_argument("--target", type=int, default=120, help="Number of benign packages to collect")
    ap.add_argument("--threshold", type=int, default=35)
    ap.add_argument("--out-dir", default=os.path.join(HERE, "..", "logs"))
    ap.add_argument("--tag", default="hook_benign_stress", help="Output filename prefix")
    ap.add_argument("--exclude-from", default=None, help="Comma-separated JSON/CSV paths or globs of previously seen packages to exclude")
    ap.add_argument("--cache-dir", default=None, help="Optional directory to cache downloaded tarballs for offline deterministic replay")
    ap.add_argument("--packages-file", default=None, help="Optional JSON file with records[{name,version,hooks}] to replay exact versions")
    ap.add_argument("--random", action="store_true", help="Shuffle search queries and candidate pool with a random seed")
    ap.add_argument("--seed", type=int, default=None, help="Explicit integer RNG seed (implies randomized sampling)")
    ap.add_argument("--any-benign", action="store_true", help="Sample general benign npm packages without requiring an active install hook")
    args = ap.parse_args()

    _disable_l3()

    used_seed = args.seed
    if args.random and used_seed is None:
        used_seed = random.SystemRandom().randint(1, 2_147_483_647)
    rng = random.Random(used_seed) if used_seed is not None else None
    if rng is not None:
        print(f"[*] Randomized sampling enabled (seed={used_seed})", flush=True)

    excluded = _load_excluded_names(args.exclude_from)
    if args.exclude_from:
        print(f"[*] Excluding {len(excluded)} previously seen packages", flush=True)

    hook_entries = []
    if args.packages_file:
        with open(args.packages_file, encoding="utf-8") as pf:
            replay_data = json.load(pf)
        replay_recs = replay_data.get("records", [])
        target_count = len(replay_recs)
        replay_cands = []
        for rec in replay_recs:
            name, ver = rec["name"], rec["version"]
            safe_dir = name.replace("@", "").replace("/", "__") + "__" + ver.replace("/", "_")
            tgz_p = os.path.join(args.cache_dir, safe_dir + ".tgz") if args.cache_dir else None
            if tgz_p and os.path.isfile(tgz_p):
                hook_entries.append((name, ver, "", rec.get("hooks", {})))
            else:
                replay_cands.append((name, ver))
        if replay_cands:
            replay_require_hook = not (args.any_benign or replay_data.get("mode") == "any_benign")
            with ThreadPoolExecutor(max_workers=8) as ex:
                for res in ex.map(lambda it: check_has_hook_via_metadata(it, require_hook=replay_require_hook), replay_cands):
                    if res is not None:
                        hook_entries.append(res)
        print(f"[+] Loaded {len(hook_entries)} replay entries from {args.packages_file}", flush=True)
    else:
        target_count = args.target
        keywords = GENERAL_SEARCH_KEYWORDS if args.any_benign else HOOK_SEARCH_KEYWORDS
        max_candidates = max(1000, args.target * 4) if args.any_benign else max(5000, args.target * 35)
        mode_desc = "broad npm ecosystem" if args.any_benign else "native/CLI"
        print(f"[*] Gathering {mode_desc} npm candidates across {len(keywords)} keywords...", flush=True)
        cands = gather_candidates(
            max_candidates=max_candidates,
            keywords=keywords,
            excluded=excluded,
            rng=rng,
        )
        filter_desc = "Fetching metadata/tarball URLs..." if args.any_benign else "Filtering for active install hooks..."
        print(f"[+] Candidate pool (after exclusions): {len(cands)} unique packages. {filter_desc}", flush=True)

        needed_hits = int(args.target * 1.25) + 10
        require_hook = not args.any_benign
        batch_size = 80
        with ThreadPoolExecutor(max_workers=12) as ex:
            for b_idx, start in enumerate(range(0, len(cands), batch_size), 1):
                batch = cands[start:start + batch_size]
                for res in ex.map(lambda item: check_has_hook_via_metadata(item, require_hook=require_hook), batch):
                    if res is not None:
                        hook_entries.append(res)
                        if len(hook_entries) >= needed_hits:
                            break
                checked = min(start + batch_size, len(cands))
                if b_idx % 3 == 0 or len(hook_entries) >= needed_hits or checked >= len(cands):
                    print(f"    Metadata checked {checked}/{len(cands)} -> {len(hook_entries)} matches", flush=True)
                if len(hook_entries) >= needed_hits:
                    break

        noun = "installable benign packages" if args.any_benign else "packages with active preinstall/install/postinstall hooks"
        print(f"[+] Found {len(hook_entries)} {noun}.", flush=True)

    work_dir = tempfile.mkdtemp(prefix="d04_hook_benign_")
    os.makedirs(args.out_dir, exist_ok=True)

    try:
        extracted = []
        dl_batch_size = 32
        with ThreadPoolExecutor(max_workers=8) as ex:
            for start in range(0, len(hook_entries), dl_batch_size):
                batch = hook_entries[start:start + dl_batch_size]
                for res in ex.map(lambda e: download_and_extract(e, work_dir, cache_dir=args.cache_dir), batch):
                    if res is not None:
                        extracted.append(res)
                        if len(extracted) >= target_count:
                            break
                if len(extracted) >= target_count:
                    break

        label_noun = "benign packages" if args.any_benign else "hook-bearing benign packages"
        print(f"[+] Successfully downloaded & extracted {len(extracted)} {label_noun}.", flush=True)
        print(f"[*] Scanning with frozen SupplyChainDetector (static-only, gated mode, thr={args.threshold})...", flush=True)

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
        if n == 0:
            print("[!] No benign packages collected (0 downloaded/scanned). Check VM NAT/network connectivity and retry.", flush=True)
            sys.exit(1)

        print("\n" + "=" * 78)
        with_hook = sum(1 for r in recs if r["hooks"])
        if args.any_benign:
            print(f" RANDOM BENIGN NPM BENCHMARK: {n} packages ({with_hook}/{n} = {with_hook/n*100:.1f}% have install hook, seed={used_seed})")
        else:
            seed_suffix = f", seed={used_seed}" if used_seed is not None else ""
            print(f" HOOK-BEARING BENIGN STRESS TEST (Test 2): {n} packages (100% have install hook{seed_suffix})")
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
            json.dump(
                {
                    "n": n,
                    "mode": "any_benign" if args.any_benign else "hook_only",
                    "seed": used_seed,
                    "threshold": args.threshold,
                    "records": recs,
                },
                jf,
                indent=2,
            )

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
