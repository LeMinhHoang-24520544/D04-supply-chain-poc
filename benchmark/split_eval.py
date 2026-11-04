import csv, json, os, random
from collections import defaultdict

BASE = os.path.expanduser("~/d04_real")
LOG = BASE + "/logs"
S = json.load(open(LOG + "/telemetry_real.json"))["telemetry_stream"]
for r in S:
    r["pid"] = os.path.basename(r["package_path"].rstrip("/"))

# Chia 50/50 co dinh (seed 42), phan tang theo category
groups = defaultdict(list)
for r in S:
    groups[r["category"]].append(r["pid"])
split = {}
for cat, ids in sorted(groups.items()):
    ids.sort()
    random.Random(42).shuffle(ids)
    for i, pid in enumerate(ids):
        split[pid] = "dev" if i % 2 == 0 else "test"
json.dump(split, open(LOG + "/split.json", "w"), indent=1)

def lscore(r, ks):
    return sum(r.get("layer_scores", {}).get(k, 0) for k in ks)

def metrics(rs, pred):
    tp = fp = tn = fn = 0
    for r in rs:
        mal = r["ground_truth"] == "MALICIOUS"
        f = pred(r)
        tp += mal and f
        fp += (not mal) and f
        tn += (not mal) and (not f)
        fn += mal and (not f)
    p = tp / (tp + fp) if tp + fp else 0
    rc = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    return "P=%5.1f R=%5.1f F1=%5.1f FPR=%5.1f  TP%3d FP%3d TN%3d FN%3d" % (p * 100, rc * 100, f1 * 100, fpr * 100, tp, fp, tn, fn)

L1 = ["layer_1_manifest"]
ALL = ["layer_1_manifest", "layer_2_source", "layer_3_behavioral"]
for name in ("dev", "test"):
    rs = [r for r in S if split[r["pid"]] == name]
    print("== %s: %d goi (doc %d, sach %d)" % (name, len(rs), sum(r["ground_truth"] == "MALICIOUS" for r in rs), sum(r["ground_truth"] == "BENIGN" for r in rs)))
    print("  v1 (ca 3 lop, thr35) ", metrics(rs, lambda r: r.get("risk_score", 0) >= 35))
    print("  chi Layer 1 (thr35)  ", metrics(rs, lambda r: lscore(r, L1) >= 35))

def rules(r):
    return ";".join(sorted({f["rule"] for f in r["findings"] if f["severity"] != "INFO"}))

# Chi xuat nua DEV (nua test giu kin de khong ro ri). Khong kem ma cua mau doc.
for kind, cls in (("fp", "FP"), ("fn", "FN")):
    with open("%s/%s_dev.csv" % (LOG, kind), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pkg_id", "name", "version", "category", "score", "L1", "L2", "L3", "rules", "hook_cmd"])
        for r in S:
            if split[r["pid"]] != "dev" or r.get("classification") != cls:
                continue
            ls = r.get("layer_scores", {})
            hook = ""
            if cls == "FP":  # goi sach: an toan de chia se lenh hook
                for x in r["findings"]:
                    if x["rule"].startswith("Suspicious Lifecycle Hook"):
                        hook = x["detail"].split("command:", 1)[-1].strip()[:200]
            w.writerow([r["pid"], r.get("package_name"), r.get("version"), r["category"], r.get("risk_score", 0), ls.get("layer_1_manifest", 0), ls.get("layer_2_source", 0), ls.get("layer_3_behavioral", 0), rules(r), hook])
print("\nDa ghi: split.json, fp_dev.csv, fn_dev.csv trong", LOG)
