import json, os, sys
from collections import Counter

p = os.path.expanduser("~/d04_real/logs/telemetry_real.json")
d = json.load(open(p))
S = d["telemetry_stream"]
print("tong:", len(S), "| ERROR:", sum(1 for r in S if r.get("verdict") == "ERROR"))

def m(pred):
    tp = fp = tn = fn = 0
    for r in S:
        mal = r["ground_truth"] == "MALICIOUS"
        flag = pred(r)
        tp += mal and flag
        fp += (not mal) and flag
        tn += (not mal) and (not flag)
        fn += mal and (not flag)
    pr = tp / (tp + fp) if tp + fp else 0
    rc = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    return "P=%.1f R=%.1f F1=%.1f FPR=%.1f (TP%d FP%d TN%d FN%d)" % (pr * 100, rc * 100, f1 * 100, fpr * 100, tp, fp, tn, fn)

print("\n== Quet nguong risk_score ==")
for t in (5, 15, 25, 35, 45, 50, 60, 70, 90, 120):
    print("thr=%3d  %s" % (t, m(lambda r, t=t: r.get("risk_score", 0) >= t)))

print("\n== Dong gop tung lop (nguong 35) ==")
def ls(r, k): return r.get("layer_scores", {}).get(k, 0)
for name, ks in (("chi L1", ["layer_1_manifest"]), ("chi L2", ["layer_2_source"]), ("chi L3", ["layer_3_behavioral"]), ("L1+L2", ["layer_1_manifest", "layer_2_source"]), ("L1+L2+L3", ["layer_1_manifest", "layer_2_source", "layer_3_behavioral"])):
    print("%-9s %s" % (name, m(lambda r, ks=ks: sum(ls(r, k) for k in ks) >= 35)))

def rules(rs):
    c = Counter()
    for r in rs:
        for x in {f["rule"] for f in r["findings"] if f["severity"] != "INFO"}:
            c[x] += 1
    return c.most_common(8)

fp = [r for r in S if r.get("classification") == "FP"]
fn = [r for r in S if r.get("classification") == "FN"]
tp = [r for r in S if r.get("classification") == "TP"]
print("\n== Luat gay FP (%d goi) ==" % len(fp))
for k, v in rules(fp): print("%4d  %s" % (v, k))
print("\n== Luat bat duoc TP (%d goi) ==" % len(tp))
for k, v in rules(tp): print("%4d  %s" % (v, k))
print("\n== FN (%d goi) ==" % len(fn))
print("diem 0:", sum(1 for r in fn if r.get("risk_score", 0) == 0), "| diem 1-34:", sum(1 for r in fn if 0 < r.get("risk_score", 0) < 35))
print("theo loai:", Counter(r["category"] for r in fn))
for k, v in rules(fn): print("%4d  %s" % (v, k))
print("\n== FN mau (ten) ==")
for r in fn[:12]: print(r.get("package_name"), r.get("version"), "score", r.get("risk_score"))
