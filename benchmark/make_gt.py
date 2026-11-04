import csv, json, os, sys

BASE = os.path.expanduser("~/d04_real")
MAL, BEN = BASE + "/real_dataset", BASE + "/benign_dataset"
OUT = BASE + "/combined"
os.makedirs(OUT, exist_ok=True)

cats = {}
with open(BASE + "/mal_map.csv") as f:
    for row in csv.DictReader(f):
        cats[row["pkg_id"]] = row["category"]

gt = {"metadata": {"source": "DataDog malicious-software-packages-dataset (npm) + top npm packages by popularity", "distribution": {}}, "packages": {}}

def add(src_dir, pid, category, label):
    link = OUT + "/" + pid
    if not os.path.islink(link):
        os.symlink(src_dir + "/" + pid, link)
    name, ver = pid, "unknown"
    try:
        with open(link + "/package.json", encoding="utf-8") as f:
            d = json.load(f)
        name, ver = str(d.get("name", pid)), str(d.get("version", "unknown"))
    except Exception:
        pass
    gt["packages"][pid] = {"name": name, "category": category, "true_label": label, "version": ver}
    gt["metadata"]["distribution"][category] = gt["metadata"]["distribution"].get(category, 0) + 1

for pid in sorted(os.listdir(MAL)):
    add(MAL, pid, cats.get(pid, "malicious_intent"), "MALICIOUS")
for pid in sorted(os.listdir(BEN)):
    add(BEN, pid, "benign", "BENIGN")

gt["metadata"]["total_samples"] = len(gt["packages"])
with open(OUT + "/ground_truth.json", "w") as f:
    json.dump(gt, f, indent=2)
print("tong:", len(gt["packages"]), gt["metadata"]["distribution"])
