import json, os, shutil, tarfile, tempfile, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
OUT = os.path.expanduser("~/d04_real/benign_dataset")
MAP = os.path.expanduser("~/d04_real/ben_map.csv")
WANT, MAXB = 500, 20 * 1024 * 1024
KEYS = ["framework", "cli", "typescript", "react", "utility", "plugin", "database", "testing", "http", "async", "parser", "logger", "build", "crypto", "date"]
shutil.rmtree(OUT, ignore_errors=True)
os.makedirs(OUT)

def get(url, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nt230-lab"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read(MAXB + 1)
        except Exception:
            time.sleep(3 * (i + 1))
    return None

cands = {}
for k in KEYS:
    for frm in (0, 250):
        q = urllib.parse.urlencode({"text": "keywords:" + k, "popularity": "1.0", "quality": "0", "maintenance": "0", "size": 250, "from": frm})
        raw = get("https://registry.npmjs.org/-/v1/search?" + q)
        if raw:
            for o in json.loads(raw)["objects"]:
                cands[o["package"]["name"]] = o["package"]["version"]
        time.sleep(2)
    if len(cands) >= 1500:
        break
cands = list(cands.items())
print("ung vien:", len(cands))

def fetch(item):
    name, ver = item
    try:
        base = name.split("/")[-1]
        data = get("https://registry.npmjs.org/%s/-/%s-%s.tgz" % (name.replace("/", "%2f"), base, ver))
        if not data or len(data) > MAXB:
            return None
        tmp = tempfile.mkdtemp()
        open(tmp + "/a.tgz", "wb").write(data)
        with tarfile.open(tmp + "/a.tgz") as t:
            ok = [m for m in t.getmembers() if (m.isfile() or m.isdir()) and not m.name.startswith("/") and ".." not in m.name.split("/")]
            t.extractall(tmp + "/x", members=ok)
        root = tmp + "/x/package"
        if not os.path.exists(root + "/package.json"):
            return None
        return name, ver, root
    except Exception:
        return None

n = 0
with open(MAP, "w") as m:
    m.write("pkg_id,name,version\n")
    with ThreadPoolExecutor(4) as ex:
        for r in ex.map(fetch, cands):
            if r and n < WANT:
                n += 1
                pid = "ben-%05d" % n
                shutil.move(r[2], OUT + "/" + pid)
                m.write("%s,%s,%s\n" % (pid, r[0], r[1]))
print("xong:", n)
