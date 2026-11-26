# NT230 - Đề tài D04: Supply Chain Compromise (npm)

Đồ án môn học: **Cơ chế hoạt động của mã độc (NT230)**  
Trường Đại học Công nghệ Thông tin (ĐHQG-HCM)  
Giảng viên hướng dẫn: **TS. Phan Thế Duy**  
Nhóm thực hiện: **Nhóm 02** — **24520544 - Lê Minh Hoàng**, **24520557 - Nguyễn Minh Hoàng**

---

## 1. Tổng quan dự án

Dự án xây dựng bộ công cụ mô phỏng và phát hiện tấn công chuỗi cung ứng phần mềm (**Software Supply Chain Compromise**) trên hệ sinh thái **Node.js (npm)** theo chuẩn **MITRE ATT&CK T1195**.

Các thành phần chính:
- **`packages/` (Bộ 6 mẫu Package đối chứng: 3 Benign + 3 Malicious PoCs):**
  - **3 Gói Benign sạch đối chứng:** `uit-benign` (gói cơ bản), `uit-benign-native` (gói dùng hook `node-gyp` trong Whitelist), và `uit-benign-minified` (gói chứa bundle nén Webpack + icon SVG Base64).
  - **3 Gói PoC độc hại an toàn:** `uit-marker-lifecycle` (chèn hook `preinstall`), `uit-core-auth` (Dependency Confusion `v99.9.9` + Base64 Eval), và `uit-marker-tamper` (can thiệp mã băm tệp nén `.tgz`).
- **`scripts/detector.py`, `scripts/detector_core/` & `scripts/sandbox_runner.js` (Động cơ phát hiện 3 lớp độc lập với PoC):**
  - **Layer 1 (Manifest, Dependency Graph, Integrity & Version Diff):**
    - *1A Manifest:* Phân tách 3 bậc tín hiệu (`HARD_EVIDENCE`, `CAPABILITY` trần `+20`/gói, `WEAK_ANOMALY`). Kiểm tra `package.json` (`preinstall`/`install`/`postinstall`/`preuninstall`/`postuninstall`, author hooks `prepare`/`prepack`/`postpack`/`prepublish`), nối cầu `npm/yarn/pnpm run`, khử rối shell, soi `.pnpmfile*`/`.yarnrc.yml`/`bunfig.toml`, tiêm lệnh build trong `binding.gyp`/`Makefile`/`CMakeLists.txt`, binary ELF/Mach-O/PE giả dạng phần mở rộng tĩnh, script phụ trợ, bất thường phiên bản (CalVer `YYYYMMDD`-aware & sentinel version), URL metadata nội bộ, typosquatting (Damerau-Levenshtein), binary shadowing; áp dụng Whitelist build tool (`node-gyp`, `tsc`, `esbuild`, `opencollective`, `echo` thuần), tải release GitHub chính chủ và ngoại lệ banner script ngắn an toàn. Hỗ trợ tùy chọn **Offline Version Diff** (`version_diff.py` qua `baseline_path`) phát hiện leo thang hook/năng lực giữa 2 phiên bản.
    - *1B Dependency Graph:* Hỗ trợ đa lockfile (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`) và `overrides`/`resolutions`/`pnpm.overrides`; phát hiện nguồn ngoài registry tin cậy (URL/IP thô/Gist), tự phụ thuộc runtime, path traversal `file:`/`link:`, alias hijacking `npm:`, tráo gói trong lockfile (`Package Substitution`), giả mạo cờ `inBundle`/`bundled`, hạ cấp HTTP/thiếu SRI SHA-512 và `node_modules/` đóng gói sẵn chưa khai báo.
    - *1C Integrity:* Đối chiếu SRI hash (`sha512`/`sha384`/`sha256`/`sha1`) và kiểm tra cấu trúc `.tgz` (Tar Slip, symlink/hardlink escape, Tar Clobbering / trùng `package.json`).
  - **Layer 2 (Static Source Analysis & Deobfuscation + Cross-Layer Gating):**
    - Phân tích tĩnh mã `.js/.cjs/.mjs` (và `node -e` inline): xóa comment, giải mã `\xXX`/`\uXXXX`, gấp hằng & biểu thức (`fold_js_expressions`: biến hằng cục bộ, nối chuỗi `+`, `.join()`/`.reverse().join()`, `fromCharCode`, `atob`/`Buffer.from`, khử `require` gián tiếp qua `mainModule`/`getBuiltinModule`/`globalThis`/`Function.call`), BFS 2 bước entrypoint cài đặt, nhận diện bundle/minified, kiểm chứng payload Base64/Hex giải mã, luồng `decode → eval/vm`, luồng `recon → exfil` (gồm tương quan liên file), ngữ cảnh `child_process` (phân tách shell `exec` vs non-shell `execFile`/`spawn`, thực thi top-level, silent detached spawn), timer trễ `setTimeout >= 5s`, Trojan Source (Bidi không cân bằng / Variation Selectors / zero-width stego), JJEncode, độn khoảng trắng, anti-analysis (`v8debug`, `--inspect`, `CI`+`exit`), entropy trượt 512 byte, nhận diện làm rối nặng (JSFuck, XOR loop, `_0x`, `fromCharCode`) và bộ ngắt mạch chống FP.
    - Hỗ trợ chế độ **có cổng liên lớp** mặc định (`12` rule độc lập vượt cổng kết hợp thúc đẩy theo ngữ cảnh cài đặt để giảm FP khi Layer 1 sạch) và chế độ **cộng điểm độc lập** (`--always-scan-l2`).
  - **Layer 3 (Dynamic Behavioral Sandbox):**
    - Chạy cô lập trong Node.js (tự động nhận diện `--permission` trên Node 22+ hoặc `--experimental-permission` trên Node 20–21) với `--allow-fs-read` giới hạn vào thư mục runner và gói mục tiêu (`cwd` tại gói), giả lập shell hook + API Hooking `Module._load`, ghi nhận hành vi mạng (`http`, `https`, `dns`, `net`, `tls`, `dgram`, `fetch`), shell (`child_process`), truy cập file (`fs`), Honeypot `process.env`, bóc vỏ `eval`/`Function`/`vm`, time-warp (`Date`/`performance.now`/`setTimeout`), chạy **3 pha (`install`, `import`, `export_fuzz` hỗ trợ cả ES6 `class`)**, lọc FP `child_process` ở pha `export_fuzz`, xuất tóm tắt hành vi **4 trục** (`commands`, `files`, `network`, `env`) và tương quan Kill-Chain.
- **`scripts/supply_chain_gate.py` (CI/CD Security Gate):** Chốt chặn tiền cài đặt, tự động dừng pipeline (`Exit Code 1`) nếu tổng điểm rủi ro đạt ngưỡng (mặc định: `35`) hoặc gói lỗi.
- **`infrastructure/`:** Môi trường Docker cô lập gồm registry nội bộ Verdaccio (Air-gapped, `uplinks: {}`), container nạn nhân `victim-consumer`, và script demo tự động `infrastructure/demo.sh`.
- **`benchmark/`:** Bộ công cụ benchmark tĩnh trên 1.000 gói npm thật (dev/test split chống rò rỉ) và thí nghiệm biến thể né tránh có kiểm soát (`benchmark/evasion/`).

---

## 2. Cấu trúc thư mục

```text
.
├── infrastructure/                       # Hạ tầng Docker cô lập (Verdaccio Air-gap + Victim)
│   ├── docker-compose.yml                # Ghim phiên bản verdaccio/verdaccio:5
│   ├── demo.sh                           # Script demo end-to-end tự động (lưu logs/docker_demo.log)
│   ├── verdaccio/config.yaml             # uplinks: {} (Air-gap hoàn toàn)
│   └── victim-consumer/                  # Container nạn nhân (node:20-alpine, >=1.0.0)
├── packages/                             # Bộ 6 gói đối chứng (3 Benign + 3 Malicious PoCs)
│   ├── uit-benign/                       # [Benign 1] Gói đối chứng sạch cơ bản
│   ├── uit-benign-native/                # [Benign 2] Gói native addon dùng hook trong Whitelist
│   ├── uit-benign-minified/              # [Benign 3] Gói chứa bundle nén Webpack + SVG Base64
│   ├── uit-marker-lifecycle/             # [PoC 1] Lifecycle Hook (preinstall)
│   ├── uit-core-auth/                    # [PoC 2] Dependency Confusion (v99.9.9) + Base64 Eval
│   └── uit-marker-tamper/                # [PoC 3] Artifact Hash Tampering (SHA-512)
├── scripts/                              # Bộ công cụ phát hiện và kiểm thử
│   ├── detector.py                       # Động cơ quét đa lớp (Layer 1, 2, 3 & Integrity)
│   ├── detector_core/                    # Các module phân tích chuyên biệt (L1/L2/L3, JS, Shell, Version Diff)
│   ├── sandbox_runner.js                 # Harness hộp cát hành vi động Node.js (Layer 3)
│   ├── supply_chain_gate.py              # Chốt chặn bảo mật CI/CD trước cài đặt
│   ├── data_gen.py                       # Bộ sinh dữ liệu thử nghiệm tổng hợp
│   ├── evaluate.py                       # Công cụ đo đạc hiệu năng và xuất telemetry
│   ├── run_pipeline.py                   # Script tự động kiểm tra toàn bộ pipeline
│   └── test_detector_upgrades.py         # Bộ unit test cho các lớp phát hiện (pytest)
├── benchmark/                            # Đánh giá thực nghiệm (dữ liệu thật + evasion)
│   ├── bench_real.py                     # Benchmark tĩnh (L1+L2, khóa Layer 3) trên 1.000 gói thật
│   ├── bench_hook_benign.py              # Stress-test / lấy mẫu ngẫu nhiên gói sạch từ npm registry
│   ├── evasion/                          # Thí nghiệm 16 biến thể né tránh + 7 đối chứng sạch
│   └── README.md                         # Hướng dẫn tái lập bộ dữ liệu thật
└── README.md
```

---

## 3. Yêu cầu môi trường

- **Python >= 3.10**
- **Node.js >= 20.x** (khuyến nghị **22.x** để hỗ trợ cờ `--permission`; Node 20–21 dùng `--experimental-permission`)
- **Docker & Docker Compose v2** (nếu chạy demo cụm registry nội bộ)
- **Máy ảo (VMware Workstation / VirtualBox) có Snapshot/Rollback** khi làm việc với bộ mẫu độc thật.

---

## 4. Hướng dẫn chạy nhanh & tái lập

### 4.1. Kiểm tra tự động toàn bộ Pipeline & Unit Tests (mẫu an toàn, đủ 3 lớp)
```bash
python scripts/run_pipeline.py
python -m pytest -v scripts/test_detector_upgrades.py
```

### 4.2. Quét 6 gói đối chứng & kiểm tra cổng CI/CD
```bash
# Sinh tệp kiểm thử toàn vẹn SHA-512 và quét 6 gói trong packages/
python packages/uit-marker-tamper/simulate_tamper.py
python scripts/detector.py packages

# Cổng CI/CD: gói sạch -> GATE PASSED (exit code 0)
python scripts/supply_chain_gate.py packages/uit-benign
python scripts/supply_chain_gate.py packages/uit-benign-native
python scripts/supply_chain_gate.py packages/uit-benign-minified

# Cổng CI/CD: gói độc -> GATE FAILED / BLOCKED (exit code 1)
python scripts/supply_chain_gate.py packages/uit-core-auth
python scripts/supply_chain_gate.py packages/uit-marker-lifecycle
python scripts/supply_chain_gate.py packages/uit-marker-tamper
```

### 4.3. Demo end-to-end trong Docker cô lập (Verdaccio Air-gap + Victim Container)
```bash
# Chạy toàn bộ kịch bản: dựng Verdaccio -> publish uit-core-auth@1.0.0 & 99.9.9,
# uit-marker-lifecycle -> chạy cổng CI/CD -> cài trong victim-consumer -> kiểm tra /tmp/uit_marker_*.log
bash infrastructure/demo.sh --reset
```
Toàn bộ log phiên demo được tự động lưu tại `logs/docker_demo.log`. Để dừng cụm container sau khi demo:
```bash
docker compose -f infrastructure/docker-compose.yml down
```

### 4.4. Thí nghiệm biến thể né tránh có kiểm soát (460 gói an toàn, so sánh L1+L2 vs L1+L2+L3)
```bash
python benchmark/evasion/gen_evasion.py --out ./generated_evasion --seed 42
python benchmark/evasion/run_evasion.py --dataset ./generated_evasion --label eval
```

### 4.5. Dữ liệu tổng hợp (1.000 gói) và đánh giá định lượng
```bash
python scripts/data_gen.py --count 1000 --output ./generated_packages
python scripts/evaluate.py --dataset ./generated_packages
```

### 4.6. Benchmark trên dữ liệu thật & npm registry (CHỈ chạy L1+L2 tĩnh trong VM cô lập)
Xem chi tiết tải dataset và tái lập trong [`benchmark/README.md`](benchmark/README.md):
```bash
python3 benchmark/bench_real.py --part dev                    # đo & kiểm tra trên nửa dev (NAT tắt)
python3 benchmark/bench_real.py --part dev --always-scan-l2   # so sánh chế độ không cổng
python3 benchmark/bench_real.py --part test --final           # chạy tập test độc lập (chống rò rỉ, NAT tắt)
python3 benchmark/bench_hook_benign.py --target 240 --any-benign --random  # lấy mẫu ngẫu nhiên gói sạch npm
```

**Thông số đánh giá thực nghiệm (ngưỡng mặc định `35`):**

| Tập đánh giá | Chế độ | Precision | Recall | F1 | FPR | Ghi chú |
|---|---|---:|---:|---:|---:|---|
| 6 gói PoC đối chứng (`packages/`, 3 sạch + 3 độc) | Đầy đủ (3 lớp) | 100,0% | 100,0% | 100,0% | 0,0% | Toàn bộ PoC PASS/BLOCK (`score`: `0` vs `195`/`130`/`50`) |
| 100 gói tổng hợp (`data_gen.py`, `evaluate.py`) | Đầy đủ (3 lớp) | 100,0% | 68,9% | 81,6% | 0,0% | `TP31 FP0 TN55 FN14` (`100%` dep_conf/obf/tamper) |
| Bộ né tránh có kiểm soát (`460` gói, `16` biến thể + `7` sạch) | Tĩnh (`L1+L2`) | 100,0% | 100,0% | 100,0% | 0,0% | `320/320` độc, `0/140` FP |
| Bộ né tránh có kiểm soát (`460` gói, `16` biến thể + `7` sạch) | Đầy đủ (`L1+L2+L3`) | 100,0% | 100,0% | 100,0% | 0,0% | `320/320` độc, `0/140` FP |
| Tập thật **DEV** (`501` gói: `251` độc, `250` sạch) | Tĩnh có cổng (`L1+L2`) | 100,0% | 65,3% | 79,0% | 0,0% | `TP164 FP0`, `compromised_lib` 88,2% |
| Tập thật **TEST** (`440` gói: `190` độc, `250` sạch, chống rò rỉ) | Tĩnh có cổng (`L1+L2`) | 94,6% | 64,2% | 76,5% | 2,8% | `TP122 FP7`, `L1 manifest` FPR 0,0% |
| Gói sạch ngẫu nhiên npm (`240` gói unseen, `--any-benign --random`) | Tĩnh có cổng (`L1+L2`) | — | — | — | 0,4% | `1/240` FP (Wilson 95% CI: 0,1%–2,3%) |
| Stress-test gói sạch có install hook (`167` gói long-tail unseen) | Tĩnh có cổng (`L1+L2`) | — | — | — | 24,0% | `L1>=35`: 6,6%, `L2>=35`: 8,4% |

---

## 5. Cấu hình máy ảo & Checklist an toàn (Hạng mục D)

- **Cô lập hai lớp:** Mọi thử nghiệm dữ liệu thật thực hiện trong máy ảo **Oracle VirtualBox** (`SupplyChain-Sandbox`, Ubuntu 26.04.1 LTS, 1 vCPU, 4 GiB RAM) có chụp **Snapshot** trước khi chạy và **Rollback** sau khi hoàn tất; hạ tầng demo chạy trong mạng Docker bridge nội bộ, Verdaccio đã tắt hoàn toàn uplink ra Internet (`uplinks: {}`).
- **Payload PoC vô hại 100%:** Các gói PoC trong `packages/` và `benchmark/evasion/` chỉ ghi chuỗi đánh dấu vào `/tmp/uit_marker_*.log` (hoặc `C:/Users/Public/uit_marker_*.log` trên Windows) và `console.log` — không C2 Internet, không đánh cắp thông tin xác thực, không rò rỉ dữ liệu, không persistence ngoài phạm vi.
- **Tách biệt tĩnh/động với mẫu thật:** Bộ 500 gói độc DataDog **không** được commit vào repository; khi quét trong VM phải:
  - [x] Chụp Snapshot sạch (`supplay chain`) trước khi quét mẫu thật.
  - [x] Ngắt hoàn toàn kết nối Internet của VM (tắt NAT, chỉ giữ Host-Only nội bộ để thao tác qua SSH; xác nhận `ping -c 2 8.8.8.8` báo `Network is unreachable`).
  - [x] Không gắn thư mục chia sẻ giữa VM và máy thật (xác nhận `mount | grep -iE 'vboxsf|hgfs'` rỗng).
  - [x] Tuyệt đối **không** chạy `npm install`, `node`, hay Layer 3 trên mẫu độc thật (`bench_real.py` khóa cứng Layer 3 và mọi lệnh tạo tiến trình con).
  - [ ] Khôi phục Snapshot sau khi đã sao lưu kết quả log định lượng.
