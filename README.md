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
- **`scripts/detector.py` & `scripts/sandbox_runner.js` (Động cơ phát hiện 3 lớp độc lập với PoC):**
  - **Layer 1 (Manifest, Dependency Graph & Integrity):**
    - *1A Manifest:* Kiểm tra `package.json` (`preinstall`/`install`/`postinstall`/`preuninstall`/`postuninstall`, author hooks `prepare`/`prepack`/`postpack`/`prepublish`), phân giải chuỗi `npm/yarn/pnpm run`, khử làm rối shell, kiểm tra `binding.gyp` `<!(...)` và script phụ trợ, bất thường phiên bản (CalVer-aware), typosquatting, binary shadowing; áp dụng Whitelist build tool (`node-gyp`, `tsc`, `esbuild`, `opencollective`, `echo` thuần) và ngoại lệ banner script ngắn an toàn.
    - *1B Dependency Graph:* Phát hiện nguồn phụ thuộc ngoài registry tin cậy (URL/IP thô/Gist), tự phụ thuộc runtime, path traversal `file:`/`link:`, alias hijacking `npm:`, `overrides`/`resolutions` hijacking, đầu độc URL trong lockfile và `node_modules/` đóng gói sẵn chưa khai báo.
    - *1C Integrity:* Đối chiếu SRI hash (`sha512`/`sha384`/`sha256`/`sha1`) và kiểm tra cấu trúc `.tgz` (Tar Slip, symlink/hardlink escape, Tar Clobbering / trùng `package.json`).
  - **Layer 2 (Static Source Analysis + Cross-Layer Gating):**
    - Phân tích tĩnh mã `.js/.cjs/.mjs` có ngữ cảnh: loại bỏ comment, giải thoát `\xXX`/`\uXXXX` & gộp nối chuỗi, tìm entrypoint qua BFS 2 bước, nhận diện bundle/minified, kiểm chứng ngữ nghĩa chuỗi Base64/Hex giải mã, luồng decode → `eval`/`vm`, luồng recon → exfil, kiểm tra cửa sổ tham số `child_process`, nhận diện làm rối nặng (JSFuck, XOR loop, `_0x`, `fromCharCode`) và entropy trượt chống báo nhầm.
    - Hỗ trợ chế độ **có cổng liên lớp** (mặc định, giảm FP khi Layer 1 sạch) và chế độ **cộng điểm độc lập** (`--always-scan-l2`).
  - **Layer 3 (Dynamic Behavioral Sandbox):**
    - Chạy cô lập trong Node.js (tự động nhận diện `--permission` trên Node 22+ hoặc `--experimental-permission` trên Node 20–21) + API Hooking `Module._load`, chặn và ghi nhận hành vi mạng (`http`, `https`, `dns`, `net`, `tls`, `dgram`, `fetch`), shell (`child_process`), truy cập file ngoài phạm vi (`fs`), bẫy Honeypot `process.env`, bóc vỏ `eval`/`Function`/`vm`, chống trì hoãn (`Date`/`performance.now`/`setTimeout`/`Atomics.wait`), tách pha `load` và `export_fuzz` để tránh báo nhầm thư viện CLI hợp lệ.
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
│   ├── sandbox_runner.js                 # Harness hộp cát hành vi động Node.js (Layer 3)
│   ├── supply_chain_gate.py              # Chốt chặn bảo mật CI/CD trước cài đặt
│   ├── data_gen.py                       # Bộ sinh dữ liệu thử nghiệm tổng hợp
│   ├── evaluate.py                       # Công cụ đo đạc hiệu năng và xuất telemetry
│   └── run_pipeline.py                   # Script tự động kiểm tra toàn bộ pipeline
├── benchmark/                            # Đánh giá thực nghiệm (dữ liệu thật + evasion)
│   ├── bench_real.py                     # Benchmark tĩnh (L1+L2, khóa Layer 3) trên 1.000 gói thật
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

### 4.1. Kiểm tra tự động toàn bộ Pipeline (mẫu an toàn, đủ 3 lớp)
```bash
python scripts/run_pipeline.py
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
python benchmark/evasion/run_evasion.py --dataset ./generated_evasion --label after
```

### 4.5. Dữ liệu tổng hợp (1.000 gói) và đánh giá định lượng
```bash
python scripts/data_gen.py --count 1000 --output ./generated_packages
python scripts/evaluate.py --dataset ./generated_packages
```

### 4.6. Benchmark trên dữ liệu thật (1.000 gói npm — CHỈ chạy tĩnh trong VM cô lập)
Xem chi tiết tải dataset và tái lập trong [`benchmark/README.md`](benchmark/README.md):
```bash
python3 benchmark/bench_real.py --part dev                    # đo & chỉnh luật trên nửa dev
python3 benchmark/bench_real.py --part dev --always-scan-l2   # so sánh chế độ không cổng
python3 benchmark/bench_real.py --part all --final            # chạy DUY NHẤT 1 lần để lấy kết quả test
```

---

## 5. Cấu hình máy ảo & Checklist an toàn (Hạng mục D)

- **Cô lập hai lớp:** Mọi thử nghiệm thực hiện trong máy ảo Ubuntu (VMware Workstation) có chụp **Snapshot** trước khi chạy và **Rollback** sau khi hoàn tất; hạ tầng demo chạy trong mạng Docker bridge nội bộ, Verdaccio đã tắt hoàn toàn uplink ra Internet (`uplinks: {}`).
- **Payload PoC vô hại 100%:** Các gói PoC trong `packages/` và `benchmark/evasion/` chỉ ghi chuỗi đánh dấu vào `/tmp/uit_marker_*.log` (hoặc `C:\Users\Public\uit_marker_*.log` trên Windows) và `console.log` — không C2 Internet, không đánh cắp thông tin xác thực, không rò rỉ dữ liệu, không persistence ngoài phạm vi.
- **Tách biệt tĩnh/động với mẫu thật:** Bộ 500 gói độc DataDog **không** được commit vào repository; khi quét trong VM phải:
  - [ ] Chụp Snapshot sạch trước khi giải nén/quét mẫu thật.
  - [ ] Ngắt hoàn toàn card mạng VM (Disconnect Network Adapter; xác nhận `ping 1.1.1.1` thất bại).
  - [ ] Gỡ thư mục chia sẻ giữa VM và máy thật (xác nhận `mount | grep -i hgfs` rỗng) và tắt copy/paste hai chiều.
  - [ ] Tuyệt đối **không** chạy `npm install`, `node`, hay Layer 3 trên mẫu độc thật (`bench_real.py` khóa cứng Layer 3 và mọi lệnh tạo tiến trình con).
  - [ ] Khôi phục Snapshot sau khi đã sao lưu kết quả log định lượng.
