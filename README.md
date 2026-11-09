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
  - **3 Gói PoC độc hại an toàn:** `uit-marker-lifecycle` (chèn hook `preinstall`), `uit-core-auth` (Dependency Confusion `v99.9.9` + Graph Anomaly + Base64 Eval), và `uit-marker-tamper` (can thiệp mã băm tệp nén `.tgz`).
- **`scripts/detector.py` & `scripts/sandbox_runner.js` (Động cơ phát hiện 3 lớp):**
  - **Layer 1 (Manifest & Dependency Graph):** Kiểm tra `package.json`, phát hiện hook cài đặt nguy hiểm (`preinstall`, `postinstall`), nhảy vọt phiên bản ($\ge 90.0$), bất thường đồ thị phụ thuộc và áp dụng Whitelist cho công cụ build hợp lệ (`node-gyp`, `tsc`, `esbuild`).
  - **Layer 2 (Static Source Analysis):** Phân tích tĩnh mã nguồn `.js` có ngữ cảnh: giải mã kiểm chứng Base64, nhận diện mã nén/bundle hợp lệ, phát hiện hàm thực thi động (`eval`, `child_process`), mẫu làm rối (`_0x`, hex escape) và domain rò rỉ dữ liệu (OAST/Webhook/IP thô).
  - **Layer 3 (Dynamic Behavioral Sandbox):** Chạy cô lập trong môi trường Node.js (`--experimental-permission` + API Hooking trên `Module._load`), chặn và ghi nhận hành vi kết nối mạng (`http`, `dns`, `net`), mở shell (`child_process`), truy cập file ngoài phạm vi (`fs`), bẫy Honeypot `process.env`, bóc vỏ `eval()` và chống ngủ đông (`setTimeout`, `Atomics.wait`).
  - **Integrity Check:** Đối chiếu mã băm SHA-512 thực tế của gói `.tgz` với mã băm kỳ vọng.
- **`scripts/supply_chain_gate.py` (CI/CD Security Gate):** Chốt chặn tiền cài đặt, tự động hủy quá trình build (`Exit Code 1`) nếu tổng điểm rủi ro vượt ngưỡng (mặc định: `35`).
- **`infrastructure/`:** Môi trường thử nghiệm Docker cô lập gồm registry nội bộ Verdaccio (Air-gapped) và container nạn nhân.
- **`benchmark/`:** Kịch bản và báo cáo đánh giá thực nghiệm trên 1.000 gói npm.

---

## 2. Cấu trúc thư mục

```text
.
├── infrastructure/                       # Hạ tầng Docker cô lập (Verdaccio Air-gap + Victim)
│   ├── docker-compose.yml
│   ├── verdaccio/config.yaml
│   └── victim-consumer/
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
├── benchmark/                            # Đánh giá thực nghiệm trên dữ liệu thật
└── README.md
```

---

## 3. Hướng dẫn chạy nhanh

Yêu cầu: **Python >= 3.10**, **Node.js >= 18.x** (và **Docker** nếu chạy cụm registry nội bộ).

### 1. Chạy kiểm tra tự động toàn bộ Pipeline
```bash
python scripts/run_pipeline.py
```

### 2. Quét gói bằng Detector 3 lớp
```bash
# Sinh tệp kiểm thử toàn vẹn và quét toàn bộ 6 gói trong packages/
python packages/uit-marker-tamper/simulate_tamper.py
python scripts/detector.py packages
```

### 3. Kiểm tra chốt chặn CI/CD Security Gate
```bash
# Gói sạch -> GATE PASSED (Exit code 0)
python scripts/supply_chain_gate.py packages/uit-benign
python scripts/supply_chain_gate.py packages/uit-benign-native
python scripts/supply_chain_gate.py packages/uit-benign-minified

# Gói độc hại -> GATE FAILED (Exit code 1)
python scripts/supply_chain_gate.py packages/uit-core-auth
python scripts/supply_chain_gate.py packages/uit-marker-tamper
```

### 4. Sinh dữ liệu tổng hợp và đánh giá
```bash
python scripts/data_gen.py --count 100 --output ./generated_packages
python scripts/evaluate.py --dataset ./generated_packages
```

### 5. Khởi chạy hạ tầng Docker cô lập
```bash
docker compose -f infrastructure/docker-compose.yml up -d
```

---

## 4. Nguyên tắc an toàn

- **Cô lập hoàn toàn:** Mọi thử nghiệm thực hiện trong máy ảo và mạng Docker nội bộ; Verdaccio đã tắt hoàn toàn kết nối ra `npmjs.org` (`uplinks: {}`).
- **Payload vô hại:** Các gói PoC chỉ ghi chuỗi đánh dấu vào `/tmp/uit_marker_*.log` (hoặc `C:\Users\Public\uit_marker_*.log`) và `console.log`.
- **Sandbox khóa quyền:** Layer 3 tước quyền ghi đĩa và tạo tiến trình ở tầng C++ (`--experimental-permission`) kết hợp chặn toàn bộ mạng/shell/file ở tầng JS và giới hạn `timeout=2.0s`.
