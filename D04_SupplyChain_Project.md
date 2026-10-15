# D04 - Supply Chain Compromise: Package Độc Hại An Toàn
**Môn học:** NT230 - Cơ chế hoạt động của mã độc  
**Học kỳ:** HK1 - Năm học 2026-2027 | Giảng viên hướng dẫn: Đoàn Minh Trung  
**Nhóm thực hiện:** Nhóm D04 (NT230.R12.ANTT)  
**Tiêu chuẩn đồ án:** DEV TRACK - Xây dựng PoC an toàn, tạo biến thể né tránh có kiểm soát và detector độc lập đánh giá định lượng.

---

## 1. TỔNG QUAN ĐỀ TÀI & ĐỐI CHIẾU YÊU CẦU GIẢNG VIÊN

| Tiêu chí theo Đề cương NT230 | Yêu cầu của Giảng viên | Mức độ đáp ứng của Đồ án D04 |
|---|---|---|
| **Mã & Tên đề tài** | D04 - Supply Chain Compromise: package độc hại an toàn | Đáp ứng 100% |
| **Mục tiêu & Phạm vi PoC** | Chọn npm hoặc PyPI; private registry/local index; package marker | Đã triển khai hệ sinh thái npm, Verdaccio local registry và safe marker logging |
| **Yêu cầu kỹ thuật né tránh** | Dependency confusion, lifecycle script hoặc artifact hash tampering ở local | Triển khai đầy đủ cả 3 kỹ thuật: Lifecycle Hook, Dependency Confusion, Artifact Hash Tampering |
| **Detector phát hiện** | Metadata, install script, dependency graph, version/hash và hành vi cài đặt | Engine 3 lớp: Layer 1 (Manifest & Version), Layer 2 (Source AST/Regex), Layer 3 (Sandbox/Behavior) + Hash verification |
| **Dữ liệu & Thực nghiệm tối thiểu** | >= 3 benign + >= 3 PoC/biến thể; Precision, Recall, F1, FPR; log telemetry và HD tái lập | Bộ 4 mẫu PoC chuẩn + Dataset nội suy 100 packages; xuất log `logs/telemetry_log.json`; đầy đủ ma trận nhầm lẫn và chỉ số định lượng |
| **Ràng buộc an toàn** | Chỉ VM có snapshot/rollback; không payload phá hoại, C2 Internet, credential theft, exfiltration, persistence | Cơ chế cô lập 2 lớp (VM + Docker container air-gapped); 100% Safe Mock Marker, không C2, không phá hoại |
| **TTP liên quan** | MITRE ATT&CK T1195 (Supply Chain Compromise) | T1195.001 (Compromise Software Dependencies), T1195.002 (Compromise Software Supply Chain) |

---

## 2. KIẾN TRÚC HỆ THỐNG PHÒNG THỦ & THỰC NGHIỆM

Hệ thống được thiết kế theo cơ chế **Cô lập 2 lớp (Double Isolation)**:

```
                          ┌─────────────────────────┐
                          │   Host / VM Isolation   │
                          │   Windows 11 / Ubuntu   │
                          │   (Snapshot / Rollback) │
                          └────────────┬────────────┘
                                       │
                          ┌────────────▼────────────┐
                          │     Docker Network      │
                          │      (Air-Gapped)       │
                          └────────────┬────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │                                         │
         ┌────────▼─────────┐                     ┌─────────▼─────────┐
         │    Verdaccio     │                     │  Victim Consumer  │
         │  Local Registry  │◄──── npm install ───│     Container     │
         │ (Uplinks: Empty) │                     │      (.npmrc)     │
         └────────┬─────────┘                     └─────────┬─────────┘
                  │                                         │
                  │                                         │
         ┌────────▼─────────┐                     ┌─────────▼─────────┐
         │   PoC Packages   │                     │  Multi-Layer Gate │
         │                  │                     │   (detector.py)   │
         │ - uit-benign     │                     │ Layer 1: Manifest │
         │ - uit-lifecycle  │                     │ Layer 2: Source   │
         │ - uit-core-auth  │                     │ Layer 3: Behavior │
         │ - uit-tamper     │                     │ Auxiliary: Hash   │
         └──────────────────┘                     └─────────┬─────────┘
                                                            │
                                                   ┌────────▼────────┐
                                                   │ Telemetry & Eval│
                                                   │                 │
                                                   │ TP / FP / TN / FN│
                                                   │ Precision: 100% │
                                                   │ Recall:    100% │
                                                   │ F1-Score:  100% │
                                                   │ FPR:       0.0% │
                                                   └─────────────────┘
```

---

## 3. BỐN MẪU POC CƠ SỞ (BASE POC PACKAGES)

Toàn bộ 4 package mẫu nằm tại thư mục `packages/`:

1. **`uit-benign` (Gói đối chứng sạch):**
   - Đóng vai thư viện tiện ích thông thường (`add`, `greet`).
   - Tích hợp các script hợp lệ (`build`, `test`, `node-gyp rebuild`) để kiểm chứng khả năng lọc cảnh báo giả (FPR).
2. **`uit-marker-lifecycle` (Tấn công Hook Vòng đời):**
   - Kỹ thuật: Sử dụng hook `preinstall` trong `package.json`.
   - Hành vi an toàn: Ghi file marker vô hại tại `/tmp/uit_marker_lifecycle.log` (Linux) hoặc `C:\Users\Public\uit_marker_lifecycle.log` (Windows) để làm bằng chứng viễn trắc.
3. **`uit-core-auth` (Dependency Confusion + Obfuscation):**
   - Kỹ thuật: Đặt version nhảy vọt `99.9.9` (so với bản nội bộ `1.0.0`) nhằm lạm dụng thuật toán phân giải Semantic Versioning.
   - Né tránh: Mã hóa payload bằng chuỗi Base64 và giải mã động bằng `eval(Buffer.from(..., 'base64').toString())`.
4. **`uit-marker-tamper` (Sai lệch mã băm Artifact):**
   - Kỹ thuật: Giả lập kịch bản gói nén `.tgz` trên registry bị kẻ tấn công can thiệp sửa đổi nội dung sau khi đã đăng ký mã băm.
   - Kịch bản kiểm chứng: Script `simulate_tamper.py` đóng gói và tính SHA-512 đối chứng, sau đó chèn mã giả mạo và chứng minh sự bất nhất về tính toàn vẹn (Integrity Mismatch).

---

## 4. BỘ ĐỘNG CƠ PHÁT HIỆN ĐA LỚP (3-LAYER DETECTOR)

Hệ thống phát hiện được hiện thực tại `scripts/detector.py` và `scripts/supply_chain_gate.py`:

### Layer 1: Phân tích Siêu dữ liệu tĩnh (Manifest Analysis)
- Quét các hook vòng đời nguy hiểm: `preinstall`, `install`, `postinstall`, `preuninstall`, `postuninstall`.
- Nhận diện chỉ dấu Dependency Confusion: Major version `>= 90.0`.
- **Cơ chế Whitelist thông minh:** Bóc tách các công cụ build hợp lệ (`node-gyp rebuild`, `node-pre-gyp`, `esbuild`, `tsc`) để hạ tỷ lệ cảnh báo sai (FPR) từ 31.91% về 0.00%.

### Layer 2: Phân tích Mã nguồn tĩnh (Static Source Analysis)
- Quét biểu thức chính quy (Regex) và AST nhận diện các mẫu làm rối:
  - `eval(Buffer.from(..., 'base64'))`
  - `eval(Buffer.from(..., 'hex'))`
  - `new Function(...)`
  - `child_process.exec / spawn`
- Tính toán Shannon Entropy trên các khối mã: Cảnh báo entropy cao (`> 5.5`) và chuỗi Base64 hằng số dài (`>= 40` ký tự).

### Layer 3: Phân tích Hành vi Động (Behavioral Sandbox Simulation)
- Giám sát các lời gọi lệnh ngoại lai: `bash -c`, `powershell`, `curl`, `wget`.
- Bắt bẫy ngủ đông nhằm lẩn tránh sandbox (`sleep`, `setTimeout`, `Atomics.wait`).
- Phát hiện chuyển hướng luồng dữ liệu nhằm che giấu nhật ký (`> /dev/null 2>&1`).

---

## 5. ĐÁNH GIÁ ĐỊNH LƯỢNG & PHÂN TÍCH ĐÁNH ĐỔI (TRADE-OFF ANALYSIS)

Thực nghiệm được thực hiện tự động bằng công cụ `scripts/data_gen.py` (sinh 100 package đa dạng) và `scripts/evaluate.py`:

### 5.1. Ma trận nhầm lẫn (Confusion Matrix)

| Thực tế \ Dự đoán | Dự đoán MALICIOUS | Dự đoán BENIGN | Tổng |
|---|---|---|---|
| **Thực tế MALICIOUS** | **TP = 53** | **FN = 0** | 53 |
| **Thực tế BENIGN** | **FP = 0** | **TN = 47** | 47 |
| **Tổng** | 53 | 47 | 100 |

### 5.2. Các chỉ số hiệu năng

$$\text{Precision} = \frac{TP}{TP + FP} = \frac{53}{53 + 0} = 100.00\%$$

$$\text{Recall} = \frac{TP}{TP + FN} = \frac{53}{53 + 0} = 100.00\%$$

$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 100.00\%$$

$$\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN} = \frac{0}{0 + 47} = 0.00\%$$

### 5.3. Phân tích sự đánh đổi (Trade-off Analysis)

| Chế độ Detector | Số ca FP | Tỷ lệ FPR | Precision | Recall | F1-Score | Nhận xét bảo mật |
|---|---|---|---|---|---|---|
| **Có Whitelist (Mặc định)** | **0** | **0.00%** | **100.00%** | **100.00%** | **100.00%** | Tối ưu hóa cho môi trường CI/CD doanh nghiệp; không gây gián đoạn quy trình build bình thường |
| **Không có Whitelist** | **15** | **31.91%** | **77.94%** | **100.00%** | **87.60%** | Báo động giả nghiêm trọng trên các package sử dụng `node-gyp` và công cụ build C++ hợp pháp |

**Kết luận thực nghiệm:** Việc bổ sung Whitelist Layer 1 là bước cải tiến bắt buộc trong thực tế, giúp triệt tiêu 15 ca báo động nhầm (giảm FPR từ 31.91% xuống 0.00%) mà không làm suy giảm độ nhạy (Recall 100%).

---

## 6. KỊCH BẢN DEMO GIỮA 2 MÁY ẢO: KALI LINUX VS WINDOWS 11

Đồ án xây dựng kịch bản mô phỏng chân thực:
- **Máy 1: Kali Linux (`192.168.100.10`)** - Kẻ tấn công bên ngoài (External Threat Actor).
- **Máy 2: Windows 11 (`192.168.100.20`)** - Lập trình viên FinTech của doanh nghiệp.

*Tài liệu hướng dẫn chi tiết từng câu lệnh và ngữ cảnh tấn công được lưu tại:*  
📁 [`demo_kali_win11/SCENARIO_WALKTHROUGH.md`](file:///c:/D04-supply-chain-poc/demo_kali_win11/SCENARIO_WALKTHROUGH.md)

---

## 7. CẤU TRÚC MÃ NGUỒN CHUẨN HÓA

```text
c:\D04-supply-chain-poc/
├── infrastructure/                       # Hạ tầng Lab cô lập
│   ├── docker-compose.yml                # Điều phối Verdaccio + Victim container
│   ├── verdaccio/
│   │   └── config.yaml                   # Cấu hình air-gap, chặn uplink ra ngoài
│   └── victim-consumer/
│       ├── Dockerfile                    # Container mô phỏng nạn nhân
│       ├── .npmrc                        # Ép registry nội bộ
│       └── package.json                  # Khai báo dependency uit-core-auth
│
├── packages/                             # 4 mẫu PoC cơ sở
│   ├── uit-benign/                       # Gói sạch đối chứng (index.js, package.json)
│   ├── uit-marker-lifecycle/             # Hook preinstall + Safe marker log
│   ├── uit-core-auth/                    # Version 99.9.9 + Base64 obfuscation
│   └── uit-marker-tamper/                # Giả lập can thiệp mã băm (.tgz)
│       ├── simulate_tamper.py            # Script chứng minh lỗi toàn vẹn hash
│       └── dist/                         # Artifacts .tgz đối chứng
│
├── scripts/                              # Lõi thuật toán & Tự động hóa
│   ├── detector.py                       # Động cơ phát hiện 3 lớp
│   ├── supply_chain_gate.py              # Pre-install Security Gate cho CI/CD
│   ├── data_gen.py                       # Sinh 100 package + ground_truth.json
│   ├── evaluate.py                       # Đo đạc TP/FP/TN/FN, F1, FPR, Trade-off
│   └── run_pipeline.py                   # Tự động hóa toàn bộ luồng lab trong 1 lệnh
│
├── demo_kali_win11/                      # Kịch bản demo giữa 2 máy ảo
│   └── SCENARIO_WALKTHROUGH.md           # Hướng dẫn chi tiết từng bước + sơ đồ
│
├── logs/
│   └── telemetry_log.json                # Báo cáo Telemetry chi tiết 100 package
│
├── generated_packages/                   # Tập dữ liệu 100 package tự động sinh
└── README.md                             # Tài liệu kỹ thuật dự án
```

---

## 8. HƯỚNG DẪN TÁI LẬP LAB TRONG 1 BƯỚC

Để chạy toàn bộ quy trình kiểm thử, quét mã, giả lập sai lệch hash và đánh giá định lượng:

```bash
python scripts/run_pipeline.py
```

Để chạy riêng lẻ từng module:
```bash
# 1. Quét 4 package mẫu cơ sở
python scripts/detector.py packages

# 2. Kiểm tra gate ngăn chặn gói độc hại
python scripts/supply_chain_gate.py packages/uit-core-auth

# 3. Giả lập lỗi mã băm Artifact Tampering
python packages/uit-marker-tamper/simulate_tamper.py

# 4. Sinh dataset kiểm thử quy mô lớn
python scripts/data_gen.py --count 100

# 5. Đánh giá định lượng & xuất telemetry
python scripts/evaluate.py
```
