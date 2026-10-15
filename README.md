# NT230 - Đề tài D04: Supply Chain Compromise (Package Độc Hại An Toàn)

Đồ án môn học: **Cơ chế hoạt động của mã độc (NT230)**  
Khoa Mạng máy tính và Truyền thông - Trường Đại học Công nghệ Thông tin (ĐHQG-HCM)  
Giảng viên hướng dẫn: **ThS. Đoàn Minh Trung**  
Phân hệ: **DEV TRACK** (Học kỳ I - Năm học 2026-2027)  
Nhóm thực hiện: **D04**

---

## 1. Giới thiệu đề tài & Mục tiêu nghiên cứu

Đề tài **D04** tập trung nghiên cứu cơ chế tấn công và kỹ thuật phòng thủ đối với hiểm họa xâm phạm chuỗi cung ứng phần mềm (**Software Supply Chain Compromise - MITRE ATT&CK T1195**) trong hệ sinh thái Node.js (npm).

Mục tiêu của đề tài gồm 3 cấu phần chính:
1. **Xây dựng Proof-of-Concept (PoC) an toàn:** Mô phỏng các kỹ thuật lạm dụng chuỗi cung ứng bằng mã độc vô hại (safe marker) trong môi trường registry cục bộ độc lập.
2. **Kỹ thuật lẩn tránh có kiểm soát (Controlled Evasion):** Hiện thực và phân tích 3 vector tấn công phổ biến gồm Dependency Confusion, Hook vòng đời cài đặt (Lifecycle Scripts), và can thiệp sai lệch mã băm tệp nén (Artifact Hash Tampering), kết hợp làm rối mã (Base64 Obfuscation).
3. **Bộ phát hiện đa lớp độc lập (Multi-Layer Detector):** Xây dựng công cụ phân tích tĩnh kết hợp mô phỏng hành vi để phát hiện gói độc hại trước khi được cài đặt vào hệ thống, tích hợp cơ chế danh sách trắng (Whitelist) nhằm tối ưu hóa chỉ số cảnh báo sai (FPR), xuất dữ liệu viễn trắc (Telemetry) và đánh giá định lượng trên tập dữ liệu chuẩn.

---

## 2. Nguyên tắc an toàn & Ràng buộc phòng thí nghiệm

Dự án tuân thủ tuyệt đối các ràng buộc an toàn kỹ thuật theo quy chế môn học NT230:
- **Cô lập hai lớp (Double Isolation):** Toàn bộ thử nghiệm thực thi trong máy ảo (VirtualBox / VMware) có thiết lập cơ chế Snapshot/Rollback. Bên trong máy ảo, các dịch vụ phân phối gói chạy trên các container Docker được cô lập mạng hoàn toàn (Air-gapped local network).
- **Mã độc an toàn (Safe Mock Marker):** 100% mã thử nghiệm không chứa mã lệnh phá hoại, không thực hiện hành vi thu thập thông tin xác thực (credential theft), không kết nối tới máy chủ điều khiển bên ngoài Internet (C2 server), và không phát tán ra ngoài phạm vi phòng thí nghiệm. Dấu vết kích hoạt được giới hạn trong việc ghi nhật ký cục bộ (Local Telemetry Log).
- **Registry độc lập:** Sử dụng Verdaccio làm máy chủ quản lý gói nội bộ với cấu hình vô hiệu hóa hoàn toàn các kết nối uplink tới `npmjs.org`.

---

## 3. Kiến trúc hệ thống & Luồng xử lý

```
                           +----------------------------------------+
                           |          Host / VM Environment         |
                           |   (Windows 11 / Ubuntu Server VM)      |
                           +-------------------+--------------------+
                                               |
                           +-------------------v--------------------+
                           |        Docker Air-Gapped Network       |
                           |             (lab-network)              |
                           +-------------------+--------------------+
                                               |
             +---------------------------------+---------------------------------+
             |                                                                   |
+------------v------------+                                             +--------v--------+
|    Verdaccio Registry   |                                             | Victim Consumer |
|  (Local NPM Server)     |<---------- npm install (Internal Repo) -----|   Container     |
|   uplinks: disabled     |                                             |     (.npmrc)    |
+------------+------------+                                             +--------+--------+
             |                                                                   |
             |                                                                   |
+------------v------------+                                             +--------v--------+
|      PoC Packages       |                                             |  Security Gate  |
|                         |                                             |  (detector.py)  |
| - uit-benign            |                                             |                 |
| - uit-marker-lifecycle  |                                             | Layer 1: Manif. |
| - uit-core-auth         |                                             | Layer 2: Source |
| - uit-marker-tamper     |                                             | Layer 3: Behav. |
+-------------------------+                                             +--------+--------+
                                                                                 |
                                                                        +--------v--------+
                                                                        | Telemetry Log & |
                                                                        | Evaluation      |
                                                                        |                 |
                                                                        | Precision, Rec. |
                                                                        | F1, FPR, Matrix |
                                                                        +-----------------+
```

### Các thành phần chính trong kiến trúc:
1. **Local Registry (Verdaccio):** Máy chủ lưu trữ gói npm nội bộ tại cổng 4873, được cấu hình `uplinks: {}` để ngăn chặn rò rỉ gói tin ra ngoài mạng Internet.
2. **Victim Consumer Container:** Môi trường đại diện cho máy trạm lập trình viên hoặc máy chủ CI/CD, có tệp cấu hình `.npmrc` ép buộc mọi gói phụ thuộc phải tải qua Local Registry.
3. **Bộ mẫu PoC cơ sở (`packages/`):**
   - `uit-benign`: Gói chuẩn sạch, cung cấp các hàm tiện ích và chứa các script biên dịch hợp lệ (`node-gyp rebuild`, `tsc`) nhằm đánh giá khả năng chống cảnh báo giả.
   - `uit-marker-lifecycle`: Gói chứa hook `preinstall` kích hoạt tự động khi cài đặt, ghi nhận dấu vết an toàn tại thư mục tạm của hệ điều hành.
   - `uit-core-auth`: Gói mô phỏng kỹ thuật Dependency Confusion với số phiên bản vượt bậc (`v99.9.9`), kết hợp mã hóa Base64 và hàm nạp động `eval(Buffer.from(..., 'base64'))` để kiểm tra độ nhạy của bộ dò quét tĩnh.
   - `uit-marker-tamper`: Gói kiểm thử tính toàn vẹn, mô phỏng tình huống tệp nén `.tgz` trên kho lưu trữ bị can thiệp sửa đổi nội dung mà không cập nhật lại mã băm SHA-512 tương ứng.
4. **Động cơ phân tích đa lớp (`scripts/detector.py`):**
   - **Layer 1 - Phân tích Siêu dữ liệu (Manifest Analysis):** Kiểm tra tệp `package.json`, nhận diện các hook vòng đời nguy hiểm (`preinstall`, `install`, `postinstall`), phát hiện số phiên bản nhảy vọt bất thường ($\ge 90.0$), đồng thời áp dụng cơ chế Whitelist để bỏ qua các công cụ biên dịch C++ hợp lệ (`node-gyp`, `esbuild`, `tsc`).
   - **Layer 2 - Phân tích Mã nguồn tĩnh (Static Source Analysis):** Quét nội dung các tệp JavaScript bằng biểu thức chính quy và phân tích cấu trúc nhằm tìm kiếm các mẫu giải mã động (`eval(Buffer.from)`, `new Function`), hàm thực thi lệnh hệ thống (`child_process`), chuỗi ký tự Base64 dung lượng lớn và đo độ hỗn loạn thông tin (Shannon Entropy $> 5.5$).
   - **Layer 3 - Mô phỏng Hành vi Động (Behavioral Sandbox Analysis):** Phân tích luồng thực thi trong script cài đặt, kiểm tra các lệnh gọi trình thông dịch vỏ bọc (`bash -c`, `powershell`), lệnh gọi mạng (`curl`, `wget`) và kỹ thuật trì hoãn lẩn tránh hộp cát (`sleep`, `Atomics.wait`).
   - **Kiểm tra tính toàn vẹn (Integrity Verification):** Đo đạc và đối chiếu mã băm SHA-512 thực tế của tệp nén so với giá trị khai báo trong metadata hoặc `package-lock.json`.
5. **Cổng kiểm soát an ninh tiền cài đặt (`scripts/supply_chain_gate.py`):** Đóng vai trò chốt chặn (Quality Gate) trên pipeline CI/CD, quét gói phụ thuộc và tự động dừng tiến trình (Exit Code 1) khi điểm rủi ro vượt ngưỡng an toàn.

---

## 4. Kết quả thực nghiệm & Đánh giá định lượng

Thực nghiệm được thực hiện trên tập dữ liệu tổng hợp gồm $N = 100$ gói npm, được sinh tự động bởi công cụ `scripts/data_gen.py` theo tỷ lệ phân bổ kiểm soát: 47% gói sạch (benign), 18% gói chứa hook vòng đời (lifecycle injection), 15% gói dependency confusion và 20% gói làm rối mã (obfuscation).

### 4.1. Ma trận nhầm lẫn (Confusion Matrix)

| Thực tế \ Dự đoán | Dự đoán Nguy hại (MALICIOUS) | Dự đoán An toàn (BENIGN) | Tổng |
|---|---|---|---|
| **Thực tế Nguy hại** | **True Positive (TP) = 53** | **False Negative (FN) = 0** | 53 |
| **Thực tế An toàn** | **False Positive (FP) = 0** | **True Negative (TN) = 47** | 47 |
| **Tổng số mẫu** | 53 | 47 | 100 |

### 4.2. Các chỉ số hiệu năng

- **Độ chuẩn xác (Precision):**
  $$\text{Precision} = \frac{TP}{TP + FP} = \frac{53}{53 + 0} = 100.00\%$$
- **Độ nhạy / Tỷ lệ phát hiện (Recall):**
  $$\text{Recall} = \frac{TP}{TP + FN} = \frac{53}{53 + 0} = 100.00\%$$
- **Chỉ số F1 (F1-Score):**
  $$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 100.00\%$$
- **Tỷ lệ báo động giả (False Positive Rate - FPR):**
  $$\text{FPR} = \frac{FP}{FP + TN} = \frac{0}{0 + 47} = 0.00\%$$
- **Độ chính xác tổng thể (Accuracy):**
  $$\text{Accuracy} = \frac{TP + TN}{TP + FP + TN + FN} = \frac{53 + 47}{100} = 100.00\%$$

### 4.3. Phân tích sự đánh đổi (Trade-off Analysis)

Thực nghiệm so sánh giữa hai cấu hình của bộ dò quét:

| Cấu hình | Số lượng FP | Tỷ lệ FPR | Precision | Recall | F1-Score | Nhận xét kỹ thuật |
|---|---|---|---|---|---|---|
| **Có Whitelist (Mặc định)** | **0** | **0.00%** | **100.00%** | **100.00%** | **100.00%** | Nhận diện chính xác gói sạch có dùng `node-gyp`, không gây nghẽn tiến trình build. |
| **Không dùng Whitelist** | **15** | **31.91%** | **77.94%** | **100.00%** | **87.60%** | Báo động nhầm 15 gói sạch chứa lệnh build hợp lệ; tỷ lệ cảnh báo sai tăng vọt lên 31.91%. |

Toàn bộ dữ liệu chi tiết từng mẫu kiểm thử và bằng chứng viễn trắc được lưu trữ tại tệp `logs/telemetry_log.json`.

---

## 5. Kịch bản Demo thực chiến giữa 2 máy ảo: Kali Linux vs Windows 11

Đồ án xây dựng kịch bản mô phỏng tương tác trực tiếp qua mạng nội bộ cô lập (Host-Only Network):
- **Máy 1: Kali Linux (`192.168.100.10`)** - Đóng vai kẻ tấn công bên ngoài (External Adversary).
- **Máy 2: Windows 11 (`192.168.100.20`)** - Đóng vai máy trạm lập trình viên doanh nghiệp mục tiêu.

### Tóm tắt kịch bản tấn công và phòng thủ:
1. **Ngữ cảnh:** Doanh nghiệp có tường lửa và phần mềm diệt virus trên Windows 11 rất nghiêm ngặt, ngăn chặn mọi file thực thi lạ. Tuy nhiên, dự án phần mềm có khai báo sử dụng gói nội bộ unscoped `uit-core-auth: "^1.0.0"`.
2. **Khai thác:** Kẻ tấn công trên Kali Linux tạo gói `uit-core-auth` với số phiên bản vượt bậc `99.9.9`, chèn mã rối Base64 và xuất bản lên kho lưu trữ.
3. **Thâm nhập (Không có Security Gate):** Khi lập trình viên trên Windows 11 thực hiện lệnh `npm install`, trình quản lý npm tự động ưu tiên tải bản `99.9.9`. Hook `postinstall` tự động kích hoạt và ghi file dấu vết an toàn tại `C:\Users\Public\uit_marker_dependency_confusion.log`.
4. **Chặn đứng cuộc tấn công (Kích hoạt Security Gate):** Khi tích hợp công cụ `scripts/supply_chain_gate.py`, bộ lọc 3 lớp lập tức phát hiện chỉ dấu bất thường về phiên bản và mẫu giải mã động, trả về mã lỗi (`Exit Code 1`) và hủy bỏ phiên cài đặt, bảo vệ an toàn cho máy trạm.

Tài liệu hướng dẫn thao tác chi tiết từng câu lệnh được trình bày tại:  
`demo_kali_win11/SCENARIO_WALKTHROUGH.md`

---

## 6. Hướng dẫn cài đặt & Tái lập thực nghiệm

### Yêu cầu môi trường
- Hệ điều hành: Windows 10/11, Ubuntu 20.04/22.04 LTS hoặc macOS.
- Python: Phiên bản 3.10 trở lên.
- Node.js: Phiên bản 18.x LTS trở lên kèm `npm`.
- Docker & Docker Compose (tùy chọn, dùng khi chạy cụm container cô lập).

### Chạy kiểm thử tự động toàn bộ quy trình (1 lệnh duy nhất)

```bash
python scripts/run_pipeline.py
```

### Chạy từng thành phần riêng lẻ

1. **Quét 4 gói mẫu cơ sở bằng Detector đa lớp:**
   ```bash
   python scripts/detector.py packages
   ```

2. **Kiểm tra cơ chế chặn gói độc hại của CI/CD Gate:**
   ```bash
   # Quét gói sạch (Kỳ vọng: PASS - Exit code 0)
   python scripts/supply_chain_gate.py packages/uit-benign

   # Quét gói độc hại (Kỳ vọng: BLOCKED - Exit code 1)
   python scripts/supply_chain_gate.py packages/uit-core-auth
   ```

3. **Mô phỏng và kiểm tra sai lệch mã băm (Artifact Tampering):**
   ```bash
   python packages/uit-marker-tamper/simulate_tamper.py
   ```

4. **Tạo tập dữ liệu gói tổng hợp:**
   ```bash
   python scripts/data_gen.py --count 100 --output ./generated_packages
   ```

5. **Đánh giá định lượng hiệu năng và xuất báo cáo Telemetry:**
   ```bash
   python scripts/evaluate.py --dataset ./generated_packages --log ./logs/telemetry_log.json
   ```

6. **Khởi chạy môi trường container cô lập bằng Docker:**
   ```bash
   docker compose -f infrastructure/docker-compose.yml up -d
   ```

---

## 7. Cấu trúc thư mục dự án

```text
.
├── infrastructure/                       # Cấu hình môi trường mạng & dịch vụ cô lập
│   ├── docker-compose.yml                # Khởi tạo Verdaccio Registry và Victim Container
│   ├── verdaccio/
│   │   └── config.yaml                   # Cấu hình Air-gap vô hiệu hóa kết nối ngoài
│   └── victim-consumer/
│       ├── Dockerfile                    # Container mô phỏng môi trường nạn nhân
│       ├── .npmrc                        # File cấu hình trỏ registry cục bộ
│       └── package.json                  # Dự án mẫu phụ thuộc gói uit-core-auth
│
├── packages/                             # Các gói PoC cơ sở
│   ├── uit-benign/                       # Gói đối chứng sạch đạt chuẩn
│   ├── uit-marker-lifecycle/             # PoC chèn hook preinstall vòng đời
│   ├── uit-core-auth/                    # PoC Dependency Confusion version 99.9.9
│   └── uit-marker-tamper/                # PoC kiểm thử tính toàn vẹn mã băm
│       └── simulate_tamper.py            # Script mô phỏng sai lệch mã SHA-512
│
├── scripts/                              # Bộ công cụ mã nguồn chính
│   ├── detector.py                       # Động cơ quét đa lớp (Manifest, Source, Sandbox)
│   ├── supply_chain_gate.py              # Chốt chặn kiểm định bảo mật CI/CD
│   ├── data_gen.py                       # Bộ sinh dữ liệu thử nghiệm chuẩn hóa
│   ├── evaluate.py                       # Engine đo đạc ma trận nhầm lẫn và chỉ số
│   └── run_pipeline.py                   # Script tự động điều phối toàn bộ lab
│
├── demo_kali_win11/                      # Kịch bản demo giữa hai máy ảo
│   └── SCENARIO_WALKTHROUGH.md           # Hướng dẫn thao tác kịch bản chi tiết
│
├── logs/
│   └── telemetry_log.json                # Báo cáo kết quả định lượng chi tiết
│
├── D04_SupplyChain_Project.md            # Tài liệu tổng kết kỹ thuật đồ án
├── README.md                             # Tài liệu kỹ thuật chính của dự án
└── .gitignore                            # Cấu hình loại trừ tệp rác và build cache
```

---

## 8. Khuyến nghị phòng ngừa tấn công chuỗi cung ứng trong doanh nghiệp

Dựa trên kết quả nghiên cứu thực nghiệm, các giải pháp bảo vệ chuỗi cung ứng phần mềm cần được triển khai đồng bộ:
1. **Sử dụng Không gian tên có phạm vi (Scoped Packages):** Khai báo các thư viện nội bộ dưới dạng `@organization/package-name` và thiết lập quyền sở hữu độc quyền trên kho lưu trữ chung để triệt tiêu hoàn toàn nguy cơ Dependency Confusion.
2. **Khóa chặt tính toàn vẹn qua Lockfile:** Luôn đưa tệp `package-lock.json` vào hệ thống quản lý phiên bản (Git). Trên môi trường tích hợp liên tục (CI/CD), bắt buộc sử dụng lệnh `npm ci` thay thế cho `npm install` để kiểm tra nghiêm ngặt mã băm SHA-512 của mọi tệp phụ thuộc.
3. **Vô hiệu hóa thực thi script tự động:** Chạy lệnh `npm install --ignore-scripts` trong các tác vụ kiểm thử hoặc đối với các thư viện không yêu cầu biên dịch C++ nội tại.
4. **Triển khai cổng kiểm soát tự động:** Tích hợp bộ quét mã chuỗi cung ứng vào quy trình tiền cài đặt (Pre-install Hook) nhằm phát hiện và ngăn chặn kịp thời các gói có số phiên bản hoặc cấu trúc script bất thường trước khi nạp vào hệ thống.
