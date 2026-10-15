# NT230 - Đề tài D04: Supply Chain Compromise (Package Độc Hại An Toàn)

Đồ án môn học: **Cơ chế hoạt động của mã độc (NT230)**  
Khoa Mạng máy tính và Truyền thông - Trường Đại học Công nghệ Thông tin (ĐHQG-HCM)  
Giảng viên hướng dẫn: **TS. Phan Thế Duy**  
Nhóm thực hiện: **Nhóm 02**  
Thành viên: **24520544 - Lê Minh Hoàng**, **24520557 - Nguyễn Minh Hoàng**  

---

## 1. Giới thiệu đề tài & Phạm vi công cụ

Kho lưu trữ này tập trung vào việc **xây dựng bộ công cụ kiểm thử bảo mật và phòng thủ chuỗi cung ứng phần mềm** (**Software Supply Chain Security Toolchain**) nhắm vào hệ sinh thái Node.js (npm), ánh xạ theo kỹ thuật **MITRE ATT&CK T1195**.

Mục tiêu trọng tâm của dự án là thiết kế và hoàn thiện các công cụ phần mềm kỹ thuật:
- **Hệ thống PoC mô phỏng tấn công:** Triển khai 4 mẫu package đại diện cho các kỹ thuật Hook vòng đời (`preinstall`), Dependency Confusion (nhảy vọt số phiên bản kết hợp làm rối mã Base64) và giả lập can thiệp tính toàn vẹn tệp nén (Artifact Hash Tampering).
- **Bộ động cơ phát hiện đa lớp (`detector.py`):** Công cụ phân tích tĩnh kết hợp mô phỏng hành vi 3 tầng nhằm rà soát và đánh giá mức độ rủi ro của package trước khi cài đặt.
- **Cổng kiểm soát an ninh tiền cài đặt (`supply_chain_gate.py`):** Công cụ chốt chặn (Quality Gate) tích hợp vào quy trình CI/CD hoặc pre-commit hook để tự động đình chỉ tiến trình cài đặt khi phát hiện dấu hiệu bất thường.
- **Công cụ giả lập can thiệp toàn vẹn (`simulate_tamper.py`):** Kiểm tra và đối chiếu sai lệch mã băm SHA-512 giữa tệp nén `.tgz` thực tế và giá trị khai báo.
- **Công cụ sinh dữ liệu thử nghiệm (`data_gen.py`):** Tạo các tập package tổng hợp có cấu trúc để phục vụ thử nghiệm công cụ.
- **Hạ tầng môi trường cô lập (`infrastructure/`):** Cụm container Docker gồm máy chủ Verdaccio (Air-gapped) và môi trường nạn nhân để thử nghiệm thực tế.

---

## 2. Nguyên tắc an toàn kỹ thuật

Dự án được xây dựng với các rào cản an toàn nghiêm ngặt:
- **Cơ chế cô lập hai lớp (Double Isolation):** Toàn bộ thử nghiệm thực thi trong máy ảo (VirtualBox / VMware) có tính năng Snapshot/Rollback. Bên trong máy ảo, các dịch vụ phân phối gói chạy trên các container Docker được cô lập mạng hoàn toàn (Air-gapped local network).
- **Mã độc an toàn (Safe Mock Marker):** 100% mã thử nghiệm không chứa mã lệnh phá hoại, không thực hiện hành vi thu thập thông tin xác thực, không kết nối tới máy chủ điều khiển bên ngoài Internet (C2 server), và không phát tán ra ngoài phạm vi phòng thí nghiệm. Dấu vết kích hoạt được giới hạn trong việc ghi nhật ký cục bộ (Local Telemetry Log).
- **Registry độc lập:** Sử dụng Verdaccio làm máy chủ quản lý gói nội bộ với cấu hình vô hiệu hóa hoàn toàn các kết nối uplink tới `npmjs.org`.

---

### Chi tiết các thành phần công cụ:

#### 1. Bộ 4 mẫu PoC cơ sở (`packages/`)
- **`uit-benign`:** Gói thư viện tiện ích thông thường, tích hợp các script biên dịch hợp lệ (`node-gyp rebuild`, `tsc`) nhằm kiểm tra khả năng phân biệt mã sạch của công cụ.
- **`uit-marker-lifecycle`:** Gói chứa hook `preinstall` trong `package.json`. Khi `npm install` được thực thi, hook tự động chạy và ghi dấu vết an toàn vào thư mục tạm của hệ điều hành.
- **`uit-core-auth`:** Gói mô phỏng kỹ thuật Dependency Confusion với số phiên bản vượt bậc (`v99.9.9`), kết hợp mã hóa Base64 và hàm nạp động `eval(Buffer.from(..., 'base64').toString())` để kiểm tra độ nhạy của bộ dò quét tĩnh.
- **`uit-marker-tamper`:** Gói kiểm thử tính toàn vẹn, đi kèm script `simulate_tamper.py` để đóng gói `.tgz`, tạo bản sao bị can thiệp và chứng minh sự bất nhất về mã băm SHA-512.

#### 2. Động cơ phân tích đa lớp (`scripts/detector.py`)
Hoạt động theo 3 lớp phân tích chuyên sâu:
- **Layer 1 - Phân tích Siêu dữ liệu (Manifest Analysis):** Quét danh sách script trong `package.json`, phát hiện các hook nguy hiểm (`preinstall`, `install`, `postinstall`), nhận diện số phiên bản nhảy vọt bất thường ($\ge 90.0$), đồng thời áp dụng cơ chế Whitelist để bỏ qua các công cụ biên dịch C++ hợp lệ (`node-gyp`, `esbuild`, `tsc`).
- **Layer 2 - Phân tích Mã nguồn tĩnh (Static Source Analysis):** Quét biểu thức chính quy và cú pháp các tệp JavaScript để tìm kiếm các hàm nạp động (`eval(Buffer.from)`, `new Function`), hàm thực thi lệnh hệ thống (`child_process`), chuỗi ký tự Base64 dung lượng lớn và đo độ hỗn loạn thông tin (Shannon Entropy $> 5.5$).
- **Layer 3 - Mô phỏng Hành vi Động (Behavioral Sandbox Analysis):** Phân tích luồng thực thi trong script cài đặt, kiểm tra các lệnh gọi trình thông dịch vỏ bọc (`bash -c`, `powershell`), lệnh gọi mạng (`curl`, `wget`) và kỹ thuật trì hoãn lẩn tránh hộp cát (`sleep`, `Atomics.wait`).
- **Kiểm tra tính toàn vẹn (Integrity Verification):** Đo đạc và đối chiếu mã băm SHA-512 thực tế của tệp nén so với giá trị đối chứng.

#### 3. Cổng an ninh tiền cài đặt CI/CD (`scripts/supply_chain_gate.py`)
- Kiểm tra tính an toàn của package trước khi cho phép tiến hành cài đặt vào dự án.
- Tự động chặn và trả về mã lỗi (`Exit Code 1`) khi điểm rủi ro vượt ngưỡng an toàn; trả về `Exit Code 0` khi package hợp lệ.

#### 4. Công cụ sinh dữ liệu thử nghiệm (`scripts/data_gen.py`)
- Tự động sinh hàng loạt package mẫu có cấu trúc theo các kịch bản định sẵn (benign, lifecycle, confusion, obfuscation) kèm tệp `ground_truth.json` phục vụ việc thử nghiệm bộ công cụ.

---

## 3. Kịch bản Demo giữa 2 máy ảo: Kali Linux vs Windows 11

Dự án cung cấp kịch bản mô phỏng trực quan tương tác giữa 2 máy ảo trong mạng Host-Only cô lập:
- **Máy 1: Kali Linux (`192.168.100.10`)** - Đóng vai kẻ tấn công bên ngoài (External Adversary).
- **Máy 2: Windows 11 (`192.168.100.20`)** - Đóng vai máy trạm lập trình viên doanh nghiệp mục tiêu.

### Tóm tắt kịch bản tấn công và phòng thủ:
1. **Ngữ cảnh:** Doanh nghiệp có tường lửa và phần mềm diệt virus trên Windows 11 rất nghiêm ngặt, ngăn chặn mọi file thực thi lạ. Tuy nhiên, dự án phần mềm có khai báo sử dụng gói nội bộ unscoped `uit-core-auth: "^1.0.0"`.
2. **Khai thác:** Kẻ tấn công trên Kali Linux tạo gói `uit-core-auth` với số phiên bản vượt bậc `99.9.9`, chèn mã rối Base64 và xuất bản lên kho lưu trữ.
3. **Thâm nhập (Không có Security Gate):** Khi lập trình viên trên Windows 11 thực hiện lệnh `npm install`, trình quản lý npm tự động ưu tiên tải bản `99.9.9`. Hook `postinstall` tự động kích hoạt và ghi file dấu vết an toàn tại `C:\Users\Public\uit_marker_dependency_confusion.log`.
4. **Chặn đứng cuộc tấn công (Kích hoạt Security Gate):** Khi tích hợp công cụ `scripts/supply_chain_gate.py`, bộ lọc 3 lớp lập tức phát hiện chỉ dấu bất thường về phiên bản và mẫu giải mã động, trả về mã lỗi (`Exit Code 1`) và hủy bỏ phiên cài đặt, bảo vệ an toàn cho máy trạm.
---

## 4. Hướng dẫn sử dụng & Vận hành công cụ

### Yêu cầu môi trường
- Hệ điều hành: Windows 10/11, Ubuntu 20.04/22.04 LTS hoặc macOS.
- Python: Phiên bản 3.10 trở lên.
- Node.js: Phiên bản 18.x LTS trở lên kèm `npm`.
- Docker & Docker Compose (dùng khi khởi chạy cụm registry cô lập).

### 1. Kiểm tra tính sẵn sàng của toàn bộ công cụ (Toolchain Verification)

Chạy lệnh tự động để kiểm tra toàn bộ các công cụ trong dự án:
```bash
python scripts/run_pipeline.py
```

### 2. Sử dụng từng công cụ độc lập

#### Quét phân tích gói bằng Detector đa lớp:
```bash
# Quét toàn bộ thư mục packages/
python scripts/detector.py packages

# Quét một package cụ thể và xuất kết quả ra file JSON
python scripts/detector.py packages/uit-core-auth --output logs/scan_result.json

# Quét với ngưỡng rủi ro tùy chỉnh (mặc định: 35)
python scripts/detector.py packages/uit-marker-lifecycle --threshold 50
```

#### Sử dụng CI/CD Security Gate:
```bash
# Kiểm tra package sạch (Kỳ vọng: PASS - Exit code 0)
python scripts/supply_chain_gate.py packages/uit-benign

# Kiểm tra package độc hại (Kỳ vọng: BLOCKED - Exit code 1)
python scripts/supply_chain_gate.py packages/uit-core-auth
```

#### Chạy công cụ giả lập lỗi toàn vẹn mã băm (Artifact Tampering):
```bash
python packages/uit-marker-tamper/simulate_tamper.py
```

#### Sử dụng công cụ sinh package thử nghiệm:
```bash
# Sinh 20 package thử nghiệm vào thư mục test_data/
python scripts/data_gen.py --count 20 --output ./test_data
```

#### Khởi chạy hạ tầng Docker cô lập:
```bash
docker compose -f infrastructure/docker-compose.yml up -d
```

---

## 5. Cấu trúc thư mục dự án

```text
.
├── infrastructure/                       # Cấu hình môi trường mạng & dịch vụ cô lập
│   ├── docker-compose.yml                # File duy nhất quản lý cụm Verdaccio + Victim
│   ├── verdaccio/
│   │   └── config.yaml                   # Cấu hình Air-gap vô hiệu hóa kết nối ngoài
│   └── victim-consumer/                  # Container mô phỏng môi trường nạn nhân
│       ├── Dockerfile                    # Image môi trường nạn nhân
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
│   ├── evaluate.py                       # Công cụ đo đạc hiệu năng (dùng khi cần thử nghiệm)
│   └── run_pipeline.py                   # Script tự động kiểm tra toàn bộ bộ công cụ        
│
├── logs/                                 # Thư mục lưu nhật ký viễn trắc khi vận hành
│   └── .gitkeep
│
├── D04_SupplyChain_Project.md            # Tài liệu kỹ thuật chi tiết của đồ án
├── README.md                             # Tài liệu kỹ thuật chính của dự án
└── .gitignore                            # Cấu hình loại trừ tệp rác và build cache
```

---

## 6. Khuyến nghị phòng ngừa tấn công chuỗi cung ứng trong doanh nghiệp

Dựa trên nghiên cứu cơ chế hoạt động của mã độc chuỗi cung ứng, các biện pháp phòng vệ cần được áp dụng:
1. **Sử dụng Không gian tên có phạm vi (Scoped Packages):** Khai báo các thư viện nội bộ dưới dạng `@organization/package-name` và thiết lập quyền sở hữu độc quyền trên kho lưu trữ chung để triệt tiêu hoàn toàn nguy cơ Dependency Confusion.
2. **Khóa chặt tính toàn vẹn qua Lockfile:** Luôn đưa tệp `package-lock.json` vào hệ thống quản lý phiên bản (Git). Trên môi trường tích hợp liên tục (CI/CD), bắt buộc sử dụng lệnh `npm ci` thay thế cho `npm install` để kiểm tra nghiêm ngặt mã băm SHA-512 của mọi tệp phụ thuộc.
3. **Vô hiệu hóa thực thi script tự động:** Chạy lệnh `npm install --ignore-scripts` trong các tác vụ kiểm thử hoặc đối với các thư viện không yêu cầu biên dịch C++ nội tại.
4. **Triển khai cổng kiểm soát tự động:** Tích hợp bộ quét mã chuỗi cung ứng vào quy trình tiền cài đặt (Pre-install Hook) nhằm phát hiện và ngăn chặn kịp thời các gói có số phiên bản hoặc cấu trúc script bất thường trước khi nạp vào hệ thống.
