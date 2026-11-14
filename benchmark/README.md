# Benchmark trên dữ liệu thật

Đo `scripts/detector.py` trên 1000 gói npm thật: 500 gói độc (bộ DataDog `malicious-software-packages-dataset`, mục npm) và 500 gói phổ biến (npm registry). Kết quả và phân tích đầy đủ trong `report/baocao_benchmark.pdf`.

## Kết quả (ngưỡng 35)

| | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Dataset tổng hợp (`data_gen.py`) | 100% | 100% | 100% | 0% |
| Dữ liệu thật | 78,9% | 66,6% | 72,2% | 17,8% |

Ma trận nhầm lẫn (dữ liệu thật): TP 333, FP 89, TN 411, FN 167. Layer 1 một mình cho F1 75,2% và FPR 1,6%; Layer 3 hiện không phát hiện mẫu nào.

## Tái lập

Mẫu độc **không** nằm trong repo. Chỉ làm trong VM Ubuntu cô lập, tuyệt đối không chạy `npm install` hay `node` trên các gói này.

1. Lấy dataset DataDog (chỉ thư mục npm) và chọn 500 mẫu ngẫu nhiên, seed cố định:
   ```bash
   mkdir -p ~/d04_real && cd ~/d04_real
   git clone --depth 1 --filter=blob:none --sparse https://github.com/DataDog/malicious-software-packages-dataset.git
   cd malicious-software-packages-dataset && git sparse-checkout set samples/npm
   git ls-tree -r --name-only HEAD samples/npm | grep '\.zip$' > ~/d04_real/all_zips.txt
   shuf -n 500 --random-source=<(yes) ~/d04_real/all_zips.txt | sed 's|^|/|' > ~/d04_real/pick.txt
   git sparse-checkout init --no-cone
   git sparse-checkout set --no-cone --stdin < ~/d04_real/pick.txt
   ```
2. Giải nén mẫu độc (mật khẩu zip là `infected`): `bash benchmark/extract_malicious.sh`
3. Tải 500 gói sạch phổ biến: `python3 benchmark/get_benign.py` (tải `.tgz` trực tiếp, không chạy script cài đặt; kết quả phụ thuộc thời điểm tải).
4. Dựng nhãn và chạy đánh giá (mất khoảng 16 phút):
   ```bash
   python3 benchmark/make_gt.py
   cd scripts && python3 evaluate.py --dataset ~/d04_real/combined --log ~/d04_real/logs/telemetry_real.json
   ```
5. Phân tích ngưỡng và đóng góp từng lớp: `python3 benchmark/analyze.py`

## Benchmark tĩnh cho detector hiện tại (dev/test)

`bench_real.py` quét một lượt 1000 gói thật **chỉ bằng Layer 1+2** (Layer 3 và mọi lệnh tạo tiến trình bị chặn trong code, vì tập dữ liệu chứa mã độc thật). Script chia kết quả theo dev/test và ablation theo lớp; nửa test chỉ chạy với `--final`.

```bash
python3 benchmark/bench_real.py --part dev            # chỉnh luật theo kết quả dev
python3 benchmark/bench_real.py --part all --final    # chạy MỘT lần cuối, báo cáo test
python3 benchmark/dataset_stats.py --latex            # thống kê dữ liệu cho báo cáo
```

Đầu ra nằm ở `~/d04_real/logs/` (`static_*.json`, `fp_static_dev.csv`, `fn_static_dev.csv`).

## Hạn chế

Tỷ lệ 50/50 là nhân tạo, nhãn "sạch" là giả định, mẫu độc chủ yếu thuộc loại `malicious_intent`. Xem mục Hạn chế trong báo cáo.
