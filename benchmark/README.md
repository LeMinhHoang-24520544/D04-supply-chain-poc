# Benchmark trên dữ liệu thật

Đo `scripts/detector.py` trên 1000 gói npm thật: 500 gói độc (bộ DataDog `malicious-software-packages-dataset`, mục npm) và 500 gói phổ biến (npm registry). Kết quả và phân tích đầy đủ trong `report/baocao_benchmark.pdf`.

## Kết quả (ngưỡng 35)

| Tập đánh giá | Chế độ | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Dataset tổng hợp (`data_gen.py`, 100 gói) | Đầy đủ (3 lớp) | 100,0% | 68,9% | 81,6% | 0,0% |
| Tập thật DEV (501 gói: 251 độc, 250 sạch) | Tĩnh có cổng (`L1+L2`) | 100,0% | 65,3% | 79,0% | 0,0% |
| Tập thật TEST (440 gói: 190 độc, 250 sạch) | Tĩnh có cổng (`L1+L2`) | 94,6% | 64,2% | 76,5% | 2,8% |
| Bộ né tránh (`460` gói: `16` biến thể + `7` sạch) | Tĩnh (`L1+L2`) / Đầy đủ (`L1+L2+L3`) | 100,0% | 100,0% | 100,0% | 0,0% |
| Gói sạch ngẫu nhiên npm (`240` gói unseen) | Tĩnh có cổng (`L1+L2`) | — | — | — | 0,4% |
| Gói sạch có install hook (`167` gói long-tail unseen) | Tĩnh có cổng (`L1+L2`) | — | — | — | 24,0% |

Ma trận nhầm lẫn trên dữ liệu thật (ngưỡng 35): DEV `TP=164, FP=0, TN=250, FN=87`; TEST `TP=122, FP=7, TN=243, FN=68` (`L1 manifest` FPR `0,0%`). Báo cáo nền v1 trước đây (`Precision 78,9%`, `Recall 66,6%`, `F1 72,2%`, `FPR 17,8%`) được lưu tham chiếu trong `benchmark/report/baocao_benchmark.pdf`.

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
python3 benchmark/bench_real.py --part dev                    # đánh giá trên nửa dev (NAT tắt)
python3 benchmark/bench_real.py --part test --final           # chạy tập test độc lập (chống rò rỉ, NAT tắt)
python3 benchmark/bench_real.py --part all --final            # chạy gộp cả dev và test
python3 benchmark/bench_hook_benign.py --target 240 --any-benign --random  # lấy mẫu ngẫu nhiên gói sạch npm
python3 benchmark/bench_hook_benign.py --target 240 --random               # stress-test gói sạch có install hook
python3 benchmark/dataset_stats.py --latex                    # thống kê dữ liệu cho báo cáo
```

Đầu ra của `bench_real.py` nằm ở `~/d04_real/logs/` (`<tag>_dev.json`, `<tag>_test.json`, `fp_<tag>_dev.csv`, `fn_<tag>_dev.csv`); đầu ra của `bench_hook_benign.py` nằm ở `logs/` (`<tag>.json`, `<tag>_fp.csv`).

## Hạn chế

Tỷ lệ 50/50 là nhân tạo, nhãn "sạch" là giả định, mẫu độc chủ yếu thuộc loại `malicious_intent`. Xem mục Hạn chế trong báo cáo.
