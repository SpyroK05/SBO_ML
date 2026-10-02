# Huấn luyện trên Kaggle

Phần này được bổ sung từ mã và log Kaggle do tác giả cung cấp sau bản ZIP ban đầu. Đã tách 6 script Python khỏi cell magic, lệnh shell và log. Có thêm notebook độc lập và luồng chia nhóm trước khi chọn đặc trưng.

## Chạy notebook

1. Mở/import `notebooks/SBO_Kaggle_Training.ipynb` trong Kaggle.
2. Cung cấp CSV gốc `dataset_labeled_sbo_rich_v6_context_clean.csv`, hoặc tar.gz chứa CSV này. Log gốc ghi 36.963 dòng, 654 cột. File này chưa có trong bản GitHub; CSV demo 200 dòng không thay thế được.
3. Chọn `FEATURE_COUNT = 260` hoặc `160`; mặc định CPU, 4 worker, seed 42.
4. Chạy các cell theo thứ tự. Có thể bật `PREPARE_ONLY` để chỉ kiểm tra cách chia dữ liệu. Cell cài dependencies mặc định tắt; chỉ bật khi môi trường cần cài lại các package.
5. Tải `SBO_training_artifacts.zip` ở cuối notebook. Mỗi lần chạy tạo thư mục riêng, không xóa kết quả cũ.

Notebook nhúng mã nguồn cần thiết nên không phải upload riêng repository. Sau khi sửa script, sinh lại notebook bằng:

```bash
python training/build_notebook.py
```

## Chạy bằng dòng lệnh

```bash
python -m pip install -r requirements-training.txt
python training/run_experiment.py \
  --data /path/to/dataset_labeled_sbo_rich_v6_context_clean.csv \
  --out-dir experiments/run_260_seed42 \
  --features 260 --seed 42 --n-jobs 4
```

Thay `--features 160` để thử bản 160; phải dùng thư mục output mới. Không tự chuyển sang random split nếu thiếu `source_core` hoặc thiếu nhóm.

`requirements-training.txt` ghi pandas 2.3.3, scikit-learn 1.6.1 và XGBoost 3.2.0 theo log train. Numpy/joblib/matplotlib chỉ có khoảng phiên bản vì log không ghi đủ; đây chưa phải lockfile tái lập hoàn toàn. `requirements.txt` của app vẫn phản ánh môi trường demo ban đầu, không phải môi trường train Kaggle.

## Luồng mới và khác biệt với mã lịch sử

```text
CSV gốc
  → chia nhóm source_core: train / meta / select / test
  → chỉ train: xếp hạng RF + ExtraTrees + MI, correlation pruning
  → chỉ train: audit + chọn 160 nếu được yêu cầu
  → áp dụng cùng danh sách feature lên mọi tập
  → train: fit bốn model cơ sở
  → meta: fit stacking/gating
  → select: chọn trọng số/threshold ensemble
  → test: tính metrics
```

Threshold model cơ sở giữ cách chọn trên toàn bộ validation của script gốc. Tham số `recall_min` áp dụng cho việc chọn ensemble, không bảo đảm recall tối thiểu trên test và không được áp dụng vào lời gọi chọn threshold model cơ sở trong mã gốc.

Lưu `source_split_manifest.json`, `split_manifest.json`, hash CSV, chỉ số từng dòng, seed, tham số và phiên bản thư viện. Khi dùng manifest để train, script kiểm tra hash dữ liệu, độ bao phủ dòng và không trùng nhóm giữa bốn tập. Group split vẫn phụ thuộc định nghĩa `source_core`: các mẫu khác tên nhưng cùng template vẫn có thể tương tự nhau. Đây chưa thay thế đánh giá theo họ template hoặc theo dự án ngoài.

Các công thức model, cách tìm trọng số và cách chọn feature được giữ từ mã tác giả. Sửa cách phân chia dữ liệu sẽ thay đổi feature được chọn và kết quả; không gán metrics cũ cho model mới. Chưa chạy full training của luồng mới vì chưa có CSV gốc 654 cột và môi trường hiện tại thiếu XGBoost.

## Sáu script khôi phục

| Script | Vai trò |
|---|---|
| `train_sbo_v5_ensemble_suite_kaggle.py` | Bốn model cơ sở, weighted voting, stacking, pair gate, softmax gate |
| `make_v6_noise_pruned_datasets.py` | Xếp hạng feature và loại tương quan cao |
| `analyze_v6_top260_components.py` | Báo cáo thành phần feature, hình thống kê |
| `make_top260_group_drop_ablation.py` | Tạo dataset bỏ từng nhóm feature |
| `export_feature_inventory_for_review.py` | Audit feature theo nhãn và importance |
| `select_final_security_features.py` | Chọn bộ 160 theo điểm, quota và tương quan |

Trainer được bổ sung `--split-manifest`, xuất `feature_columns.json`, seed, tham số và phiên bản thư viện; không còn ẩn toàn bộ warning. Script chọn 160 được sửa `proxy_flags` trống bị pandas đọc thành NaN, khiến `proxy_count` trong log cũ tính cả các dòng không có cờ. Không thay các giá trị metrics lịch sử.

`source_manifest.json` lưu hash phần code được tách từ tài liệu và hash file đã đóng gói, đánh dấu những file có sửa. Không đưa nguyên transcript có log/lệnh xóa thư mục vào notebook thực thi.

## Kết quả lịch sử 160 feature

Các số dưới đây chép từ log tác giả, chưa được tái huấn luyện trong phiên này:

| Model | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|
| WEIGHT_RF_DT | 76,15% | 96,08% | 84,97% | 837 | 109 |
| RandomForest | 76,16% | 95,97% | 84,92% | 836 | 112 |
| STACK_LOGISTIC_PROB_RISK | 75,43% | 97,02% | 84,87% | 879 | 83 |

Giảm 260 xuống 160 feature là giảm 38,46% số cột. So sánh riêng Random Forest, F1 từ 85,66% xuống 84,92%, giảm khoảng 0,740 điểm phần trăm. So sánh model có F1 cao nhất trong mỗi bảng, mức giảm khoảng 0,763 điểm phần trăm nhưng đó là hai loại model khác nhau. Chưa có đo thời gian/RAM hoặc benchmark theo protocol mới nên chưa kết luận ứng dụng nhanh hơn hay tổng quát tốt hơn.

Model 160 feature trong log không được đính kèm; bundle demo vẫn là model 260 feature gốc. Khi đưa model mới vào app phải thay đồng bộ model, schema, metrics, run_info và CSV mẫu. Stacking/gating vẫn chưa được bật trong app; nay đã có công thức train để thực hiện tích hợp và đối chiếu ở bước tiếp theo.

## Kiểm chứng đã thực hiện

```bash
python -m unittest discover -s tests -v
```

11 bài kiểm tra đạt: 6 kiểm tra suy luận/nén model trước đó và 5 kiểm tra protocol mới. Đã phân tích cú pháp các file Python và 7 cell code của notebook; chạy `--prepare-only` trên 36.963 dòng dữ liệu cũ để xác nhận bốn tập không giao nhau theo nhóm. Đây không phải full training.

Môi trường kiểm tra scikit-learn 1.8.0 cho split khác log train 1.6.1. Vì vậy các số tái dựng trong `training_verification.json` chỉ là chẩn đoán, không phải số nhóm/dòng giao nhau đã được xác nhận trong lần chạy lịch sử. Cần môi trường gốc và split manifest để tái lập chính xác.
