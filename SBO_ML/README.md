# SBO Detector

Demo nghiên cứu phát hiện **nguy cơ Stack Buffer Overflow ở mức hàm** bằng đặc trưng phân tích tĩnh và machine learning. Có hai luồng: đọc CSV đặc trưng hoặc phân tích ELF bằng Ghidra rồi dự đoán.

**Trạng thái:** bản demo đã tinh gọn để chia sẻ mã nguồn. Chưa phải công cụ xác nhận lỗ hổng; cần kiểm tra thủ công các cảnh báo. Chưa kiểm thử toàn bộ luồng ELF trong môi trường đóng gói.

## Tính năng

- Giao diện Streamlit, xuất kết quả CSV.
- 260 đặc trưng; Random Forest, Decision Tree, XGBoost, Logistic Regression và weighted voting.
- Trích xuất đặc trưng từ ELF bằng Ghidra headless và script Java.
- Dữ liệu demo 200 hàm, 100 dòng mỗi lớp; đây không phải tập đánh giá độc lập.
- Lưu toàn bộ artifact model gốc dưới dạng nén không mất dữ liệu; có SHA-256 để kiểm tra.

Stacking và dynamic gating được giữ dưới dạng artifact nghiên cứu. Mã train Kaggle và công thức ensemble đã được bổ sung, nhưng chưa tích hợp/kiểm chứng suy luận các model này trong app nên chúng chưa có trong danh sách dự đoán. Xem [đánh giá kỹ thuật ban đầu](docs/REVIEW_VI.md) và [đánh giá phát triển cập nhật](docs/DEVELOPMENT_ASSESSMENT_VI.md).

## Huấn luyện trên web (Kaggle)

Mở [SBO_Kaggle_Training.ipynb](notebooks/SBO_Kaggle_Training.ipynb) trên Kaggle và cung cấp CSV dữ liệu gốc. Notebook đã nhúng mã train; hỗ trợ thử 260 hoặc 160 đặc trưng, chia nhóm trước khi chọn feature và xuất model/schema/metrics/split manifest. [Hướng dẫn chi tiết](docs/TRAINING_KAGGLE.md).

Mã lịch sử có nguy cơ rò rỉ dữ liệu qua chọn feature, đặc biệt nhánh 160 dùng nhãn toàn bộ dataset để audit/chọn cột. Số liệu cũ bên dưới là kết quả thăm dò; chưa có kết quả huấn luyện lại theo protocol mới. Bộ dữ liệu gốc 654 cột chưa được cung cấp trong repository.

## Chạy demo CSV

Môi trường gốc trong ZIP sử dụng Python 3.13 trên Linux. `requirements.txt` ghi lại phiên bản trực tiếp từ metadata của môi trường gốc và scikit-learn 1.6.1 từ model. Chưa xác nhận cài mới được toàn bộ các phiên bản này trên một máy sạch; không phải lockfile đầy đủ.

Tại thư mục dự án:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Ứng dụng tự nạp 200 dòng mẫu nếu chưa tải CSV lên. Model mặc định là Random Forest. CSV cần có đầy đủ các cột trong `models/sbo_detector/feature_columns.json`; thứ tự cột được tự căn chỉnh. Giá trị trống/vô hạn được điền 0 như bản gốc; cột thiếu hoặc văn bản không phải số sẽ báo lỗi.

CSV có thể chạy riêng, không cần Ghidra. Nếu một model không nạp được, app hiển thị lỗi và ẩn các lựa chọn phụ thuộc vào model đó; không tự chuyển sang mô hình khác để trả kết quả.

## Phân tích ELF

Cần Ghidra và JDK tương thích với bản Ghidra đang dùng. Luồng này giữ cách chạy Linux của dự án gốc; khi dùng Windows, nên chạy trong môi trường Linux/WSL đã cài đủ công cụ.

```bash
export GHIDRA_HEADLESS=/path/to/ghidra/support/analyzeHeadless
python -m streamlit run app.py
```

Mở trang **Upload ELF**, chọn ELF và chạy phân tích. Có thể chạy riêng bước trích xuất:

```bash
python scripts/elf_to_features_generic.py \
  --elf /path/to/program \
  --out-csv runtime/features.csv \
  --model-dir models/sbo_detector \
  --work-dir runtime/analysis/example \
  --script-dir ghidra_scripts
```

Extractor căn schema và điền 0 cho các cột không sinh được. Danh sách cột thiếu được ghi trong file `.info.json` và hiển thị trên trang ELF. Cần kiểm tra lại sự tương đương với pipeline huấn luyện trước khi dùng kết quả để kết luận. Đặc biệt, vectorizer gốc chưa tính các thống kê `*_nonzero` có trong schema.

Chế độ **Kết hợp điểm luật tĩnh** mặc định tắt. Khi bật, kết quả là `max(model_prob, static_finding_score)`, một điểm ưu tiên kiểm tra, không phải xác suất đã hiệu chuẩn. Các benchmark bên dưới không đánh giá chế độ này. Nhãn `SAFE` còn có trong trang ELF kế thừa từ bản gốc chỉ có nghĩa là dưới ngưỡng cảnh báo.

Chỉ nạp các file model `.joblib` có nguồn đáng tin cậy. Luồng ELF dùng phân tích tĩnh, không chạy chương trình được tải lên. Thư mục `runtime/` chứa đầu vào/kết quả cục bộ và được bỏ qua bởi Git.

## Kết quả được cung cấp trong archive

Tập test có 7.446 hàm. `run_info.json` ghi train/validation/test lần lượt là 22.010 / 7.507 / 7.446 dòng và cách chia theo nhóm `source_core`. Mã huấn luyện được bổ sung từ phiên Kaggle, nhưng chưa có manifest của lần chạy lịch sử để kiểm chứng độc lập. Protocol mới lưu manifest cho các lần train tiếp theo.

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|
| Random Forest | 77,47% | 95,79% | 85,66% | 0,9677 |
| Decision Tree | 76,62% | 96,12% | 85,27% | 0,9605 |
| XGBoost | 75,54% | 94,79% | 84,07% | 0,9615 |
| Stacking + risk (tham khảo) | 76,64% | 97,27% | 85,73% | 0,9682 |

Đây là số liệu lưu sẵn, không phải kết quả tái huấn luyện. Đã đối chiếu confusion matrix của 9 model có cột xác suất tương ứng trong `test_predictions.csv` gốc; cả 9 khớp. File dự đoán đầy đủ được bỏ khỏi bản gọn.

## Cấu trúc

```text
app.py                         Giao diện CSV
sbo_core.py                    Suy luận dùng chung
pages/1_Upload_ELF.py           Giao diện ELF và phân tích bằng luật
scripts/elf_to_features_generic.py
ghidra_scripts/ExtractSBOFeatureRaw.java
models/sbo_detector/            Model nén, schema và metrics
samples/                       200 dòng demo và thông tin lấy mẫu
tests/                         Kiểm tra hồi quy phần suy luận
training/                      Train, chọn feature, audit và protocol chia nhóm
notebooks/                     Notebook Kaggle độc lập
docs/                          Đánh giá và kết quả kiểm tra
```

## Kiểm tra và giới hạn

```bash
python -m unittest discover -s tests -v
```

Đã chạy 11 bài kiểm tra, gồm 5 kiểm tra protocol huấn luyện mới và 6 kiểm tra suy luận: trọng số và thứ tự lớp, thiếu model thành phần, loại ensemble chưa hỗ trợ, thiếu feature, giá trị không hợp lệ, và toàn vẹn model nén. Random Forest, Decision Tree, Logistic Regression dự đoán trên 200 dòng mẫu trùng với artifact gốc trong cùng môi trường kiểm tra; hai weighted ensemble khả dụng cũng chạy thành công.

Môi trường kiểm tra có Python 3.14 / scikit-learn 1.8.0, khác môi trường huấn luyện; các kiểm tra này không thay thế việc chạy lại bằng scikit-learn 1.6.1. Chưa chạy giao diện Streamlit, XGBoost, biên dịch Java hoặc luồng Ghidra hoàn chỉnh vì môi trường kiểm tra thiếu các thành phần đó. Chi tiết kiểm tra demo trước khi thêm mã train: [verification.json](docs/verification.json). Kiểm tra mới: [training_verification.json](docs/training_verification.json).

## Đưa lên GitHub

Giải nén bản gọn và đưa **nội dung thư mục dự án** lên repository. Giữ các file `.gitignore` và `.gitattributes`; không chép lại `.venv` hoặc thư mục `runtime`.

Mô tả repository gợi ý: **Function-level stack buffer overflow risk screening with Ghidra, machine learning, and Streamlit.**

## Nguồn dữ liệu và giấy phép

Tên mẫu trong archive có dạng `CWE121_Stack_Based_Buffer_Overflow__...`, nhưng không có tài liệu nguồn dữ liệu hay LICENSE kèm theo. Bản gọn giữ nguyên thông tin hiện có và chưa tự gán giấy phép. Tác giả cần bổ sung nguồn dữ liệu, quyền phân phối model/dữ liệu và giấy phép phù hợp cho mã nguồn trước khi công bố như một dự án mã nguồn mở.
