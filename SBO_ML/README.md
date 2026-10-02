# SBO Detector

SBO Detector là dự án nghiên cứu sử dụng phân tích tĩnh và học máy để sàng lọc nguy cơ **Stack Buffer Overflow (SBO)** trong chương trình ELF. Mục tiêu của dự án là giúp người phân tích xác định những hàm cần kiểm tra trước, dựa trên đặc trưng trích xuất bằng Ghidra.

Bạn có thể thử các model bằng CSV mẫu đi kèm, phân tích một file ELF của mình, hoặc sử dụng notebook để huấn luyện trên Kaggle. Giao diện được xây dựng bằng Streamlit và hỗ trợ tải kết quả về dưới dạng CSV.

Dự án đang trong quá trình hoàn thiện. Kết quả dự đoán cần được đối chiếu với mã và bằng chứng phân tích; một hàm không bị cảnh báo vẫn có thể chứa lỗi.

## Bắt đầu từ đâu?

- **Muốn xem thử ứng dụng:** chạy demo CSV bên dưới. Cách này không cần cài Ghidra.
- **Muốn phân tích ELF:** cài thêm Ghidra và làm theo mục Phân tích ELF.
- **Muốn huấn luyện lại:** mở notebook Kaggle và chuẩn bị bộ dữ liệu gốc.

## Chạy demo CSV

Các lệnh dưới đây dành cho Linux hoặc WSL. Môi trường ứng dụng ban đầu dùng Python 3.13; các phiên bản thư viện được ghi trong `requirements.txt`. Việc cài mới toàn bộ môi trường này chưa được kiểm chứng trên máy sạch.

Mở terminal tại thư mục dự án và chạy:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Sau đó mở địa chỉ mà Streamlit hiển thị trong terminal.

Ứng dụng sẽ tự nạp 200 dòng dữ liệu mẫu và chọn Random Forest làm model mặc định. Bạn có thể đổi model, điều chỉnh ngưỡng cảnh báo và tải bảng kết quả về để xem lại. Dữ liệu mẫu chỉ dùng để thử giao diện, không phải một tập test độc lập.

Nếu dùng CSV riêng, file cần có đủ 260 cột đặc trưng trong [feature_columns.json](models/sbo_detector/feature_columns.json). Các cột được tự sắp xếp theo thứ tự model yêu cầu. Giá trị trống hoặc vô hạn được thay bằng 0; thiếu cột hoặc có văn bản trong cột đặc trưng sẽ báo lỗi.

Các model hiện có thể chọn trong app gồm Random Forest, Decision Tree, XGBoost, Logistic Regression và weighted voting. Nếu model nào không nạp được, ứng dụng sẽ hiển thị lỗi và ẩn những lựa chọn phụ thuộc vào model đó.

## Phân tích ELF

Bạn cần cài Ghidra cùng JDK phù hợp với phiên bản Ghidra đang dùng. Luồng phân tích hiện được thiết kế cho Linux; nếu dùng Windows, hãy chuẩn bị môi trường WSL để chạy phần này.

Khai báo đường dẫn đến `analyzeHeadless`, thay đường dẫn ví dụ bằng vị trí cài Ghidra trên máy:

```bash
export GHIDRA_HEADLESS=/path/to/ghidra/support/analyzeHeadless
python -m streamlit run app.py
```

Trong ứng dụng:

1. Mở trang **Upload ELF**.
2. Kiểm tra đường dẫn Ghidra và thư mục model.
3. Chọn file ELF, model và ngưỡng cảnh báo.
4. Nhấn **Chạy Ghidra và dự đoán**.
5. Xem kết quả theo hàm, các bằng chứng liên quan và tải báo cáo CSV nếu cần.

Luồng xử lý:

```text
ELF → Ghidra → đặc trưng của từng hàm → model → bảng kết quả
```

Ứng dụng phân tích tĩnh, không chạy chương trình ELF được tải lên. File đầu vào và kết quả được lưu trong `runtime/`; thư mục này đã được loại khỏi Git.

Bạn cũng có thể chạy riêng bước trích xuất đặc trưng:

```bash
python scripts/elf_to_features_generic.py \
  --elf /path/to/program \
  --out-csv runtime/features.csv \
  --model-dir models/sbo_detector \
  --work-dir runtime/analysis/example \
  --script-dir ghidra_scripts
```

**Lưu ý khi đọc kết quả:** một số đặc trưng, trong đó có các thống kê `*_nonzero`, chưa được vectorizer ELF sinh đầy đủ. Các cột thiếu được điền 0 và liệt kê trong file `.info.json`. Cần kiểm tra cảnh báo này trước khi sử dụng kết quả để đánh giá một binary.

Tùy chọn **Kết hợp điểm luật tĩnh** mặc định tắt. Khi bật, điểm hiển thị kết hợp đầu ra ML với các luật phân tích; điểm này chưa được hiệu chuẩn thành xác suất. Nhãn `SAFE` trên trang ELF chỉ có nghĩa là dưới ngưỡng cảnh báo.

## Huấn luyện trên Kaggle

Mở [SBO_Kaggle_Training.ipynb](notebooks/SBO_Kaggle_Training.ipynb) trong Kaggle. Notebook đã chứa mã cần thiết; bạn chỉ cần cung cấp CSV gốc `dataset_labeled_sbo_rich_v6_context_clean.csv`, hoặc file `.tar.gz` chứa CSV đó.

Bộ dữ liệu gốc 654 cột không nằm trong repository. Không dùng CSV mẫu 200 dòng để thay thế khi đánh giá chất lượng model.

Notebook hỗ trợ thử nghiệm với 260 hoặc 160 đặc trưng. Quy trình mới chia nhóm dữ liệu trước khi chọn đặc trưng, sau đó lưu model, danh sách feature, metrics và thông tin phân chia dữ liệu để tiện kiểm tra lại.

Xem [hướng dẫn huấn luyện](docs/TRAINING_KAGGLE.md) để biết cách cấu hình, yêu cầu thư viện và xuất kết quả. Khi sử dụng model mới trong app, cần cập nhật đồng bộ model, schema, metrics và dữ liệu mẫu tương ứng.

## Kết quả thử nghiệm

Bảng dưới là kết quả đã lưu của lần thử nghiệm với 260 đặc trưng, trên tập test gồm 7.446 hàm:

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|
| Random Forest | 77,47% | 95,79% | 85,66% | 0,9677 |
| Decision Tree | 76,62% | 96,12% | 85,27% | 0,9605 |
| XGBoost | 75,54% | 94,79% | 84,07% | 0,9615 |
| Stacking + risk | 76,64% | 97,27% | 85,73% | 0,9682 |

Các số liệu này được giữ để tham khảo. Quy trình chọn đặc trưng trước đây có nguy cơ rò rỉ thông tin giữa dữ liệu dùng để phát triển model và tập test. Chưa có kết quả huấn luyện lại theo quy trình chia nhóm mới, nên chưa dùng bảng này để khẳng định hiệu quả trên phần mềm thực tế.

Mã huấn luyện và model stacking/gating có trong repository, nhưng phần suy luận của chúng chưa được tích hợp và kiểm chứng trong app.

## Cấu trúc dự án

```text
app.py                    Giao diện dự đoán từ CSV
sbo_core.py               Phần suy luận dùng chung
pages/                    Trang phân tích ELF
scripts/                  Chuyển kết quả Ghidra thành CSV đặc trưng
ghidra_scripts/           Script trích xuất đặc trưng bằng Ghidra
models/sbo_detector/      Model, schema và kết quả thử nghiệm
samples/                  Dữ liệu để chạy thử
training/                 Mã huấn luyện, chọn đặc trưng và phân tích
notebooks/                Notebook Kaggle
tests/                    Các bài kiểm tra tự động
docs/                     Hướng dẫn và ghi nhận kỹ thuật
```
