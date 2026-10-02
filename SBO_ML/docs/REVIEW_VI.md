# Nhận xét dự án SBO ML — vòng xem xét ZIP ban đầu

**Cập nhật:** sau đánh giá này, tác giả đã cung cấp mã Kaggle. Đã bổ sung `training/` và notebook độc lập, xác định vấn đề rò rỉ dữ liệu khi chọn feature và thêm protocol chia nhóm trước. Xem [đánh giá mới](DEVELOPMENT_ASSESSMENT_VI.md) và [hướng dẫn train](TRAINING_KAGGLE.md). Các nhận xét về việc thiếu mã bên dưới mô tả ZIP ban đầu, không mô tả toàn bộ repository sau cập nhật.

## Đánh giá tổng thể

Phù hợp làm đồ án hoặc portfolio nghiên cứu về phân tích nhị phân và machine learning: có extractor Ghidra, model, metrics và giao diện demo tương đối đầy đủ. Điểm mạnh nằm ở luồng từ ELF đến kết quả theo hàm. Mức sẵn sàng cho sử dụng thực tế còn hạn chế vì thiếu pipeline huấn luyện tái lập, chưa chứng minh tính tương đương của feature runtime và chưa có kiểm thử trên chương trình độc lập.

## Điểm tốt

- Đặc trưng bao gồm instruction/p-code, CFG, stack, buffer, sink và ngữ cảnh guard/alias; phong phú hơn chỉ đếm API nguy hiểm.
- Có nhiều baseline và ensemble để so sánh, đồng thời lưu precision/recall/F1, ROC-AUC và confusion matrix.
- Metadata ghi cách chia dữ liệu theo `source_core`, một hướng hợp lý để tách các biến thể cùng nguồn. Chưa đủ dữ liệu để xác nhận việc chia thực sự không bị trùng nhóm.
- Có định vị function/entry và candidate finding để hỗ trợ kiểm tra thủ công.
- Model/schema và số liệu tương đối dễ theo dõi; toàn bộ model cơ sở có 260 tên feature.

## Các vấn đề quan trọng trong bản gốc

1. **Suy luận stacking/gating chưa đúng.** Trang CSV thử đưa thẳng 260 feature vào meta-model rồi fallback. Trang ELF tự dựng feature theo các alias, nhưng thiếu những cột như `u_RandomForest` và `diff_RandomForest_minus_XGBoost`, sau đó điền 0. Softmax gate có 3 lớp `[0, 1, 2]`, nhưng code lấy `predict_proba(... )[:, 1]` như xác suất lỗ hổng nhị phân. Xác suất lựa chọn nhánh của gate phải được kết hợp với model cơ sở theo đúng công thức huấn luyện. Bản gọn không cung cấp các lựa chọn này để dự đoán; artifact vẫn được giữ.

2. **Feature ELF chưa chứng minh tương đương feature huấn luyện.** `aggregate_list` của vectorizer gốc có count/sum/mean/max/min nhưng không tạo thống kê `*_nonzero` trong schema model. Căn chỉnh schema bằng 0 che khuất lỗi này; UI trước đây kiểm tra sau khi đã điền cột nên thường không báo thiếu. Bản gọn bổ sung báo cáo cột thiếu trước khi căn schema. Chưa tự suy đoán công thức huấn luyện để sửa extractor.

3. **Điểm luật tĩnh bị trình bày giống xác suất ML.** Trang ELF gốc tự thay xác suất bằng giá trị lớn hơn giữa xác suất model và điểm luật. Đây không phải đầu ra classifier đã được đo trong bảng metrics. Bản gọn mặc định tắt bước kết hợp và ghi rõ khi bật.

4. **Chọn model theo kết quả test.** Bản gốc dùng F1/recall trên test để tự chọn mặc định/fallback. Nếu tiếp tục tối ưu hệ thống bằng tập này, test không còn là đánh giá độc lập. Bản gọn dùng mặc định cố định Random Forest, không xếp hạng test để tự đổi model. Không thể xác minh cách chọn threshold lúc huấn luyện vì thiếu mã train.

5. **Khả năng tái lập còn yếu.** Không có train script/notebook, seed/split manifest, bước chọn 260 feature hoặc môi trường khóa đầy đủ. File requirements gốc không ghim phiên bản. Model ghi scikit-learn 1.6.1; nạp trên 1.8.0 tạo cảnh báo tương thích. Bản gọn ghi phiên bản quan sát được và không còn ẩn cảnh báo trong vectorizer.

6. **Đóng gói quá nặng và mã lặp.** ZIP chứa cả môi trường Linux `.venv`; CSV “sample” thực tế có 36.963 dòng. Hai trang lặp logic nạp và suy luận, đường dẫn sample trong trang CSV không đúng tên file. Bản gọn bỏ môi trường, lấy 200 mẫu, nén model và dùng `sbo_core.py` chung.

## Diễn giải kết quả

Theo metrics gốc, stacking + risk đạt recall 97,27%, precision 76,64%, F1 85,73%; có 2.706 true positive, 825 false positive và 76 false negative. Khoảng 23,36% cảnh báo của model này là cảnh báo nhầm trong tập test. Tỷ lệ false positive trên các hàm thực sự không lỗi là 825/4.664, khoảng 17,69%.

Random Forest có precision 77,47%, recall 95,79%, F1 85,66%. Chênh F1 với stacking chỉ khoảng **0,064 điểm phần trăm** trong lần chạy được lưu. Chưa có khoảng tin cậy hoặc nhiều seed để kết luận ensemble tốt hơn một cách ổn định.

Đã đối chiếu confusion matrix với 7.446 dự đoán lưu sẵn cho 9 model có cột tương ứng: đều khớp. Điều này xác nhận tính nhất quán nội bộ của file kết quả, không xác nhận dữ liệu độc lập, nhãn chính xác hay năng lực phát hiện trên phần mềm thực tế.

## Những thay đổi của bản gọn

- Giữ script Java và phần phân tích ELF; không rút bỏ thuật toán extractor chỉ để giảm số dòng.
- Tách suy luận model cơ sở/weighted voting thành module chung; bỏ phần suy luận meta-model phỏng đoán.
- Không fallback hoặc tự bỏ thành phần có trọng số dương khi thiếu model.
- Chuẩn hóa đường dẫn demo; schema được lưu riêng dưới dạng JSON.
- Dùng một worker khi dự đoán model có `n_jobs`, phù hợp môi trường demo hạn chế tài nguyên.
- Model được nén trực tiếp từ byte gốc bằng zlib; joblib đọc được định dạng này. Không train lại, không thay trọng số, không chuyển phiên bản serialization. Manifest lưu hash trước/sau.
- Giữ toàn bộ bảng metrics và 10 artifact model; bỏ `test_predictions.csv` và phần lớn dữ liệu mẫu để giảm dung lượng.
- Dữ liệu demo lấy mẫu reservoir với seed 42, 100 dòng mỗi lớp; không dùng mẫu này để báo cáo benchmark.
- Thêm README, gitignore, gitattributes, 6 bài kiểm tra hồi quy và bản ghi kiểm chứng.

## Việc nên làm tiếp

Script train và cơ chế lưu manifest đã được bổ sung ở vòng tiếp theo. Ưu tiên chạy lại protocol mới và kiểm tra feature runtime trên cùng một binary so với pipeline tạo dữ liệu train. Khi hai bước này ổn định, khôi phục công thức stacking/gating từ mã huấn luyện, đánh giá riêng ML và hybrid trên tập ngoài, rồi mới mở rộng triển khai. Cần bổ sung tài liệu nguồn dữ liệu, giấy phép và ít nhất một bộ ELF kiểm thử có nhãn rõ ràng.

Chưa có LICENSE trong archive; bản đóng gói không tự gán quyền sở hữu hoặc quyền phân phối thay tác giả.
