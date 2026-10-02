# Đề tài có thể phát triển không?

**Có.** Dự án có nền tảng tốt cho đồ án hoặc khóa luận về sàng lọc nguy cơ Stack Buffer Overflow trong ELF. Để thành nghiên cứu có đóng góp rõ hoặc công cụ hỗ trợ kiểm toán, ưu tiên độ tin cậy của thực nghiệm, khả năng tổng quát và bằng chứng giải thích. Việc ghép thêm classifier đơn thuần chưa đủ tạo điểm mới: phát hiện lỗ hổng trên mã nhị phân bằng học máy đã có nghiên cứu trước, chẳng hạn [Deep-Learning-based Vulnerability Detection in Binary Executables](https://arxiv.org/abs/2212.01254).

## Giá trị đã có

Bạn đã làm nhiều hơn một bài phân loại bảng dữ liệu: có pipeline Ghidra/p-code, feature theo stack/buffer/sink/guard, baseline và ensemble, audit/ablation, thử giảm feature, cùng giao diện ELF. Mã Kaggle mới cung cấp công thức uncertainty `1 - 2|p - 0.5|`, biến đổi signed-log cho risk feature và cách kết hợp gate với xác suất model cơ sở. Những phần trước đây thiếu trong ZIP nay đã có nguồn để đối chiếu.

Định hướng nên tập trung: **“Sàng lọc nguy cơ tràn bộ đệm ngăn xếp trong ELF bằng đặc trưng ngữ nghĩa từ Ghidra, ưu tiên giảm cảnh báo nhầm và cung cấp bằng chứng ở mức hàm.”** Cụm “sàng lọc nguy cơ” phù hợp hơn tuyên bố công cụ chứng minh lỗ hổng hoặc phát hiện được mọi lỗi SBO.

## Vấn đề phải giải quyết trước khi khẳng định chất lượng

**Rò rỉ thông tin ở chọn feature.** Trong mã lịch sử, selector dùng seed 1337 còn trainer dùng seed 42; hai bước không dùng chung một test holdout. Với nhánh 160, `compute_audit` tính mutual information, tương quan nhãn và separation trên toàn bộ 36.963 dòng, rồi dùng điểm đó chọn feature trước khi chia test. Như vậy nhãn test có thể tác động vào thiết kế model; riêng luồng 160 thể hiện trực tiếp điều này trong code. Không thể coi các con số hiện tại là đánh giá độc lập hoàn toàn. Nguyên tắc chọn feature chỉ trên train cũng được nêu trong [tài liệu scikit-learn về data leakage](https://scikit-learn.org/1.8/common_pitfalls.html#data-leakage).

**Chia validation theo dòng.** Outer train/val/test của trainer có group split, nhưng meta/select trong validation lại dùng `train_test_split` theo dòng. Các biến thể cùng nguồn có thể xuất hiện ở cả nơi fit gate và nơi chọn ngưỡng. Protocol mới tách nhóm cả bốn tập.

**Tính tương đương train/runtime.** Vectorizer ELF chưa sinh một số cột `*_nonzero`; điền 0 không chứng minh feature đúng. Trước khi tăng độ phức tạp model, cần bộ kiểm tra lấy cùng một binary qua pipeline dữ liệu và qua app rồi so sánh từng feature.

**Khả năng tổng quát chưa được chứng minh.** Tên dữ liệu giống mẫu CWE121/Juliet, nhưng chưa có provenance xác nhận. Nếu chủ yếu là dữ liệu tổng hợp, cần thêm chương trình thật có phiên bản lỗi/bản vá hoặc nhãn được kiểm chứng. NIST SATE dùng cả chương trình sản xuất và test tổng hợp để xem các khía cạnh bổ sung của công cụ; đây là một tham khảo phù hợp cho thiết kế đánh giá, không phải bằng chứng dự án này đã đạt chất lượng tương tự. [NIST SATE V](https://www.nist.gov/itl/csd/secure-systems-and-applications/static-analysis-tool-exposition-sate-v).

## Các hướng phát triển đáng ưu tiên

| Hướng | Câu hỏi cần trả lời | Bằng chứng cần có |
|---|---|---|
| Giảm cảnh báo nhầm | Ở cùng recall, feature ngữ nghĩa có tăng precision so với RF và luật tĩnh? | Precision/FPR tại recall mục tiêu, PR-AUC, FP trên mỗi binary |
| Tổng quát qua cấu hình build | Model còn hiệu quả khi đổi compiler, mức tối ưu, strip symbol? | Các tập build mới từ nhóm nguồn không thuộc train; đánh giá tách từng yếu tố |
| Giải thích theo sink | Có chỉ ra buffer, phép ghi, bound/guard và vị trí liên quan không? | Bộ finding có nhãn thủ công và ví dụ TP/FP/FN |
| Rút gọn feature | 160 feature có giữ chất lượng và giảm chi phí không? | Cùng protocol, cùng model; thời gian Ghidra/feature/inference đo riêng |
| ML kết hợp luật | Hybrid có cải thiện so với chỉ ML và chỉ luật không? | Ablation độc lập, ngưỡng chọn bằng validation, kiểm tra calibration |

Giảm số feature trong CSV không tự làm Ghidra nhanh hơn: nếu script Java vẫn tính toàn bộ đặc trưng thì chi phí phân tích vẫn gần như giữ nguyên. Cần đo từng bước rồi mới tối ưu extractor.

## Lộ trình khả thi

1. **Củng cố thí nghiệm:** chạy protocol mới, lưu dataset hash/split/schema/environment, kiểm tra trùng mẫu và các template gần giống; lặp nhiều seed và báo cáo độ biến thiên. Dùng bootstrap theo nhóm nguồn nếu tính khoảng tin cậy để không giả định từng dòng độc lập.
2. **Đóng khoảng cách giữa train và app:** kiểm thử feature trên cùng binary, tích hợp stacking/gating bằng đúng công thức train, đối chiếu xác suất giữa notebook và app; đo riêng điểm heuristic.
3. **Tập trung một đóng góp:** chọn giảm false positive hoặc tổng quát qua compiler/optimization làm câu hỏi chính. So sánh với baseline đơn giản; xác định trước metric và tiêu chí chọn cấu hình.
4. **Kiểm chứng trên tập ngoài:** thêm chương trình thật, ghi nguồn và quy trình gán nhãn. Hoàn thiện xử lý timeout, tài nguyên và báo cáo bằng chứng trước khi dùng trong quy trình kiểm toán.

## Đánh giá mức độ sẵn sàng

- **Đồ án/portfolio:** có nền tảng rõ và demo hữu ích, nên tiếp tục phát triển.
- **Khóa luận/nghiên cứu:** khả thi nếu sửa thiết kế đánh giá và có câu hỏi đóng góp cụ thể; chưa thể bảo đảm tính mới hoặc khả năng công bố chỉ từ code hiện tại.
- **Công cụ dùng thực tế:** còn cần đánh giá ngoài tập mẫu, xử lý FP, đồng bộ feature và kiểm thử luồng ELF. Chưa đủ chứng cứ để gọi là công cụ phát hiện lỗ hổng đáng tin cậy trong sản xuất.

Các kết quả 260/160 hiện có nên trình bày là kết quả thăm dò. Luồng mới được bổ sung để phục vụ đánh giá tiếp theo; chưa có benchmark mới để thay thế số liệu cũ.
