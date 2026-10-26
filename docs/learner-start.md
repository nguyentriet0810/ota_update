# Bắt đầu tự học với bộ firmware tham khảo

Firmware, signed releases và logs hiện có do trợ lý chuẩn bị/chạy thử để bạn
tham khảo trước. Bạn chưa học hoặc tự làm các bài; Status của E01–E12 là
**Not started**, toàn bộ checklist hoàn thành chưa tích. Trợ lý chỉ cập nhật
tiến độ học khi bạn yêu cầu sau khi tự thực hiện.

Giữ `D:\ota_update` và các release làm bản đối chiếu. Tạo thư mục bài làm/log
riêng, chẳng hạn `evidence/my-practice/E01/`, để không trộn kết quả tham khảo với
lượt chạy của bạn. Đọc bài, dự đoán kết quả rồi tự làm và so sánh. Không chỉ
copy trạng thái PASS của bộ mẫu sang bài nộp.

Lần cuối được ghi nhận, board chạy mẫu8.0.1/code10 VALID. Policy OTA từ chối
candidate có version_code<=10; các ví dụ v1/v2 của lộ trình học không thể OTA
trực tiếp vào trạng thái này. Khi bạn bắt đầu thực hành, chọn baseline phù hợp
theo E01–E02 và signed trust/bootstrap theo E08, hoặc tạo candidate có code mới
hơn cho một bài riêng. Provision serial thay baseline là bước bạn tự chọn khi
sẵn sàng, cần backup và bộ bootloader/table/app đúng layout. Không xóa NVS hoặc
sửa otadata để lách version policy.

SDK v6.1 đã cài riêng; v5.3.1 vẫn giữ nguyên. Các ví dụ Bash trong giáo trình là
dạng tổng quát; máy này dùng PowerShell, COM đã quan sát là13 và các script ở
`tools/`. Luôn kiểm lại port/module/nguồn trước khi tự nạp. Signing keys, Wi-Fi
và Flash backup riêng không nằm trong Git; giữ chúng riêng khi tạo workspace
thực hành. Bộ khóa mới cần baseline tin đúng khóa, không chỉ đổi key ký candidate.

Nội dung chính đã được bổ sung theo các phát hiện của bản mẫu: HTTP TX buffer
cho GitHub redirect, fresh full-slot erase, checkpoint policy2, UART ISR IRAM,
giới hạn NVS reset/commit, version_code và retry thực tế. Mục25 ở mỗi bài được
đặt tên “Firmware mẫu và kết quả tham khảo”. Bài tập/checklist vẫn dành cho lượt
bạn tự làm; không có build, flash, erase hay phiên COM mới trong lần chỉnh giáo
trình và tiến độ này.
