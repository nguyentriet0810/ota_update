# Checkpoint phiên thực hành — 26/10/2026

Đã lưu tại thời điểm tiếp tục sau yêu cầu tạm dừng. Subject #3 vẫn đang thực hiện;
chưa được kết luận hoàn thành OTA capstone.

## Môi trường và dữ liệu cần giữ

- Project chính: `D:\ota_update`, repo `nguyentriet0810/ota_update`.
- SDK mới: `.tooling/esp-idf-v6.1`, commit `fff9895c82d744c7237be8847347bdd1b07c6643`;
  compiler/Python/tools riêng. SDK5.3.1 tại `C:\Espressif` được giữ nguyên.
- ESP32-S3 rev0.2, COM13/CH343, Flash16MiB, PSRAM8MiB.
- Backup Flash gốc16MiB giữ cục bộ trong `.recovery/`, SHA-256
  `e570d1427b2a7c53f1fa0f09987aa19054edfeddd258a07b059b8bf21050a780`.
- Khóa riêng và Wi-Fi nằm trong `.secrets/`; các thư mục này, SDK và build cache
  bị loại khỏi Git. Không đưa raw transcript có thông tin Wi-Fi lên repo.

## Đã kiểm chứng

- Source/build nền tại `a83d6376c584da9cba04c2854774e38789eeff2e`.
- V1–v4 build và native RSA verification thành công. Mỗi app signed1118208bytes,
  vừa slot3MiB. V3/v4 mới được đóng gói cục bộ, chưa chạy trên board.
- Đã nạp v1 qua serial; self-test, Flash/PSRAM, NVS schema1, heartbeat và partition
  đều có log. Board hiện chạy `1.0.0`, `ota_0@0x20000`, boot=`ota_0`, SDK=`VALID`.
- Có lần rút/cắm USB thật do người dùng thực hiện và xác nhận chỉ dùng nguồn USB:
  bộ ghi thấy removal/reconnect, self-testPASS và app vẫnVALID.
- Wi-Fi provision riêng và kết nối được; certificate bundle xác thực GitHub HTTPS.
- Parser cấu hình trên board PASS; bộ release tools21 host testsPASS.
- N06: 404 bị từ chối trước writer; đây là nhánh404, chưa thử200HTML.
- Trong lượt reject đã dừng: sai chip/layout và ba size âm/thập phân/quá slot PASS.
  Sai board bị BLOCKED do time/network prerequisite timeout trước gate cần kiểm.
  A06 đang chạy khi bộ ghi bị dừng để audit; không tự suy ra PASS cho ca này.

## Điểm dở dang quan trọng

Đã phát hiện native SDK verify đọc theo kích thước partition, trong khi writer
sequential cũ có thể để lại signature sector từ image trước ngoài chiều dài file
mới. Mã nguồn đã sửa fresh download thành erase toàn bộ inactive slot và tăng
checkpoint policy từ1 lên2; resume vẫn giữ prefix và replay tail theoSDK.
**Bản sửa này chưa được build/nạp/kiểm thử tại checkpoint.**

Board vẫn chạy binaryv1 đã build trước sửa. Không coi các prereleasev1/v2 hiện có
là bản đã chứa sửa này; không thay bytes dưới cùng một release URL đã phát hành.

Nhánh `lab-fault-profile` là phần đang phát triển cho local TLS/HTTP fault server
và các reset window. Public testCA được phép lưu Git; privateCA/leafkeys chỉ ở
`.secrets/fault-tls`. Hostserver có7 loopback testsPASS, chưa chạy persistent
listener hoặc kiểm thử TLS qua board; chưa tạo firewall rule.

## Tiếp tục từ đây

1. Build và provision patch baseline1.0.1 với writer/checkpoint policy2; giữ layout,
   native trust key và dữ liệu cấu hình. Đây là sửa baseline bằng serial, không tính
   là bằng chứng OTA qua mạng.
2. Rerun16 negative fixtures và kiểm riêng unsigned/wrong-key/final-file hash.
3. Chạy fixture reset khi tạo schema2 shadow, rồi v1→v2 qua HTTPS với checkpoint
   reset, mất Wi-Fi, confirm và VALID-before-pointer reconciliation.
4. Chạy explicitINVALID, unconfirmedABORTED, quarantine và bản sửa tốt.
5. Hoàn tất fault-profile/localTLS cases; sau đó quay về production transport.
6. Cập nhật32-case matrix và Notion bằng observed/evidence thật; chưa tự đánh Done.

Các prerelease đã phát hành: `v1.0.0`, `v2.0.0`, `lab-negative-v2`.
Logs và summary lưu trong `evidence/`; lỗi prerequisite và lượt bị ngắt được giữ
nguyên để phân biệt với kết quả reject thành công.
