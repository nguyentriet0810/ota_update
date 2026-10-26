# E09 — Hardware security design và recovery

Đây là **bản thiết kế**, không phải bằng chứng đã bật hardware security. Baseline hiện tại dùng signed metadata/app ở software và giữ hardware Secure Boot, Flash Encryption, eFuse anti-rollback disabled. Không burn key digest, secure-version bits, revoke key hoặc khóa download/JTAG.

## Trust boundaries

HTTPS xác thực server và bảo vệ transport. Raw manifest signature bind board/layout/schema/version/size/digest/URL. Native image signature chặn app unsigned/key lạ. Health gate và `otadata` quyết định trial/confirmation/rollback; các chữ ký không chứng minh app hoạt động đúng. CRC của checkpoint chỉ phát hiện hỏng dữ liệu lưu, không thay chữ ký.

Người có quyền ghi vật lý vào Flash có thể thay baseline trust anchor hoặc code verifier ở software profile. Nhánh hardware cần Secure Boot để ROM xác thực bootloader và bootloader xác thực app; Flash Encryption bảo vệ Flash theo threat model riêng. Không gọi software profile là chống thay Flash vật lý.

## Điều kiện trước một nhánh hardware tương lai

1. Chốt module/revision, schematic, nguồn điện, UART/USB download path thực và thiết bị recovery dự phòng.
2. Tạo backup/manifest config và thử restore trên phần cứng phát triển trước thay đổi bất hồi phục.
3. Phân biệt public key fingerprint, ESP secure-boot digest format, key purpose và eFuse block; không dùng SHA256(PKCS#1 DER) như dữ liệu burn.
4. Lập kế hoạch custody/backup key, public key slot/revocation, chuyển key và điều kiện mọi app fallback còn boot được.
5. Kiểm anti-rollback epoch với số bit hữu hạn, native image `secure_version`, fallback và trạng thái lúc confirm. Không tăng epoch chỉ để thử rollback.
6. Review generated sdkconfig, bootloader binary và lệnh provision cụ thể trước lần boot đầu; bootloader cấu hình hardware security có thể tự burn eFuse.
7. Ghi rõ thay đổi USB/JTAG/download/recovery sau bảo mật. Recovery cần artifact đúng key và policy; backup Flash cũ có thể không còn khôi phục được khi eFuse đã đổi.

## Recovery của software lab hiện tại

Backup nguyên bản được root lưu riêng tại `work/board-backup`; file đầy đủ 16 MiB có SHA256 `e570d1427b2a7c53f1fa0f09987aa19054edfeddd258a07b059b8bf21050a780`. Đây là dữ liệu riêng tư, không được đưa vào repo public. Profile Arduino ban đầu có app tại `0x10000` và otadata tại `0xE000`; không khôi phục riêng app này vào layout E02 mới.

Khôi phục nguyên bản phải dùng đúng full backup, chip/Flash size và offset `0x0`, sau khi ngắt monitor và kiểm file hash. Không chạy restore trong bài test OTA. Serial provisioning/recovery phải được ghi riêng với OTA qua HTTPS.

Nếu cả hai OTA slot của lab mất khả năng boot và hardware security vẫn disabled, đưa chip về ROM download mode bằng BOOT/EN theo board thực rồi provision bootloader/table/signed-baseline cùng một profile. Nếu chỉ trial lỗi, ưu tiên rollback theo SDK; không erase `otadata` hay NVS để làm kết quả test đẹp.

Nguồn: [ESP32-S3 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/security/secure-boot-v2.html), [Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/security/flash-encryption.html), [OTA anti-rollback](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/system/ota.html#anti-rollback).
