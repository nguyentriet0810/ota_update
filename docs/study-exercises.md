# Subject #3 — đáp án thiết kế và liên hệ với lab

Các phân tích dưới đây là bài giải thiết kế. Kết quả phần cứng nằm trong matrix
và log riêng; phân tích không thay cho một ca hardware đã chạy.

## E01–E03: identity, layout và release

Version là nhãn do publisher đặt. Resume bind SHA-256 của raw manifest, toàn file
signed app, size, origin URL, layout và target slot. Hai native app có cùng
version3.0.0 nhưng digest khác nhau được dùng làm explicit-fail/reset-fail, nên
quarantine không thể chỉ dựa version. `source_commit` truy code, sdkconfig truy
build flags, file digest truy đúng bytes đã phát hành.

Một layout **đề xuất**, chưa provision, cho Flash8MiB: giữ các vùng dữ liệu đến
0x20000 như profile chính; ota_0 tại0x20000/3MiB, ota_1 tại0x320000/3MiB; kết thúc
0x620000 <0x800000. Cả hai offset căn64KiB, vùng dữ liệu không overlap.
App signed1118208bytes còn2027520bytes trong slot3145728bytes. Nếu đổi CSV trên
thiết bị đã provision, cần migration/recovery riêng với bootloader/table/app phù
hợp; OTA app thông thường của lab không thay layout.

Chọn asset theo URL app được manifest đã ký chỉ rõ, không theo suffix đầu tiên
hoặc tên gần giống source.zip. `release.py verify` kiểm exact raw bytes; thay
newline/thứ tự key đòi chữ ký mới dù JSON có cùng ý nghĩa. Các fixture newline,
unknown/duplicate fields, wrong board/chip/layout và size bounds có log riêng.

## E04–E05: network và ownership

Capstone chọn `esp_http_client` + low-level `esp_ota_*` để kiểm manifest, HTTP,
resume và cancellation từng gate. Route one-call `esp_https_ota()` của E04 có
demo lab riêng: SDK chọn boot trong API, custom readback theo sau rồi trial
health kiểm lại trước confirm. Không dùng log hai route thay lẫn nhau. Xem
[runbook E04](E04-onecall-runbook.md). DNS/TLS/time/status/size có phase/reason riêng.

Một worker sở hữu HTTP và OTA handle. Kiểm target khác running trước begin và
kiểm lại ngay trước mutation. Khi cancel trước activation, abort writer, đóng
HTTP và xóa checkpoint; duplicate request bị từ chối. Sau activation commit bắt
đầu, cancel không được hứa app unchanged. Pending identity được lưu trước
set_boot; reset ở khoảng giữa có thể để candidate record chưa được boot, không
đủ bằng chứng để gọi crash hoặc confirmed.

## E06–E08: health, resume và authenticity

Health local gồm Flash đúng16MiB, PSRAM8MiB/memory check, internal heap/largest
block có ngưỡng, config hợp lệ/migration ready và candidate identity/full-file
readback khớp. Trial có cửa sổ5giây. Output lab là console/heartbeat; không có
actuator. Mất Internet không tự làm app local khỏe trở thành INVALID. Một timer
feed watchdog không chứng minh task sản phẩm tiến triển.

Ví dụ written150KiB/Q128KiB: giữ prefix[0,131072), tải lại từ131072 và erase/replay
tail từ Q theo SDK sequential resume. Không ghi tiếp từ150KiB. Fresh download
phải erase toàn inactive slot: SDK native validation có thể đọc ngoài file size;
signature cũ ở tail là regression đã được sửa bằng checkpoint policy2.

Chỉ206 với Content-Range/length/total chính xác mới được append. Server trả200
thì bỏ body cũ, clear checkpoint và khởi đầu fresh;416/bad range reject. Native
signature xác thực app; manifest RSA-PSS3072/SHA256/salt32 xác thực exact metadata;
full signed-file digest bao gồm padding ngoài phạm vi native signature. Cả ba
gate cần thiết. CRC checkpoint không xác thực publisher.

## E09: key/floor/fallback simulation

| Trạng thái thiết kế | Kết quả mô phỏng | Điều kiện recovery |
|---|---|---|
| Trust key1; baseline/fallback đều key1 | Boot nếu image/policy valid | Giữ key1 để cứu thiết bị |
| Bootstrap trust key1+key2, cài rescue key2 | Key2 có thể boot | Xác minh bootloader thực sự hiểu key2 trước retire |
| Revoke key1 nhưng chỉ còn fallback key1 | Mất đường fallback | Không revoke trước khi rescue key2 được kiểm |
| Floor3 đã áp dụng, old image sec2 | Old sec2 bị từ chối | Rescue signed đúng trusted key, sec>=3, data tương thích |
| Hai app slot đều không hợp key/floor | Không có fallback hợp lệ | Recovery cũng phải tuân key/floor/download policy |

Đây là simulation thiết kế, không burn/revoke bất kỳ eFuse nào. Firmware
software-verification hiện tại không chống người có quyền ghi vật lý thay trust
anchor. Flash Encryption khác authenticity; encrypted writes/resume alignment,
key custody và restricted download cần một profile/provision review riêng.

## E10–E12: data, reporting và rollout

Schema2 lưu threshold milli-degree; schema1 giữ độC. Migration dùng source
generation/CRC để tránh nhân1000 lần hai. Sau SDK VALID nhưng pointer vẫn1,
boot lại dùng shadow đã kiểm rồi commit pointer2 idempotently. Không có transaction
atomic chung giữa otadata và nvs_cfg.

Policy late rollback giữ snapshot schema1; nếu một sản phẩm thêm settings writer
sau confirm, phải chọn dual-write/back-conversion hoặc chặn downgrade. Lab chưa
có external settings writer, nên không hứa schema1 chứa mọi thay đổi tương lai.

Lab report được đọc thủ công qua console/file. Mất mạng sau confirm không đổi
SDK VALID; polling lại status/identity là retry report, không yêu cầu download
lại. Nếu thêm cloud report, dùng device/attempt/release ID làm idempotency key,
queue/report retry độc lập với download và không dùng uptime qua reset làm UTC.

Một board là một canary. Đếm attempts, activations, confirmations, rollback và
UNKNOWN riêng; nhiều lượt trên board này không thành fleet nhiều thiết bị. Dừng
rollout khi có crash bất ngờ, regression data hoặc gate sai. Những rollback của
negative fixtures là expected, phải tách khỏi failure rate của healthy releases.

Nguồn: [ESP-IDF v6.1 OTA](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/system/ota.html)
và [system time](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/system/system_time.html).
