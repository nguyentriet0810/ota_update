# Kết quả thực nghiệm Subject #3 — 26/10/2026

Board đã về **production8.0.1, version_code10, ota_0 VALID**, self-test PASS,
controller IDLE/busy0, Wi-Fi hoạt động. Config schema2/active2/generation2,
sample1000ms, threshold30000 milli-degreeC; schema1 nguồn generation1/CRCfbab8dc4
vẫn được giữ. [Trạng thái cuối](../evidence/final-production-v8.0.1-state.log).

**32/32 nhóm ca capstone đạt trong phạm vi injection đã ghi** tại
[matrix](capstone-test-matrix.csv). Đây là chiến dịch trên một ESP32-S3, qua các
binary pin source/config khác nhau, gồm16 crypto reject fixtures,12 biến thể
mạng và10 biến thể storage/controller; không phải32 thiết bị hoặc chứng minh mọi
cửa sổ mất nguồn đều an toàn.

## Danh tính bản cuối và môi trường

| Thuộc tính | Quan sát/identity |
|---|---|
| Chip/bridge | ESP32-S3 rev0.2, CH343/COM13 |
| Flash/PSRAM |16MiB quad3.3V /8MiB octal; runtime memory check PASS |
| SDK | ESP-IDF v6.1, fff9895c82d744c7237be8847347bdd1b07c6643 |
| SDK cũ | v5.3.1 giữ tại C:\Espressif, không thay thế |
| Firmware source | daf38ef3d3b897c1fe559f894578575e6a729feb |
| Final signed app SHA256 | f035f3b7a4fb19d6af25bc4da139001b0754c9f8c124432470c761107d90c6b4 |
| Size/slot |1118208 /3145728bytes |
| Security | Software signed raw manifest + native app + full signed-file SHA256 + TLS CA/hostname/time |
| Hardware security | Secure Boot=false, Flash Encryption=disabled, eFuse secure_version0; inventory chỉ đọc |

[Release cuối](https://github.com/nguyentriet0810/ota_update/releases/tag/v8.0.1-production)
có app, exact manifest, signature và release-info. Host đã tải lại toàn bộ assets,
so bytes/hash và verify cả hai chữ ký. Build audit chứng minh testCA/local origins,
clock/radio/offline/checkpoint diagnostics và intentional boot/health faults không
có trong production. Live command cũng từ chối local test origin trước writer.

## Các kết quả chính

- Good OTA1.0.2→2.0.1 qua GitHub có đầy đủ raw auth, writer, verify, NEW,
  PENDING_VERIFY và VALID. Reset sau VALID/trước active-schema commit được ghi;
  boot tiếp theo thấy pointer1, reuse shadow2 và hoàn tất pointer2 không convert lại.
- Explicit fail tạo INVALID; reset trước confirm tạo ABORTED. Fallback2.0.1VALID
  giữ data. Đúng bad identity gửi lại bị chặn trước writer; repaired4.0.1 vẫn được
  chấp nhận và confirm.
- Reset ngay trước markVALID của fixture6.0.0 cũng tạo ABORTED/fallback5.0.2VALID,
  không false-confirm. Fixture này chạy trước healthy test code6.
- Network faults giữ app VALID: DNS, CA/hostname, time prerequisite, redirect
  loop/downgrade/host,404/HTML,500/429/timeout. Retry tối đa3attempts; có delay đã
  thực sự chờ và số request phía server, không chỉ một dòng khai báo backoff.
- Resume qua disconnect/reset giữ checkpoint đúng; reset trước commitQ196608
  dùng oldQ131072.416/bad ranges bị chặn;200 bỏ body và fresh restart. Cùng URL
  đổi padding vẫn qua native verify nhưng bị full-file digest chặn. Stale target
  running và hai CP CRC lỗi đều không được dùng để đoán offset.
- Cold boot offline là cắt nguồn USB thật: người dùng xác nhận board chỉ dùng
  USB; logger thấy removal/reconnect, selftestPASS/VALID và radio autostartfalse.
  Sau đó restore Wi-Fi từ credentials đã giữ, không provision lại mật khẩu.
- Sau confirm, radio-off vẫn có heartbeat/SDKVALID; late failtrial bị từ chối.
  Lab report dùng console/file polling; không có cloud report queue để tuyên bố
  đã kiểm server-side idempotency.

## Các lỗi đã tìm và sửa

Fresh sequential write từng có thể giữ signature sector cũ ngoài file mới, trong
khi SDK native validation đọc toàn partition. Fresh attempt nay erase toàn
inactive slot; resume chỉ dùng policy2 checkpoint chứng minh prefix thuộc đúng
identity. Bộ unsigned/wrong-key/full-file-digest đã regression-test trên MCU.

UART burst nhận trong lúc program Flash bị mất byte khi ISR ngoài IRAM. Bật
CONFIG_UART_ISR_IN_IRAM, cài test5.0.4/code6 rồi chạy lại burst duplicate/cancel:
one-owner reject, abort writer/close HTTP/xóa CP và giữ VALID đều PASS. Production
cũng có ISR IRAM. Lượt thiếu marker trước sửa được giữ, không nhận là PASS.

Host logger được đặt UTF-8 để không crash vì reset noise. Hai assertion host cũng
được sửa: HTTPstatus=-1 trước headers, và HTTP416 bị chặn trước marker stream.
Đánh giá lại **cùng trace**, giữ original FAIL và reassessment trong evidence;
trace bỏ dòng completed-wait vẫn bị classifier từ chối.

UTC có thể provision từ serial tin cậy lúc idle nếu SNTP chưa đồng bộ. Parser
reject malformed/out-of-range và worker-busy; không bỏ TLS time verification.
Nhãn version và numeric version_code độc lập; test5.0.4/code6 → production6.0.4/code7.
Các prerelease0.3 chưa cài được giữ bất biến; không thay bytes dưới URL cũ.


Demo E04 lần đầu dùng HTTP TX buffer mặc định đã gặp Out of buffer với signed
redirect URL dài của GitHub, SDK trảESP_FAIL trước boot selection. Đã sửa riêng
demo thành TX2048/RX4096, tối đa5redirects; tạo release mới/code tăng, giữ trace
lỗi cũ và rerun one-call thành công. Lượt lỗi chưa activate không được tính vào
denominator healthy activations.

## Tái hiện và giới hạn

Dùng [runbook](runbook.md), [fault runbook](fault-profile-runbook.md),
[schema contract](schema-spec.md), [security design](E09-hardware-security-design.md)
và [bài giải thiết kế](study-exercises.md). Main chứa source core giống commit đã
build; public evidence có sdkconfig đã lọc, map nén, CSV/BIN và artifact hashes.
Scratch directories0.3 được tái dùng cho các build0.4 rồi7.0.1/8.0.1; assets đã publish vẫn được giữ
riêng trong immutable release assets. Không suy phiên bản từ tên cache folder.

Capstone32ca dùng low-level esp_http_client/esp_ota_*. E04 one-call đã chạy riêng
từ lab7.0.1/code9 lên production8.0.1/code10: API trảESP_OK, post-readback qua,
NEW→PENDING_VERIFY→VALID đúng identity. [Trace/verdict](../evidence/E04-onecall-result.json)
và [runbook](E04-onecall-runbook.md) nêu rõ SDK chọn boot trước custom readback;
không áp các guarantee checkpoint/cancel của capstone cho demo. Production loại
demo/testCA/hooks bằng compile flags. Knowledge checks và phần tự làm độc lập
của người học không được tự tích hoàn thành.
Hardware Secure Boot/encryption/anti-rollback không bật; các bài E09 là thiết kế,
simulation và inventory read-only. Software reset không thay cho power cut trong
Flash/NVS commit. R07 kiểm hai CRC lỗi; R08 kiểm duplicate/cancel, chưa gây lỗi
Flash phần cứng. Không tuyên bố fleet coverage hoặc sản phẩm sẵn sàng thương mại.

Metrics của lượt tiếp tục:8 healthy activations(v2,v4,v5.0.2,v5.0.4,v6.0.4,
v7.0.0,v7.0.1,v8.0.1),8confirmed;3 intentionally failing trial
activations(explicit3/reset3/prevalid6),3
fallback đúng. Denominator là attempts trên **một board**. Các metadata/image
reject không nằm trong denominator activated. Dừng rollout nếu healthy candidate
crash, data regression hoặc gate sai; không gom expected negative-fixture rollback
vào tỷ lệ lỗi của healthy releases.

Private keys, Wi-Fi, full Flash backup và raw eFuse khác giữ local. Các server lab
đã dừng; không tạo firewall rule, không cài CA vào Windows trust store, không có
automation chạy tiếp. Nạp lại serial trong lượt này là do người dùng đã xóa Flash
cho mục đích khác; không tính lần provision đó là OTA success hoặc OTA regression.
