# E04 — demo esp_https_ota() one-call riêng

Demo chỉ được compile khi LAB_FAULT_PROFILE=ON. Nó phục vụ bài nhập môn E04;
capstone32ca dùng route low-level có checkpoint và kiểm full-file trước set_boot.
Không dùng kết quả của hai route thay thế lẫn nhau.

## Source và build

Pin source `daf38ef3d3b897c1fe559f894578575e6a729feb`, cùng SDK v6.1/keys/layout.
Profile lab7.0.1 có version_code9; production8.0.1 có code10. Code phải tăng từ
firmware đang chạy, độc lập với nhãn version.

```powershell
& tools/build.ps1 -Variant v5 -ProjectVersion 7.0.1 -VersionCode 9 -FaultProfile -BuildName e04-lab -SigningKey '.secrets/app-signing.pem'
& tools/build.ps1 -Variant v6 -ProjectVersion 8.0.1 -VersionCode 10 -BuildName production8 -SigningKey '.secrets/app-signing.pem'
```

Lab được cài bằng lệnh `ota` bình thường, từ signed GitHub release
`v7.0.1-onecall-lab`; chỉ dùng demo sau khi thấy7.0.1 VALID. Sau đó:

```powershell
$otaPython = 'D:/ota_update/.tooling/python-env/Scripts/python.exe'
& $otaPython tools/serial_lab.py --port COM13 --send 'ota-basic https://github.com/nguyentriet0810/ota_update/releases/download/v8.0.1-production/manifest.json https://github.com/nguyentriet0810/ota_update/releases/download/v8.0.1-production/manifest.sig' --duration 240 --log evidence/E04-onecall.log
```

## Gate và giới hạn

Worker kiểm Wi-Fi/time, exact raw manifest signature, bounds/target/layout/version
policy rồi lưu candidate identity. Full inactive-slot erase ngăn stale signature
tail. `esp_https_ota()` được gọi **một lần** trong task OTA, với TLS certificate
bundle/hostname/time checks, per-request timeout và native signed-app verification.
Current VALID app tiếp tục heartbeat.

SDK one-call tải app và chọn boot NEW nội bộ. Sau API return, lab đọc lại toàn
signed-file và descriptor, ghi boot-selected record rồi chủ động restart. Trial
health kiểm lại compiled identity/full-file trước confirm VALID.

Vì SDK đã set_boot trước custom readback, route này có khoảng mất nguồn giữa hai
mốc và không đáp ứng gate full-file-before-set_boot của capstone. Trong khoảng
SDK call, cancel bị chặn ở activation gate; không hứa checkpoint/resume hoặc
shared whole-session deadline. Nó có HTTP timeout; metadata vẫn dùng budget của
controller. Nếu SDK đã chọn boot mà hậu kiểm/report lỗi, báo BOOT_SELECTED_REPORT_FAILED,
không báo app unchanged. Trial identity gate còn là lớp kiểm trước confirm.

Lượt đầu với HTTP buffer mặc định đã gặp Out of buffer khi GitHub redirect tới
signed URL dài, SDK trả ESP_FAIL và không chọn boot candidate. Demo đã sửa thành
TX2048/RX4096 và max5 redirects; trace lỗi ban đầu được giữ trong evidence.

Production8.0.1 compile LAB_FAULT_PROFILE=OFF: không có command/demo marker,
testCA/local origin hoặc diagnostic hooks. Route `ota` bình thường vẫn giữ các
gate và cancellation/checkpoint của capstone. Chỉ chạy positive one-call update;
các negative network/auth cases trong matrix được ghi rõ thuộc low-level route.

Observed trace và verdict được lưu ở
[evidence E04](../evidence/E04-onecall-result.json), không suy PASS từ lệnh ví dụ.

Nguồn: [ESP-IDF v6.1 HTTPS OTA](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/system/esp_https_ota.html).
