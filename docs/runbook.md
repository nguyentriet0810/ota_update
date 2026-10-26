# Runbook Subject #3 — ESP32-S3 N16R8

Project đích: `D:\ota_update`. Repo lab: `nguyentriet0810/ota_update`. Các lệnh trong tài liệu là hướng dẫn tái hiện; kết quả thực nằm trong `evidence/` và `capstone-test-matrix.csv`. Một lệnh hoặc expected trace trong runbook không phải bằng chứng PASS.

## Môi trường, key và build E01/E02/E08

Dùng ESP-IDF v6.1 pin tag/commit; không thay SDK đã có tại `C:\Espressif`. Toolchain riêng ở `.tooling/esp-idf-v6.1`, `.tooling/idf-tools`, `.tooling/python-env`. `tools/build.ps1` nhận đường dẫn riêng nếu môi trường đặt ở nơi khác. Không dùng v5.3.1 để tuyên bố đã kiểm `esp_ota_resume()`.

Chạy PowerShell tại project. Tạo key **một lần** vào thư mục riêng ngoài project; ví dụ đường dẫn bên dưới chỉ dùng khi chưa có key. Bộ key đã provision phải giữ nguyên. Script mặc định từ chối ghi đè; `--rotate` là thay trust anchor có chủ đích, cần provision baseline mới.

```powershell
$otaPython = 'D:\ota_update\.tooling\python-env\Scripts\python.exe'
$otaPrivate = 'D:\ota_update-private'
& $otaPython tools/generate_keys.py --private-dir $otaPrivate --public-dir docs/public-keys --embedded-der main/manifest_public.der
& $otaPython -m unittest discover -s tools -p 'test_*.py' -v
& tools/build.ps1 -Variant v1 -SigningKey "$otaPrivate/app-signing.pem"
& tools/build.ps1 -Variant v2 -SigningKey "$otaPrivate/app-signing.pem"
& tools/build.ps1 -Variant v3 -SigningKey "$otaPrivate/app-signing.pem"
& tools/build.ps1 -Variant v4 -SigningKey "$otaPrivate/app-signing.pem"
```

V1: version_code1/schema1; v2: code2/schema2 healthy; v3: code3/schema2 có self-test fail; v4: code4/schema2 repaired. App project name là `studybook_ota_lab`, file trong `.build/<variant>/studybook_ota_lab.bin`. Chỉ file signed cuối được phát hành. Lưu hash bootloader/table/app, source commit, SDK/tool versions, map và config đã lọc secrets.

Trước nạp: xác nhận chip ESP32-S3, Flash 16 MiB và PSRAM 8 MiB bằng probe/runtime. Kiểm layout `partitions.csv`: ota_0=0x20000, ota_1=0x320000, mỗi slot0x300000; otadata0xF000, nvs_cfg0x12000, ota_meta0x1A000. Generated sdkconfig phải bật rollback và software signed update, tắt hardware Secure Boot/Flash Encryption/anti-rollback. Xem [security profile](security-profile.md) và [E09 design](E09-hardware-security-design.md).

Provision serial chỉ thực hiện sau backup Flash và kiểm recovery. Lần đổi layout cũ sang E02 cần bootloader/table/signed-baseline cùng profile. Không dùng serial flash v2 như bằng chứng OTA. Đóng monitor trước khi dùng công cụ nạp hoặc serial helper. COM13 là port đã quan sát trong phiên này, cần liệt kê lại nếu cắm sang cổng khác.

## Provision Wi-Fi và baseline VALID

Nếu SNTP chưa cấp được giờ trên mạng lab, từ baseline1.0.2/test5.0.2/production6.0.2
có thể cấp UTC hiện tại qua serial lúc controller idle:

```powershell
$otaUTC = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
& $otaPython tools/serial_lab.py --port COM13 --send "clock $otaUTC" --log evidence/clock-provision.log --duration 3
```

Chỉ dùng giờ đúng từ máy tin cậy. Lệnh nhận10digit trong2024..2035, từ chối khi
worker bận; không bỏ CA/hostname/certificate-time verification. Clock giữ qua
software reset với cấu hình RTC+HRT; power-on cần đồng bộ lại trước OTA. Local
health/boot của app VALID không phụ thuộc Internet hoặc clock đã sync.

`serial_lab.py` không in lệnh Wi-Fi vào log; `--provision` hỏi password bằng getpass. Hoặc dùng `--wifi-file` trỏ JSON riêng ngoài project có `ssid` và `password`. Không đặt password trong `--send`, README hoặc shell history.

```powershell
& $otaPython tools/serial_lab.py --port COM13 --provision --log evidence/wifi-provision.log --duration 35
& $otaPython tools/serial_lab.py --port COM13 --send status --send partitions --send 'cfg show' --send otastatus --log evidence/v1-before-seed.log --duration 8
& $otaPython tools/serial_lab.py --port COM13 --send seed --log evidence/v1-seed-valid.log --duration 15
```

`seed` là thao tác provision một lần: chọn running slot, reboot tạo trial và self-test/confirm theo SDK. Kiểm observed state VALID trước OTA. Không gọi seed mỗi boot. Baseline cần heartbeat, version, reset reason, running/boot/next, Flash/PSRAM, internal heap và ELF identity.

## Đóng gói release E03/E08/E11

```powershell
$otaCommit = (git rev-parse HEAD).Trim()
& $otaPython tools/release.py make --image .build/v2/studybook_ota_lab.bin --manifest-key "$otaPrivate/manifest-signing.pem" --app-public-key docs/public-keys/app-public.pem --repo nguyentriet0810/ota_update --release v2.0.0 --version-code 2 --config-schema 2 --source-commit $otaCommit --output releases/v2.0.0
& $otaPython tools/release.py verify --manifest releases/v2.0.0/manifest.json --signature releases/v2.0.0/manifest.sig --manifest-public-key docs/public-keys/manifest-public.pem --image releases/v2.0.0/esp32s3-ota-lab-v2.0.0.bin --app-public-key docs/public-keys/app-public.pem --current-version-code 1
```

`release.py` dùng `python -m espsecure verify_signature --version 2`; có thể truyền `--espsecure <path/to/espsecure.py>` nếu module không ở Python environment. Builder từ chối output folder có nội dung để không ghi đè release cũ. Không chỉnh JSON sau ký. Lặp cho v1/v3/v4 với version_code/config_schema đúng từng build. Xem [schema](manifest-schema-v1.md).

Chỉ publish source đã lọc secrets và app/manifest/signature/release-info lên public lab repo. Không upload `.build`, `.tooling`, private key, credential JSON hoặc full Flash backup. Sau publish, tải app/manifest/signature bằng PC từ URL tag cố định, so size/hash và chạy verify lần nữa. HEAD/HTTP200 chưa chứng minh bytes hoặc Range đúng.

## OTA, resume và rollback E04–E07

```powershell
& $otaPython tools/serial_lab.py --port COM13 --send 'ota https://github.com/nguyentriet0810/ota_update/releases/download/v2.0.0/manifest.json https://github.com/nguyentriet0810/ota_update/releases/download/v2.0.0/manifest.sig' --log evidence/v1-to-v2.log --duration 180
& $otaPython tools/serial_lab.py --port COM13 --send status --send otastatus --send 'cfg show' --log evidence/v2-confirmed.log --duration 10
```

Happy path phải có authenticated manifest/identity, inactive slot, file bytes/hash/native verify, descriptor/compatibility gate, set_boot NEW, reboot PENDING_VERIFY, local health, VALID và config schema đúng. `download100%` hoặc version banner chưa đủ.

Để thử reset có tail sau checkpoint, chạy trên candidate mới chưa bị cài:

```powershell
& $otaPython tools/serial_lab.py --port COM13 --send 'ota-reset-at 147456' --send 'ota https://github.com/nguyentriet0810/ota_update/releases/download/v2.0.0/manifest.json https://github.com/nguyentriet0810/ota_update/releases/download/v2.0.0/manifest.sig' --log evidence/resume-interrupted.log --duration 90
```

Sau reboot, gửi lại **đúng hai URL**. Worker xác thực manifest lại rồi khôi phục checkpoint cùng release_id/filehash/slot/Q. Q lưu mỗi65536 byte; ví dụ147456 thường tạo tail sau Q131072. Ghi observed Q và Range response thật, không suy từ offset yêu cầu. Software reset không tương đương cắt nguồn vật lý.

`cancel` hủy request đang bận và dọn checkpoint; `clearresume` chỉ dùng khi idle để bắt đầu lại có chủ đích. Duplicate request khi busy phải bị từ chối. Transient download có tối đa3 attempt; metadata/auth error không retry vòng lặp. Origin URL cố định và TLS redirect allowlist được kiểm ở firmware; không lưu signed redirect URL tạm làm identity.

Sau v2 VALID, cập nhật v3.0.0 health_fail: candidate được xác thực nhưng reset khi chưa confirm; bootloader đổi trial sang ABORTED và quay về v2. `failtrial` là ca riêng B02: chỉ khi đang PENDING_VERIFY, gọi explicit SDK invalid/rollback để tạo INVALID. `testreset` là ca B03: chỉ khi đang PENDING_VERIFY, software reset tạo ABORTED ở boot sau. Chỉ kết luận fallback khi boot log tiếp theo chứng minh app/slot/identity đúng. Thử gửi lại đúng v3 để quan sát quarantine theo release_id/filehash; sau đó v4.0.0 repaired phải được nhận và VALID.

Để gây mất Wi-Fi thật trong download mà không tắt AP của người dùng, đặt `ota-wifi-drop-at 147456` trước lệnh OTA. Firmware disconnect radio ở byte threshold, tạm chặn auto-connect2giây, abort writer/HTTP rồi reconnect và retry/resume theo Q. Cần log `fault_method=wifi_disconnect`, sự kiện Wi-Fi disconnected, `fault_wifi_restore ... writer_aborted=true/http_closed=true`, `WAIT_RETRY_NETWORK` và writer resume offset đã quan sát. Đây là radio disconnect theo phần mềm, không tương đương cắt nguồn AP hoặc nguồn board. Giá trị0 disarm; chỉ arm khi idle.

## Dữ liệu, fault matrix và kết luận E10/E12

`cfg show` kiểm dữ liệu/schema/generation mà không in credentials; `cfg parser-tests` chạy kiểm parser/config cục bộ theo output. Trial schema2 dùng shadow; chỉ đổi active schema sau VALID, giữ schema1 cho fallback. `cfg arm-valid-reset` dùng thử reset sau mark VALID trước commit active-schema; ghi trigger và reconcile sau boot. Mỗi reset injection phải ghi rõ là software reset hoặc EN/RTS, chưa là power-cut test.

`docs/capstone-test-matrix.csv` có32 ca. Chỉ đổi result sang PASS khi có expected/observed/evidence tương ứng; test chưa chạy giữ NOT RUN, thiếu điều kiện ghi BLOCKED. Host21 tests là bằng chứng host validator/key custody, không tự PASS ca board. Tạo fixture metadata lỗi:

```powershell
& $otaPython tools/make_negative_fixtures.py --manifest releases/v2.0.0/manifest.json --manifest-key "$otaPrivate/manifest-signing.pem" --output releases/negative-v2
```

Một số lỗi mạng/TLS/Range cần test server HTTPS được tin cậy hoặc lab proxy có chủ đích; không tắt TLS verification để làm ca test chạy. Power-cut thực cần điều khiển nguồn vật lý. Cold boot khi tắt Internet cần xác nhận app VALID vẫn đạt local health, không update loop. Hardware-security provisioning, data migration toàn bộ failure paths, independent reproduction và câu trả lời knowledge checks chỉ được đánh hoàn thành khi có bằng chứng tương ứng.
