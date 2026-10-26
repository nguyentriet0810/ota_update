# Optional fault profile — TLS/network/resume tests

Profile test nằm trong clone riêng `D:\ota_update\.build\fault-profile`, branch `lab-fault-profile`. Production mặc định `LAB_FAULT_PROFILE=OFF` và chỉ nhận GitHub origin; chỉ binary test bật flag mới nhúng lab CA và nhận hotspot IP/port. Không tắt TLS CA/hostname/time verification. Các ca host bên dưới không tự chứng minh board PASS.

Source cuối5.0.4/6.0.4 pin commit `f2c72dd570b0306b87539e64b35700ecfc4b104e`.
Khi source profile đã được tích hợp vào main, build bằng công cụ chung:

```powershell
& tools/build.ps1 -Variant v5 -ProjectVersion 5.0.4 -VersionCode 6 -BuildName v5.0.4-test -FaultProfile -SigningKey '.secrets/app-signing.pem'
& tools/build.ps1 -Variant v6 -ProjectVersion 6.0.4 -VersionCode 7 -BuildName v6.0.4-final -SigningKey '.secrets/app-signing.pem'
```

Version label và version_code độc lập; code phải tăng so với firmware đang chạy.
`-FaultProfile` chỉ cho variantv5. Các build bình thường ép tất cả reset/profile
flags OFF, tránh tái dùng cache test cho production. Không thay bytes trong release
đã publish; một rebuild ký PSS có thể khác digest và phải có identity/release mới.

Public CA: clone `main/lab_test_ca.pem`. Private CA/leaf keys chỉ ở `D:\ota_update\.secrets\fault-tls`, không đưa vào source/Notion. Chứng thư valid 2026-01-01..2036-01-01: port8443 có SANIP192.168.137.1 và CA tin cậy;8444 self-signed không tin cậy;8445 được CA tin cậy ký nhưng SANwrong.lab.invalid. Không thêm CA này vào Windows trust store.

Khi native v6 signed image đã build:

```powershell
$otaPython = 'D:\ota_update\.tooling\python-env\Scripts\python.exe'
$otaFault = 'D:\ota_update\.build\fault-profile'
& $otaPython "$otaFault/tools/make_fault_assets.py" --image 'D:\ota_update\.build\v6-production\studybook_ota_lab.bin' --manifest-key 'D:\ota_update\.secrets\manifest-signing.pem' --app-public-key 'D:\ota_update\docs\public-keys\app-public.pem' --source-commit '68dbc4fc0ceba65eaa68c4fb325be14978c78cff' --output 'D:\ota_update\.build\fault-assets'
& $otaPython "$otaFault/tools/fault_server.py" --root 'D:\ota_update\.build\fault-assets' --tls-dir 'D:\ota_update\.secrets\fault-tls' --log "$otaFault/evidence/fault-server.jsonl"
```

Thay đường dẫn image bằng file build thực tế. Server chỉ bind192.168.137.1:8443/8444/8445; control chỉ bind127.0.0.1:8765. Chỉ phục vụ `.json/.sig/.bin` trực tiếp từ public fixture root; không traversal/private PEM. Nếu cần firewall, giới hạn đúng hotspot interface, ba port và IP board; lưu/xóa rule theo phiên test. Dừng server sau chiến dịch.

Sau khi server được người điều phối khởi chạy, kiểm listener trước khi cân nhắc firewall:

```powershell
& $otaPython "$otaFault/tools/probe_fault_server.py" --ca "$otaFault/main/lab_test_ca.pem"
```

Probe không tự mở server hoặc đổi firewall/trust store. Nó phải thấy8443 TLS/HTTP200 với manifest dummy9.9.9,8444 bị reject do CA,8445 bị reject do hostname và8765 trả status loopback. Connect-refused/timeout không được tính như TLS reject PASS. Host probe không tự chứng minh board truy cập được qua firewall.

Manifest test có version_code6/schema2, native image version6.0.0 nhưng manifest version9.9.9 có chủ đích. Ngay cả luồng tải sạch cũng phải reject descriptor, giữ app test đang chạy. Nó được ký bằng manifest key lab thật, native image ký đúng app key. Không phát hành fixture này như firmware good.

Base URL: `https://192.168.137.1:8443/releases/download/lab-fault-v6/`. Metadata chuẩn là manifest.json và manifest.sig; payload app.bin. Các endpoint metadata fault: redirect-loop.json, redirect-http.json, redirect-host.json,404.json,html.json,status-500.json,status-429.json,timeout.json. DNS case dùng `https://unresolvable.invalid:8443/releases/download/lab-fault-v6/manifest.json`.

Control bằng PowerShell; không gửi control qua hotspot:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/status
Invoke-RestMethod http://127.0.0.1:8765/control -Method Post -ContentType application/json -Body '{"reset":true}'
Invoke-RestMethod http://127.0.0.1:8765/control -Method Post -ContentType application/json -Body '{"image_mode":"cut","cut_after":147456,"fault_requests":1,"chunk_delay_ms":5}'
Invoke-RestMethod http://127.0.0.1:8765/control -Method Post -ContentType application/json -Body '{"image_mode":"good","range_mode":"ignore"}'
Invoke-RestMethod http://127.0.0.1:8765/control -Method Post -ContentType application/json -Body '{"image_mode":"tamper_tail","range_mode":"correct","fault_requests":-1}'
```

| Test | Cấu hình/đường dẫn | Bằng chứng cần có |
|---|---|---|
| N01 | DNS unresolvable.invalid | DNS error, không writer/set_boot |
| N03 | Metadata cùng path qua8444 và8445 | TLS CA/hostname reject riêng; không skip checks |
| N04 | Diagnostic lab-clock-not-ready on/off của firmware test | Clock policy chặn trước TLS, app vẫn có tiến độ |
| N05 | Ba redirect endpoint | Loop hữu hạn; HTTP downgrade/host ngoài policy bị chặn |
| N06 |404.json vàhtml.json | Không coi HTTP200 HTML là manifest/app |
| N07 | image_mode=status500/status429/timeout; fault_requests số hữu hạn hoặc-1 | Reason đúng, retry budget/thời hạn hữu hạn; không update loop |
| N08 | Có checkpoint trước, range_mode=ignore/416/wrong_start/wrong_total/wrong_end |200/416/bad Content-Range không được append vào prefix |
| R06 | Cùng manifest/URL, sau checkpoint đổi image_mode=tamper_tail | Identity cũ không tạo success; native validation vẫn qua, full-file digest reject |

`image_mode` còn có good,truncate,html,not_found,cut. `fault_requests=-1` duy trì fault,0 không inject và số dương giảm theo mỗi image request. `cut` gửi Content-Length đầy đủ rồi đóng kết nối tại offset tuyệt đối. `truncate` gửi Content-Length của file thiếu để kiểm HTTP contract. `tamper_tail` chỉ đổi một byte trailing padding của signature sector, giữ size/descriptor/native signature và làm full-file hash sai.

Range mode chỉ tác động khi request có Range; request đầu vẫn tải thường để tạo checkpoint. `ignore` trả200/full body,416 trả Content-Range bytes */total; wrong_start/wrong_total/wrong_end trả206 với header sai có chủ đích. Các Content-Length khác đều khớp bytes thực, ngoại trừ modecut chủ đích ngắt transport.

Root ghi actual commands/observed/log vào matrix. Fault-profile diagnostics R02/R05/R07 là thao tác test riêng và cần log trước/sau; không suy kết quả từ source code. Sau các ca này, quay về production firmware bằng đường OTA đã xác thực và chứng minh running/VALID/config bằng log riêng.
