# ESP32-S3 N16R8 — Study Book OTA lab

Board hiện chạy **production8.0.1/code10 VALID** sau OTA qua GitHub.
**32/32 nhóm ca capstone đạt** trong phạm vi injection đã ghi; xem
[báo cáo thực nghiệm](docs/lab-report-2026-10-26.md) và
[matrix/evidence](docs/capstone-test-matrix.csv). Báo cáo nêu rõ giới hạn một board,
software reset và hardware security. E04 one-call đã chạy riêng với [runbook/evidence](docs/E04-onecall-runbook.md).

Project thực hành Subject #3 của Study Book « OTA Update, dùng ESP-IDF **v6.1**
(`fff9895c82d744c7237be8847347bdd1b07c6643`). SDK/công cụ v6.1 được cài riêng;
ESP-IDF v5.3.1 hiện có được giữ nguyên.

Board đã probe: ESP32-S3 rev0.2, Flash quad3.3V16MiB, octal PSRAM8MiB, UART qua CH343.
Project thực tế trên máy: `D:\ota_update`.

Luồng chính: serial provision → baseline VALID → tải raw manifest đã ký qua HTTPS
→ kiểm RSA-PSS/profile/version → ghi inactive slot với checkpoint64KiB
→ SDK kiểm native signed app + SHA-256 toàn file + descriptor
→ boot thử → local health/data/identity gate → VALID hoặc rollback.

| Build | Version code | Config reader | Health |
|---|---:|---:|---|
| v1 /1.0.0 |1 |1 |Baseline |
| v2 /2.0.0 |2 |2 |Good update/migration |
| v3 /3.0.0 |3 |2 |Cố ý reset trước confirmation |
| v4 /4.0.0 |4 |2 |Bản sửa sau failed trial |

Đọc [cài SDK riêng](docs/setup-windows.md) và [runbook](docs/runbook.md) để build, provision và kiểm thử;
[manifest contract](docs/manifest-schema-v1.md), [data contract](docs/schema-spec.md)
và [hardware-security design](docs/E09-hardware-security-design.md) mô tả các gate.
Kết quả thực phải đọc từ [32-case matrix](docs/capstone-test-matrix.csv) và `evidence/`;
mã nguồn hay expected trace không tự chứng minh một test đã PASS.

Baseline dùng software signed-app verification. Hardware Secure Boot, Flash Encryption
và eFuse anti-rollback được giữ disabled theo profile giáo trình.
Private key, Wi-Fi credentials, SDK/build cache và bản sao lưu Flash nằm trong các
thư mục local bị loại khỏi Git; release chỉ chứa app đã ký, raw manifest/signature và
thông tin artifact công khai.
