# Manifest và release identity

Profile này triển khai đúng E03/E08: `manifest.json` tối đa 4096 byte UTF-8, `manifest.sig` là 384 byte nhị phân RSA-PSS-3072, SHA-256, MGF1-SHA256, salt 32 byte. Ký và verify đúng raw bytes trước parse. Thêm newline sau ký làm chữ ký sai.

| Field bắt buộc | Policy |
|---|---|
| schema_version | integer 1 |
| product | esp32s3-ota-lab |
| board | esp32s3-n16r8-lab |
| chip | esp32s3 |
| layout_id | s3-16m-2x3m-v1 |
| release | chuỗi ASCII không khoảng trắng, 1–63 byte |
| version | chuỗi ASCII không khoảng trắng, 1–31 byte; khớp app descriptor |
| version_code | integer 1–2147483647; candidate phải lớn hơn current |
| secure_version | integer 0 trong software baseline |
| config_schema | integer 1 hoặc 2 |
| min_updater_version | integer 1 |
| manifest_key_id | manifest-1 |
| size | integer 1–3145728, độ dài file signed cuối |
| sha256 | đúng 64 hex lowercase, toàn bộ file signed cuối |
| url | HTTPS GitHub release asset, tối đa 512 byte, không token/query/fragment |

Reject unknown field, field thiếu, duplicate key, boolean giả integer, số âm/thập phân/vượt bound, schema lạ và compatibility sai. Host packer sử dụng ASCII cho các chuỗi để tránh khác biệt giữa byte length và ký tự.

`release_id = SHA256(raw manifest bytes)` được tính sau khi xác thực; không thêm field này vào JSON để tránh vòng hash. File `release-info.json` là metadata phục vụ con người, không phải input tin cậy của firmware.

`sha256` của manifest là hash file BIN đã gồm padding/signature. Nó khác ELF hash và khác phạm vi của một số partition APIs. `tools/release.py verify` kiểm detached signature, schema, size/hash, ESP32-S3 header, app descriptor và chữ ký native bằng `espsecure`.

Mỗi release gồm app BIN, manifest.json, manifest.sig và release-info.json. Chỉ app BIN đi vào OTA writer; không gửi bootloader, partition table, merged image hoặc source archive.

Nguồn: [E03 trong Notion](https://app.notion.com/3fcd2576a802818387c9cd3de1c39aa9), [E08 trong Notion](https://app.notion.com/3fcd2576a80281d3a314f462805b832f), [ESP-IDF v6.1 software verification](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/security/secure-boot-v2.html#signed-app-verification-without-hardware-secure-boot).
