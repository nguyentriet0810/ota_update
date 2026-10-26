# Review giáo trình Subject #3 — 2026-10-26

Đã đối chiếu toàn bộ E01–E12 trong [Study Book OTA Update](https://app.notion.com/p/3fcd2576a80281948680f46654c6d126)
với source, CLI và SDK của bộ tham khảo. Các sửa đổi nằm trong nội dung bài,
lab và code mẫu. Status học của cả12 bài vẫn **Not started**,61 checklist còn
trống. Firmware và kết quả do trợ lý chuẩn bị là tài liệu tham khảo trước khi
bạn tự làm; chúng không chứng minh bạn đã hoàn thành bài.

## Mốc dùng để đối chiếu

- ESP32-S3 N16R8; layout hai app slot3 MiB, no factory.
- ESP-IDF v6.1, commit `fff9895c82d744c7237be8847347bdd1b07c6643`.
- Source firmware tham khảo `daf38ef3d3b897c1fe559f894578575e6a729feb`.
  Main checkpoint `9bbc02588764a5155fd567863bae231b4147dd64` chứa source
  tương đương cùng evidence/config/maps. Các commit sau chỉnh tài liệu.
- Mốc cuối đã quan sát trước review: production8.0.1, version_code10, VALID,
  config schema2. Review này không mở COM, build/nạp/xóa firmware hay ghi eFuse.
- SDK v5.3.1 hiện có vẫn giữ riêng; review không thay SDK/toolchain.

## Nội dung đã sửa

| Bài | Điều chỉnh trong bài và thực hành | Source đối chiếu |
| --- | --- | --- |
| E01 | Lệnh PowerShell và đường dẫn SDK riêng; thư mục bài tự làm khác repo tham khảo; descriptor project `studybook_ota_lab`, tên artifact đúng; build lại sau đổi CMake; v1/v2 tối thiểu khác Variant v2/schema2 của project tích hợp; giải thích baseline code10. | `CMakeLists.txt`, `main/main.c`, `sdkconfig.defaults`, `tools/build.ps1` |
| E02 | Selector C kiểm NULL/running/boot/next; lệnh kiểm partition trên Windows; `seed` chỉ cho UNDEFINED + self-test PASS, VALID bỏ qua; mapping credentials đúng. | `partitions.csv`, `main/ota_lab.c`, SDK `esp_ota_ops.h` |
| E03 | Schema2 cho Variant v2; Python tải manifest-template trước khi dùng, chặn placeholder; URL tải bằng PC; phân biệt descriptor ELF hash, native digest, full-file SHA256 và release ID; sửa API bị biến thành link. | `main/ota_lab.c`, `tools/release.py` |
| E04 | Phân biệt snippet nhận BIN URL với CLI tích hợp nhận manifest/signature; `ota-basic` chỉ có ở lab profile; negative cases one-call cần evidence riêng, không lấy strict-route PASS thay thế. | `main/ota_lab.c`, `docs/E04-onecall-runbook.md` |
| E05 | Controller mẫu dùng atomic guard và một worker, không có queue; NO_UPDATE là nhánh thiết kế mở rộng; thêm includes của C snippet và phân biệt writer-bounds với lỗi driver Flash. | `main/ota_lab.c` |
| E06 | Seed theo observed state; giải thích custom self-test và trial gate; hai candidate lỗi code3 cần file digest khác nhau; giữ code4 cho repaired khỏe. | `main/main.c`, `main/ota_lab.c`, `tools/serial_lab.py` |
| E07 | Checkpoint/identity thực là native C struct có format/sizeof/policy/CRC/readback, không phải wire codec độc lập ABI; high-level resume là route bài tập khác. | `main/ota_lab.c`, SDK `esp_ota_ops.h`, `esp_https_ota.h` |
| E08 | Signing CLI v6.1 với scheme version2; public DER của snippet khác đường dẫn trust anchor trong repo; keygen/rotation là bootstrap có chủ đích; unsigned candidate cần chạy từ baseline đã tin đúng key. | `tools/generate_keys.py`, `tools/release.py`, SDK `serial_ext.py` |
| E09 | Lệnh inventory PowerShell có điều kiện controller idle; đọc eFuse không ghi nhưng có thể reset/đưa chip vào ROM. Hardware security vẫn là nhánh thiết kế riêng. | `docs/security-profile.md`, `docs/E09-hardware-security-design.md` |
| E10 | Credentials ở `nvs_cfg/net`, config ở `cfg`, Wi-Fi runtime RAM; C function mở đúng partition và trả ownership handle; parser-tests không sửa NVS; B04/B05 cần negative builds riêng, B06 cần pointer1. | `main/cfg_store.c`, `main/ota_lab.c`, `tools/build.ps1` |
| E11 | Draft release dùng tag mới và đủ4 assets; latest/REST/cohort/cloud queue chưa có; `bad` chỉ là identity gần nhất cộng dữ kiện per-slot; guided lab dùng INVALID_VERSION thực tế thay NO_UPDATE. | `tools/release.py`, `main/ota_lab.c` |
| E12 | R02 reset trước cp_save, không khẳng định mọi reset trước nvs_commit giữ snapshot cũ; nêu đúng giới hạn CRC/writer injection; hướng dẫn cold boot USB-only và matrix bài tự làm bắt đầu NOT RUN. | `docs/capstone-test-matrix.csv`, `main/ota_lab.c`, các runbook |

Cả12 bài đã đổi phần setup sang PowerShell, giải thích đường dẫn tương đối và
việc build script chọn project theo vị trí của chính script. Các tên tài liệu
nội bộ bị tự biến thành website giả được chuyển về inline code. Nội dung lý
thuyết/bài độc lập vẫn có thể yêu cầu bạn xây thêm tính năng; phần mở rộng đã
được phân biệt với chức năng của bộ tham khảo.

## Kiểm tra đã thực hiện trong review

- **10 snippet C /9 translation units: PASS** với compiler Xtensa ESP32-S3 và
  compile context của SDK đã pin, dùng `-fsyntax-only`. E01 ghép hai snippet
  theo thứ tự; E07 có wrapper tham số cho hai route độc lập. Các custom extern
  không được link hoặc tự giả lập thành API SDK.
- **20 khối PowerShell trong Notion và8 khối trong runbook: PASS** qua parser
  PowerShell; không thực thi lệnh nạp, ký, phát hành hay eFuse trong ví dụ.
- **3 đoạn Python: PASS** qua AST parser; không đọc private key hoặc ký thử.
- **7 partition: PASS** khi so start/end của bảng E02 với offsets/sizes CSV.
- CLI signing và tên/tham số build/release được đọc trực tiếp từ source SDK
  và script. Sau lưu, fetch lại12 trang: toàn bộ giữ Not started,0 checked,
  61 unchecked; các code block cập nhật được tìm thấy đầy đủ, không có block
  bị báo unknown/truncated.

Kết quả này xác nhận cú pháp và đối chiếu nội dung trong phạm vi trên. Nó
không thay thế link/build project do bạn tự ghép, runtime test hoặc bài làm của
bạn. Kết quả32 nhóm capstone và one-call trong appendix là các lượt chạy tham
khảo trước đó, qua nhiều version/config đã pin; không phải32 lượt mới của review
này hay toàn bộ test trên cùng một binary cuối.

Evidence máy đọc được:
[C snippets](../evidence/curriculum-c-syntax-check.json),
[PowerShell](../evidence/curriculum-powershell-syntax-check.json),
[Python](../evidence/curriculum-python-syntax-check.json),
[partition](../evidence/curriculum-partition-check.json),
[Notion readback](../evidence/curriculum-review-notion-readback.json).

Các tài liệu nền được đối chiếu thêm:
[OTA v6.1](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/system/ota.html),
[NVS v6.1](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/storage/nvs_flash.html),
[Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/security/secure-boot-v2.html).
