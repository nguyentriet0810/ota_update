# Hồ sơ bảo mật lab

Baseline dùng software verification: signed raw manifest, native signed app, HTTPS xác thực CA/hostname/thời gian. Hardware Secure Boot, Flash Encryption và eFuse anti-rollback phải giữ disabled. Không chạy lệnh burn/revoke eFuse trong lab này.

Hai RSA-3072 key riêng được dùng cho hai trách nhiệm: manifest key ký metadata và app key ký app theo Secure Boot v2 format của SDK. Private keys được giữ ngoài project; chỉ public keys, public fingerprints và manifest DER nhúng được commit. `docs/public-keys/fingerprints.json` dùng SHA256 trên RSA public key PKCS#1 DER; đây không phải ESP eFuse key digest format.

`tools/generate_keys.py` tạo key mới và từ chối ghi đè nếu key/public trust anchor đã tồn tại. Chỉ `--rotate` mới thay key; trước đó script sao lưu private key cũ trong private directory. Thay public DER cần build/provision baseline mới. Không dùng lại key lab này cho sản phẩm thật. Lệnh tạo ban đầu có trong [runbook](runbook.md); không chạy lại khi đang dùng bộ key đã nạp.

Software native verification tin key ở signature block đầu của app đang chạy. Vì vậy baseline ban đầu cũng phải được ký; app unsigned có thể abort ở startup. Candidate khác key/unsigned phải bị reject ở native image gate. Software verification không bảo vệ khi người có quyền vật lý thay bootloader/app/Flash. Hardware security là nhánh riêng E09, chưa được kiểm chỉ vì software signature đã PASS.

Trước nạp phải kiểm generated sdkconfig và hash bootloader: rollback=y, signed apps/update=y; SECURE_BOOT, SECURE_FLASH_ENC_ENABLED, BOOTLOADER_APP_ANTI_ROLLBACK đều disabled; secure_version=0. Giữ backup Flash ban đầu riêng tư vì có thể chứa credentials.

Không đưa SSID/password, private PEM, GitHub PAT, sdkconfig chứa Wi-Fi hoặc Flash backup lên GitHub/Notion. `sdkconfig` không mặc nhiên an toàn để chia sẻ; dùng config đã lọc thông tin nhạy cảm và public build report.

Nguồn: [ESP-IDF v6.1 OTA](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/system/ota.html), [Secure Boot v2 / software verification](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/security/secure-boot-v2.html).
