# Phiên đã tạm dừng — 26/10/2026

Tạm dừng theo yêu cầu người dùng lúc14:01 (Asia/Bangkok). Không có OTA đang chạy,
không có build/test/server nền của phiên. SDK5.3.1 được giữ nguyên; SDK6.1 và tools
ở `.tooling/` riêng. Project: `D:\ota_update`.

## Trạng thái board khi dừng

- App **2.0.1**, running/boot=`ota_1@0x320000`, SDK=`VALID`, self-testPASS,
  service_mode0, controllerIDLE và Wi-Fi up.
- Config reader2, active_schema2, used_schema2, generation2; sample1000ms,
  threshold30000m°C. Snapshot schema1 giữ source_generation1/source_crc`fbab8dc4`.
- `cancel` trả `cancel_no_active_session`; cổng COM được đóng sau lần đọc cuối.
- Firmware standalone vẫn chạy bình thường; controller dùng update theo lệnh,
  không có lịch tự tiếp tục chiến dịch từ phiên này.

## Kết quả mới sau checkpoint trước

- Patch baseline1.0.1 đã build, verify native RSA và nạp riêng app; giữ layout,
  bootloader, Wi-Fi và NVS. Fresh writer erase toàn inactive slot, checkpoint policy2.
- **16/16 fixture reject có observed PASS** trên1.0.1. Có một attempt lỗi kết nối
  trước authentication; chỉ ca đó được rerun và PASS, lịch sử BLOCKED vẫn được giữ.
- B05: reset thực bằng software tại cửa sổ sau set_blob(schema2), trước explicit
  commit; SDKABORTED và fallback1.0.1VALID, reader1/schema1 vẫn đúng. Không suy rằng
  set_blob chưa persist, và không gọi software reset là power cut.
- R03/R04: reset tại written200704 sau checkpointQ196608; lần sau resume đúng196608.
- N02/R01: ngắt radio tại written344064/Q327680, abort writer/HTTP, reconnect và
  resume đúng327680. Final file/native verification qua và chọn boot image2.0.1.
- Sau đó app2.0.1 đạt VALID và config active2. Tuy nhiên logger Windows bị lỗi
  cp1252 lúc reset và mất phần trial/mark-valid/reconciliation. Đã sửa stdout UTF-8
  và đọc lại trạng thái, nhưng **B01/B06 còn thiếu trace đầy đủ**, không tự đánh PASS
  cho từng bước bị mất. Cần lần xác nhận có capture sạch trước khi chốt checklist.

Chi tiết nằm trong `evidence/device-rejects-policy2-campaign.json`, các log B05,
R03/R04, resume-confirm và `pause-board-state-20261026.log`. Matrix ghi đúng phạm vi
observed; việc build/đóng gói chưa tự chứng minh hardware PASS.

## Source và artifacts đang dở

- Main có source tail fix và công cụ test. Binary core patch1.0.1/2.0.1/4.0.1 pin
  source`d51d6075ac569b8b0a1cd94c5718c8b818ed1925`.
- Nhánh `lab-fault-profile`: source firmware cuối`0163b3323f06cd707656bbd4fd7496f6719e2e5f`;
  host tools tiếp theo tại`f39fc101e534dd0c00cf2a780b0357d28ac1031e`.
- V5.0.1 profile test và V6.0.1 profile production đã build/native-verify và đóng
  gói local, **chưa phát hành/chưa nạp**. Hash lần lượt:
  `18d4f763e0bb29ec5fe9a01b2678d58823e14476925a72e1cf3a7a0c723e85a7` và
  `521dea2a0d57e9e9e4c8917668b2115a5d31ab3270b620e306a7df34dc2fd9d2`.
- V6 prevalid negative fixture đã build tại `.build/v6-prevalid-fail`, hash
  `d1eace06e5e7e15941c0af4d26e1af7a514008786aa945bd0ca5bf922c052f5b`;
  chưa chạy board. Source0163, code6/schema2, prevalidON/profileOFF.
- Local fault assets cố ý dùng metadata version9.9.9/code6 và native image6.0.0
  để chặn activation sau stream. Giữ nguyên bộ dummy này.
- Chưa khởi chạy listener8443/8444/8445/8765, chưa thêm firewall rule hoặc CA vào
  Windows trust store. PublicCA có trong branch; privateCA/keys ở `.secrets/`.

## Khi người dùng yêu cầu tiếp tục

1. Đọc pause-board-state mới, không giả định port/version vẫn giống sau khi tắt máy.
2. Chạy explicitINVALID, ABORTED và repaired4.0.1 qua GitHub HTTPS; lưu identity/state.
3. Hoàn thiện capture B01/B06 bằng trạng thái migration phù hợp; không xóa NVS hay
   sửa otadata để làm kết quả đẹp. Logger đã xử lý UTF-8/reset noise.
4. Phát hành/cài5.0.1 test profile, chạy local TLS/HTTP/resume fault cases, 25-case
   retry-policy selftest và các diagnosticR02/R05/R07. `lab-radio-off/on` và
   `lab-offline-next-boot` chỉ có trong profile test; cold boot không Internet chưa chạy.
5. Kiểm B04 rồi đưa board về6.0.1 production: GitHub-only, không testCA/diagnostic hooks.
6. Cập nhật matrix và Notion bằng evidence thật. Subject #3 vẫn In progress.

Private keys, Wi-Fi, raw recovery Flash và SDK/build cache tiếp tục giữ local,
ngoài Git. Không có automation nào sẽ tự tiếp tục công việc.
