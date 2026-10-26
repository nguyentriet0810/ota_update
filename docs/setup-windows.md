# Cài SDK riêng trên Windows

Giữ nguyên SDK đang có. Ví dụ project tại `D:\ota_update`; các biến môi trường
dưới đây chỉ có hiệu lực trong PowerShell hiện tại. Cần Python3.10+ và Git.

Tải archive chính thức **có submodules** từ
[ESP-IDF v6.1 release](https://github.com/espressif/esp-idf/releases/tag/v6.1)
(file `esp-idf-v6.1.zip`, khoảng1.81GiB), rồi giải nén vào `.tooling/` để có
`.tooling/esp-idf-v6.1/tools/idf_tools.py`. Source ZIP tự sinh của GitHub thiếu
submodules nên không dùng thay archive này.

```powershell
$otaRoot = 'D:\ota_update'
$env:IDF_PATH = "$otaRoot/.tooling/esp-idf-v6.1"
$env:IDF_TOOLS_PATH = "$otaRoot/.tooling/idf-tools"
$env:IDF_PYTHON_ENV_PATH = "$otaRoot/.tooling/python-env"
python "$env:IDF_PATH/tools/idf_tools.py" install --targets=esp32s3
New-Item -ItemType Directory -Force -Path $env:IDF_PYTHON_ENV_PATH | Out-Null
python "$env:IDF_PATH/tools/idf_tools.py" install-python-env --features core
git -C $env:IDF_PATH rev-parse HEAD
```

Commit của tag dùng trong lab:
`fff9895c82d744c7237be8847347bdd1b07c6643`.
Archive Linux mất executable-bit khi giải nén trên Windows có thể làm Git báo
dirty dù nội dung không đổi. Kiểm `git diff --summary` trước; nếu chỉ là mode
100755→100644, đặt `core.filemode=false` trong repo SDK và từng submodule rồi
kiểm lại trạng thái. Không bỏ qua thay đổi nội dung thực.

Sau khi cài, tiếp tục [runbook](runbook.md). `tools/build.ps1` chọn đúng SDK và
Python environment riêng, không yêu cầu gỡ hoặc thay SDK5.3.1.
