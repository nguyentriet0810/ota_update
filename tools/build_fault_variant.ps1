param(
    [ValidateSet('v2-shadow-fail','v6-prevalid-fail')][string]$Variant='v2-shadow-fail'
)
$ErrorActionPreference='Stop'
$otaProject='D:\ota_update\.build\fault-profile'
$env:IDF_PATH='D:\ota_update\.tooling\esp-idf-v6.1'
$env:IDF_TOOLS_PATH='D:\ota_update\.tooling\idf-tools'
$env:IDF_PYTHON_ENV_PATH='D:\ota_update\.tooling\python-env'
$env:PYTHONUTF8='1'
. "$env:IDF_PATH/export.ps1"
if($LASTEXITCODE -ne 0){ throw 'Isolated ESP-IDF export failed' }
$otaBuild=Join-Path 'D:\ota_update\.build' $Variant
New-Item -ItemType Directory -Force -Path $otaBuild | Out-Null
$otaPrivateDefaults=Join-Path $otaBuild 'signing.defaults'
Set-Content -LiteralPath $otaPrivateDefaults -Encoding utf8 -Value @(
    'CONFIG_SECURE_BOOT_SIGNING_KEY="D:/ota_update/.secrets/app-signing.pem"',
    'CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y',
    'CONFIG_BOOTLOADER_APP_SECURE_VERSION=0'
)
$otaVersionCode=if($Variant -eq 'v2-shadow-fail'){2}else{6}
$otaShadowReset=if($Variant -eq 'v2-shadow-fail'){'ON'}else{'OFF'}
$otaPrevalidReset=if($Variant -eq 'v6-prevalid-fail'){'ON'}else{'OFF'}
$otaDefaults=(Join-Path $otaProject 'sdkconfig.defaults').Replace('\','/')+';'+$otaPrivateDefaults.Replace('\','/')
$otaPython=Join-Path $env:IDF_PYTHON_ENV_PATH 'Scripts/python.exe'
Push-Location -LiteralPath $otaProject
try {
    & $otaPython "$env:IDF_PATH/tools/idf.py" -B $otaBuild `
        "-DSDKCONFIG=$($otaBuild.Replace('\','/'))/sdkconfig" `
        "-DSDKCONFIG_DEFAULTS=$otaDefaults" `
        "-DPROJECT_VER=$otaVersionCode.0.0" "-DLAB_VERSION_CODE=$otaVersionCode" `
        '-DLAB_CFG_SCHEMA=2' '-DLAB_HEALTH_FAIL=OFF' '-DLAB_FAULT_PROFILE=OFF' `
        "-DLAB_CFG_FAULT_SHADOW_RESET=$otaShadowReset" "-DLAB_PREVALID_RESET=$otaPrevalidReset" build
    if($LASTEXITCODE -ne 0){throw "Fault fixture build failed: $LASTEXITCODE"}
} finally { Pop-Location }
