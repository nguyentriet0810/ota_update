param(
    [ValidateSet('v1','v2','v3','v4')][string]$Variant = 'v1',
    [Parameter(Mandatory=$true)][string]$SigningKey,
    [string]$IdfPath,
    [string]$ToolsPath,
    [string]$PythonEnvPath
)
$ErrorActionPreference = 'Stop'
$otaProject = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not $IdfPath) { $IdfPath = Join-Path $otaProject '.tooling/esp-idf-v6.1' }
if (-not $ToolsPath) { $ToolsPath = Join-Path $otaProject '.tooling/idf-tools' }
if (-not $PythonEnvPath) { $PythonEnvPath = Join-Path $otaProject '.tooling/python-env' }
$otaKey = (Resolve-Path -LiteralPath $SigningKey).Path.Replace('\','/')
$env:IDF_PATH = (Resolve-Path -LiteralPath $IdfPath).Path
$env:IDF_TOOLS_PATH = (Resolve-Path -LiteralPath $ToolsPath).Path
$env:IDF_PYTHON_ENV_PATH = (Resolve-Path -LiteralPath $PythonEnvPath).Path
. "$env:IDF_PATH/export.ps1"
if ($LASTEXITCODE -ne 0) { throw 'ESP-IDF export failed' }
$otaIndex = [int]$Variant.Substring(1)
$otaSchema = if ($otaIndex -eq 1) { 1 } else { 2 }
$otaHealthFail = if ($otaIndex -eq 3) { 'ON' } else { 'OFF' }
$otaBuild = Join-Path $otaProject ".build/$Variant"
New-Item -ItemType Directory -Force -Path $otaBuild | Out-Null
$otaPrivateDefaults = Join-Path $otaBuild 'signing.defaults'
Set-Content -LiteralPath $otaPrivateDefaults -Encoding utf8 -Value @(
    "CONFIG_SECURE_BOOT_SIGNING_KEY=`"$otaKey`"",
    'CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y',
    'CONFIG_BOOTLOADER_APP_SECURE_VERSION=0'
)
$otaDefaults = (Join-Path $otaProject 'sdkconfig.defaults').Replace('\','/') + ';' + $otaPrivateDefaults.Replace('\','/')
$otaPython = Join-Path $env:IDF_PYTHON_ENV_PATH 'Scripts/python.exe'
Push-Location -LiteralPath $otaProject
try {
    & $otaPython "$env:IDF_PATH/tools/idf.py" -B $otaBuild `
        "-DSDKCONFIG=$($otaBuild.Replace('\','/'))/sdkconfig" `
        "-DSDKCONFIG_DEFAULTS=$otaDefaults" `
        "-DPROJECT_VER=$otaIndex.0.0" "-DLAB_VERSION_CODE=$otaIndex" `
        "-DLAB_CFG_SCHEMA=$otaSchema" "-DLAB_HEALTH_FAIL=$otaHealthFail" build
    exit $LASTEXITCODE
} finally { Pop-Location }
