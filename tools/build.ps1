param(
    [ValidateSet('v1','v2','v3','v4','v5','v6')][string]$Variant = 'v1',
    [Parameter(Mandatory=$true)][string]$SigningKey,
    [string]$IdfPath,
    [string]$ToolsPath,
    [string]$PythonEnvPath,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.+_-]{0,30}$')][string]$ProjectVersion,
    [ValidateScript({
        if ($_ -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or $_.Contains('..') -or $_.EndsWith('.') -or
            $_ -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw 'BuildName must be one safe path segment, without .., separators, trailing dots or Windows device names'
        }
        $true
    })][string]$BuildName,
    [switch]$FaultProfile,
    [ValidateRange(1,2147483647)][int]$VersionCode
)
$ErrorActionPreference = 'Stop'
$otaIndex = [int]$Variant.Substring(1)
$otaPolicyCode = if ($PSBoundParameters.ContainsKey('VersionCode')) { $VersionCode } else { $otaIndex }
if ($FaultProfile -and $Variant -ne 'v5') { throw 'FaultProfile is only allowed for the explicit v5 test variant' }
$otaFaultMode = if ($FaultProfile) { 'ON' } else { 'OFF' }
if (-not $ProjectVersion) { $ProjectVersion = "$otaIndex.0.0" }
if (-not $BuildName) { $BuildName = $Variant }
$otaProject = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not $IdfPath) { $IdfPath = Join-Path $otaProject '.tooling/esp-idf-v6.1' }
if (-not $ToolsPath) { $ToolsPath = Join-Path $otaProject '.tooling/idf-tools' }
if (-not $PythonEnvPath) { $PythonEnvPath = Join-Path $otaProject '.tooling/python-env' }
$otaKey = (Resolve-Path -LiteralPath $SigningKey).Path.Replace('\','/')
$env:IDF_PATH = (Resolve-Path -LiteralPath $IdfPath).Path
$env:IDF_TOOLS_PATH = (Resolve-Path -LiteralPath $ToolsPath).Path
$env:IDF_PYTHON_ENV_PATH = (Resolve-Path -LiteralPath $PythonEnvPath).Path
$env:PYTHONUTF8 = '1'
. "$env:IDF_PATH/export.ps1"
if ($LASTEXITCODE -ne 0) { throw 'ESP-IDF export failed' }
$otaSchema = if ($otaIndex -eq 1) { 1 } else { 2 }
$otaHealthFail = if ($otaIndex -eq 3) { 'ON' } else { 'OFF' }
$otaBuild = Join-Path $otaProject ".build/$BuildName"
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
        "-DPROJECT_VER=$ProjectVersion" "-DLAB_VERSION_CODE=$otaPolicyCode" `
        "-DLAB_CFG_SCHEMA=$otaSchema" "-DLAB_HEALTH_FAIL=$otaHealthFail" `
        "-DLAB_FAULT_PROFILE=$otaFaultMode" '-DLAB_CFG_FAULT_SHADOW_RESET=OFF' `
        '-DLAB_PREVALID_RESET=OFF' build
    exit $LASTEXITCODE
} finally { Pop-Location }
