<#
.SYNOPSIS
Asserts the Windows end-to-end run produced a usable deployment folder.

.DESCRIPTION
Run against the -Output directory of a `-Keep umbrella,dart` build of the
synthetic fixture zip.

.PARAMETER DeployRoot
The -Output directory the repack wrote into.
#>
param(
    [Parameter(Mandatory)][string]$DeployRoot
)

$ErrorActionPreference = 'Stop'

$dirs = @(Get-ChildItem -LiteralPath $DeployRoot -Directory)
if ($dirs.Count -ne 1) {
    throw "expected exactly one deployment folder, found $($dirs.Count)"
}
$deploy = $dirs[0].FullName
Write-Output "deployment folder: $deploy"

foreach ($f in 'install.ps1', 'uninstall.ps1', 'detect.ps1', 'OrgInfo.json') {
    if (-not (Test-Path -LiteralPath (Join-Path $deploy $f))) { throw "missing $f" }
}

# only the kept modules are shipped
$msis = @(Get-ChildItem -LiteralPath $deploy -Filter '*.msi' | ForEach-Object { $_.Name })
if ($msis.Count -ne 3) { throw "expected 3 MSIs, found: $($msis -join ', ')" }
foreach ($want in 'core-vpn', 'umbrella', 'dart') {
    if (-not ($msis | Where-Object { $_ -like "*-$want-*" })) { throw "kept module missing: $want" }
}
foreach ($drop in 'nvm', 'iseposture', 'posture') {
    if ($msis | Where-Object { $_ -like "*-$drop-*" }) { throw "dropped module shipped: $drop" }
}

# every generated script must actually parse
foreach ($f in 'install.ps1', 'uninstall.ps1', 'detect.ps1') {
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $deploy $f), [ref]$null, [ref]$errors)
    if ($errors) { throw "$f does not parse: $($errors[0].Message)" }
}

$install = Get-Content -LiteralPath (Join-Path $deploy 'install.ps1') -Raw
if ($install -notmatch '-PassThru') { throw 'install.ps1 does not capture the msiexec exit code' }
if ($install -notmatch 'exit 3010') { throw 'install.ps1 does not propagate a required reboot' }
$corePos = $install.IndexOf('core-vpn')
$umbPos  = $install.IndexOf('umbrella-predeploy')
if ($corePos -lt 0 -or $umbPos -lt $corePos) { throw 'install.ps1 does not install the core VPN first' }
if ($install -notmatch 'Cisco Secure Client\\Umbrella') { throw 'install.ps1 does not deploy OrgInfo.json' }

$detect = Get-Content -LiteralPath (Join-Path $deploy 'detect.ps1') -Raw
if ($detect -notmatch '9\.9\.9\.9') { throw 'detect.ps1 is not version-aware' }
if ($detect -notmatch '\*Umbrella\*') { throw 'detect.ps1 does not check the kept Umbrella module' }

$uninstall = Get-Content -LiteralPath (Join-Path $deploy 'uninstall.ps1') -Raw
if ($uninstall -match 'Win32_Product') { throw 'uninstall.ps1 still uses Win32_Product' }

Write-Output 'end-to-end assertions passed'
