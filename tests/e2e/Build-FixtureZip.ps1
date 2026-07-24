<#
.SYNOPSIS
Builds a synthetic predeploy zip for the Windows end-to-end test.

.DESCRIPTION
Nothing here comes from Cisco. The MSIs are placeholder files whose names
follow the real predeploy shape, which is what the module vocabulary matches
against. They are unsigned, so the run that consumes this fixture must pass
-AllowUnsignedMsi.

.PARAMETER Destination
Directory to create the fixture in. Replaced if it already exists.
#>
param(
    [Parameter(Mandatory)][string]$Destination
)

$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $Destination) {
    Remove-Item -LiteralPath $Destination -Recurse -Force
}
New-Item -ItemType Directory -Path $Destination | Out-Null

$stage = Join-Path $Destination 'stage'
New-Item -ItemType Directory -Path $stage | Out-Null

# core-vpn is the pinned base; iseposture and posture together prove the two
# posture modules stay distinct
$modules = @('core-vpn', 'umbrella', 'dart', 'nvm', 'iseposture', 'posture')
foreach ($m in $modules) {
    $name = "cisco-secure-client-win-9.9.9.9-$m-predeploy-k9.msi"
    Set-Content -LiteralPath (Join-Path $stage $name) -Value "synthetic placeholder for $m" -Encoding Ascii
}

$zip = Join-Path $Destination 'cisco-secure-client-win-9.9.9.9-predeploy-k9.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip

Set-Content -LiteralPath (Join-Path $Destination 'OrgInfo.json') `
    -Value '{"organizationId":"1234567","fingerprint":"abcdef","userId":"7654321"}'

Write-Output "fixture zip built: $zip"
