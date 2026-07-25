<#
.SYNOPSIS
Repackage the Cisco Secure Client Windows predeploy bundle for MDM deployment.

.DESCRIPTION
Locates the Cisco Secure Client predeploy zip (a bundle of per-module MSIs),
lets you choose which modules to keep (the core VPN MSI is pinned) and emits
a deployment folder containing the kept MSIs plus generated install.ps1,
uninstall.ps1 and detect.ps1 scripts suitable for Intune Win32 apps and
other MDMs. The MSIs are shipped unmodified; their Authenticode signatures
are checked and reported, and anything not validly signed is refused unless
-AllowUnsignedMsi is given.

If the Umbrella module is kept, an OrgInfo.json can be embedded so that
install.ps1 drops it to %ProgramData%\Cisco\Cisco Secure Client\Umbrella.

This project is not affiliated with, endorsed by or supported by Cisco
Systems, Inc. Cisco Secure Client is a trademark of Cisco Systems, Inc.
You must supply your own licensed Cisco Secure Client predeploy bundle;
this tool does not download or redistribute any Cisco software.

Copyright (c) 2026 Jermaine Walkes. Released under the MIT licence.

.PARAMETER Zip
Path to the predeploy zip. When omitted the script searches SearchDir.

.PARAMETER SearchDir
Directory searched for the predeploy zip and OrgInfo.json.
Defaults to the user's Downloads folder.

.PARAMETER Keep
Comma-separated module codes to keep, e.g. "umbrella,dart" or "all".
The pinned core module (vpn) is always kept. Implies non-interactive
module selection.

.PARAMETER OrgInfo
Path to the Umbrella OrgInfo.json. When omitted the script searches
SearchDir; pass it explicitly for scripted runs.

.PARAMETER Output
Directory to write the deployment folder into. Defaults to the directory
containing the zip.

.PARAMETER Force
Replace an existing deployment folder of the same name.

.PARAMETER AllowUnsignedMsi
Continue even when a kept MSI has no valid Authenticode signature.

.PARAMETER IntuneWin
Wrap the deployment folder into an .intunewin package. Requires
IntuneWinAppUtil.exe on PATH or via -IntuneWinAppUtil. The tool is never
downloaded automatically.

.PARAMETER IntuneWinAppUtil
Explicit path to IntuneWinAppUtil.exe.

.PARAMETER Yes
Skip the confirmation prompt.

.PARAMETER Version
Print the tool version and exit.

.EXAMPLE
.\secureclient-repack.ps1

.EXAMPLE
.\secureclient-repack.ps1 -Keep umbrella,dart -Yes

.EXAMPLE
.\secureclient-repack.ps1 -Zip C:\pkgs\csc-predeploy.zip -Keep all -Output C:\out
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive console tool. Status must go to the host: Write-Output would land in the return value of every function that emits progress.')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Zip,
    [string]$SearchDir = (Join-Path $HOME 'Downloads'),
    [string]$Keep,
    [string]$OrgInfo,
    [string]$Output,
    [switch]$Force,
    [switch]$AllowUnsignedMsi,
    [switch]$IntuneWin,
    [string]$IntuneWinAppUtil,
    [switch]$Yes,
    [switch]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.2.0'

if ($Version) {
    Write-Output "secureclient-repack $script:ToolVersion"
    return
}

# ---------- module vocabulary --------------------------------------------------
function Get-ModuleCode {
    <#
    .SYNOPSIS
    Map a predeploy MSI filename to a module code.
    .DESCRIPTION
    Canonical names look like cisco-secure-client-win-<version>-<module>-predeploy-k9.msi.
    The module token is extracted first and matched with hyphen boundaries, so a
    code can never match a fragment of an unrelated word or a future rename of
    the surrounding filename.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $n = $Name.ToLowerInvariant()
    $m = [regex]::Match($n, '-\d+(\.\d+)+-(?<mod>.+?)-predeploy')
    # Without a canonical version-and-predeploy shape, fall back to the whole
    # name minus its extension: a trailing ".msi" would otherwise defeat the
    # end-of-token boundary and leave every module unrecognised.
    $token = if ($m.Success) { $m.Groups['mod'].Value } else { $n -replace '\.msi$', '' }

    # Words within a module name may be separated or run together (nvm and
    # network-visibility are both seen in the wild), hence the optional -? .
    # ISE Posture must be tested before Secure Firewall Posture: Cisco ships the
    # latter as plain "-posture-", the former as "-iseposture-".
    switch -Regex ($token) {
        '(^|-)(core-vpn|vpn-core|anyconnect-core)($|-)'   { return 'vpn' }
        '(^|-)umbrella($|-)'                             { return 'umbrella' }
        '(^|-)dart($|-)'                                 { return 'dart' }
        '(^|-)duo($|-)'                                  { return 'duo' }
        '(^|-)(ise-?posture)($|-)'                       { return 'ise' }
        '(^|-)(nvm|network-?visibility)($|-)'            { return 'nvm' }
        '(^|-)thousandeyes($|-)'                         { return 'te' }
        '(^|-)(zta|zero-?trust)($|-)'                    { return 'zta' }
        '(^|-)(fire-?amp|amp)($|-)'                      { return 'amp' }
        '(^|-)(posture|firewall-?posture|hostscan)($|-)' { return 'sfp' }
        '(^|-)(nam|network-?access(-?manager)?)($|-)'    { return 'nam' }
        '(^|-)(sbl|start-?before(-?login)?)($|-)'         { return 'sbl' }
        '(^|-)web-?security($|-)'                        { return 'websecurity' }
        default                                          { return 'mod' }
    }
}

function Get-ModuleFriendlyName {
    param([Parameter(Mandatory)][string]$Code)
    switch ($Code) {
        'vpn'         { 'VPN — Core & AnyConnect (base client, pinned)' }
        'umbrella'    { 'Umbrella Roaming Security' }
        'dart'        { 'DART — Diagnostics & Reporting' }
        'duo'         { 'Duo Desktop' }
        'ise'         { 'ISE Posture' }
        'nvm'         { 'Network Visibility Module' }
        'te'          { 'ThousandEyes Endpoint Agent' }
        'zta'         { 'Zero Trust Access' }
        'amp'         { 'AMP Enabler / Secure Endpoint' }
        'sfp'         { 'Secure Firewall Posture' }
        'nam'         { 'Network Access Manager' }
        'sbl'         { 'Start Before Login' }
        'websecurity' { 'Web Security (deprecated)' }
        default       { $Code }
    }
}

# The core client's Add/Remove Programs name is not identical across builds
# ("AnyConnect VPN" and "Core VPN" are both seen), and both the uninstall order
# and detection depend on recognising it, so match either spelling.
$script:CoreVpnCondition = '($_.DisplayName -like ''*AnyConnect VPN*'' -or $_.DisplayName -like ''*Core VPN*'')'
$script:NotCoreVpnCondition = '(-not ($_.DisplayName -like ''*AnyConnect VPN*'' -or $_.DisplayName -like ''*Core VPN*''))'

function Get-ModuleDisplayNamePattern {
    <#
    .SYNOPSIS
    The Add/Remove Programs DisplayName pattern for a module code.
    .DESCRIPTION
    Used by the generated detect.ps1 to confirm a kept module is actually
    installed. Returns $null for the core client (handled separately, since its
    name varies) and for codes with no dependable pattern.
    #>
    param([Parameter(Mandatory)][string]$Code)
    switch ($Code) {
        'vpn'      { $null }
        'umbrella' { '*Umbrella*' }
        'dart'     { '*Diagnostic*' }
        'duo'      { '*Duo*' }
        'ise'      { '*ISE Posture*' }
        'nvm'      { '*Network Visibility*' }
        'te'       { '*ThousandEyes*' }
        'zta'      { '*Zero Trust*' }
        'amp'      { '*AMP Enabler*' }
        'sfp'      { '*Secure Firewall Posture*' }
        'nam'      { '*Network Access Manager*' }
        'sbl'      { '*Start Before Login*' }
        default    { $null }
    }
}

function Test-PinnedModule {
    param([Parameter(Mandatory)][string]$Code)
    return $Code -eq 'vpn'
}

function Get-MsiProductInfo {
    <#
    .SYNOPSIS
    Read ProductCode and ProductVersion out of an MSI's own Property table.
    .DESCRIPTION
    This is what makes detection exact. Matching on Add/Remove Programs
    DisplayName means guessing a string Cisco can change between builds, and a
    wrong guess leaves detection failing for ever. The product code is the key
    the installer itself uses.

    Returns $null when the file cannot be read as an MSI — on a non-Windows
    host, or for a placeholder — so the caller can fall back.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $installer = $null
    $database = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        # 0 = read-only
        $database = $installer.GetType().InvokeMember(
            'OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $result = @{}
        foreach ($property in 'ProductCode', 'ProductVersion', 'ProductName') {
            $view = $database.GetType().InvokeMember(
                'OpenView', 'InvokeMethod', $null, $database,
                @("SELECT Value FROM Property WHERE Property = '$property'"))
            $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
            $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($record) {
                $result[$property] = $record.GetType().InvokeMember(
                    'StringData', 'GetProperty', $null, $record, @(1))
            }
            $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
        }
        if (-not $result.ContainsKey('ProductCode')) { return $null }
        return [pscustomobject]@{
            ProductCode    = [string]$result['ProductCode']
            ProductVersion = [string]$result['ProductVersion']
            ProductName    = [string]$result['ProductName']
        }
    } catch {
        return $null
    } finally {
        foreach ($obj in $database, $installer) {
            if ($obj) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj) }
        }
    }
}

# ---------- safety helpers ------------------------------------------------------
function Test-SafeMsiName {
    <#
    .SYNOPSIS
    Is this MSI filename safe to embed in a generated script and ship?
    .DESCRIPTION
    NTFS permits $ ( ) ` and ' in filenames, all of which are live inside
    PowerShell string literals. Names are constrained rather than escaped alone,
    so a hostile bundle cannot smuggle anything into the artefacts an MDM runs
    elevated on every endpoint.
    #>
    param([Parameter(Mandatory)][string]$Name)
    return $Name -match '^[A-Za-z0-9._-]+\.msi$'
}

function ConvertTo-PsSingleQuoted {
    <#
    .SYNOPSIS
    Render a string as a PowerShell single-quoted literal.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    return "'" + $Text.Replace("'", "''") + "'"
}

function Expand-ArchiveSafely {
    <#
    .SYNOPSIS
    Extract a zip, refusing any entry whose path escapes the destination.
    .DESCRIPTION
    Expand-Archive in the Microsoft.PowerShell.Archive module shipped with
    Windows PowerShell 5.1 joins the destination with the entry name without
    checking the result stays inside it, so an entry called ..\..\somewhere
    writes outside the work directory (zip slip).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $root = [IO.Path]::GetFullPath($Destination)
    if (-not $root.EndsWith([IO.Path]::DirectorySeparatorChar)) {
        $root += [IO.Path]::DirectorySeparatorChar
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($entry in $archive.Entries) {
            if (-not $entry.Name) { continue }   # directory entry
            $full = [IO.Path]::GetFullPath((Join-Path $Destination $entry.FullName))
            if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing archive entry that escapes the work directory: $($entry.FullName)"
            }
            $dir = Split-Path -Parent $full
            if (-not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $full, $true)
        }
    } finally {
        $archive.Dispose()
    }
}

# ---------- selection logic (testable) ------------------------------------------
function Select-KeptModule {
    <#
    .SYNOPSIS
    Apply a -Keep spec to the discovered module objects (Name, Code).
    .DESCRIPTION
    Returns the module objects to keep. Pinned modules are always kept.
    Throws on a code that matches nothing in the bundle.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Modules,
        [Parameter(Mandatory)][string]$KeepSpec
    )
    $spec = $KeepSpec.Trim().ToLowerInvariant()
    if ($spec -eq 'all') { return $Modules }

    $wanted = @($spec -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $codes  = @($Modules | ForEach-Object { $_.Code })
    foreach ($w in $wanted) {
        if ($codes -notcontains $w) {
            $avail = ($codes | Sort-Object -Unique) -join ' '
            throw "-Keep: no module in this bundle matches '$w' (available: $avail)"
        }
    }
    return @($Modules | Where-Object { (Test-PinnedModule -Code $_.Code) -or ($wanted -contains $_.Code) })
}

function Test-OrgInfoFile {
    <#
    .SYNOPSIS
    Validate an OrgInfo.json candidate: parseable JSON, expected keys present.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "OrgInfo file not found: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw
    try { $json = $raw | ConvertFrom-Json } catch { throw "OrgInfo.json is not valid JSON: $Path" }
    foreach ($k in 'organizationId', 'fingerprint', 'userId') {
        $found = $false
        if ($null -ne $json -and $json -is [psobject]) {
            $found = @($json.PSObject.Properties | ForEach-Object { $_.Name }) -contains $k
        }
        if (-not $found) {
            Write-Warning "'$k' not found in OrgInfo.json — double-check it is the dashboard file."
        }
    }
    return $true
}

# ---------- generated deployment scripts ----------------------------------------
function New-InstallScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns script text; writes nothing itself')]
    param(
        [Parameter(Mandatory)][object[]]$Kept,
        [bool]$HasOrgInfo
    )
    $core = @($Kept | Where-Object { Test-PinnedModule -Code $_.Code })
    $rest = @($Kept | Where-Object { -not (Test-PinnedModule -Code $_.Code) })

    $lines = @(
        '# install.ps1 — generated by secureclient-repack',
        '# Installs the kept Cisco Secure Client modules. Core VPN installs first.',
        '# Exit codes: 0 success, 3010 success but a reboot is required, otherwise',
        '# the failing msiexec code.',
        '$ErrorActionPreference = ''Stop''',
        '$here = Split-Path -Parent $MyInvocation.MyCommand.Path',
        '$script:rebootRequired = $false',
        '# the first failing msiexec code, so the MDM sees the real reason rather',
        '# than a generic failure',
        '$script:firstFailure = 0',
        '',
        'function Install-Msi {',
        '    param([string]$FileName, [switch]$Required)',
        '    $path = Join-Path $here $FileName',
        '    if (-not (Test-Path -LiteralPath $path)) {',
        '        Write-Output "missing installer: $FileName"',
        '        if ($Required) { exit 1 }',
        '        if ($script:firstFailure -eq 0) { $script:firstFailure = 1 }',
        '        return',
        '    }',
        '    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/package `"$path`" /qn /norestart"',
        '    switch ($p.ExitCode) {',
        '        0    { Write-Output "installed: $FileName" }',
        '        3010 { Write-Output "installed, reboot required: $FileName"; $script:rebootRequired = $true }',
        '        1641 { Write-Output "installed, reboot initiated: $FileName"; $script:rebootRequired = $true }',
        '        default {',
        '            Write-Output "FAILED ($($p.ExitCode)): $FileName"',
        '            if ($Required) { exit $p.ExitCode }',
        '            if ($script:firstFailure -eq 0) { $script:firstFailure = $p.ExitCode }',
        '        }',
        '    }',
        '}',
        ''
    )
    foreach ($m in $core) {
        $lines += ('Install-Msi -FileName {0} -Required' -f (ConvertTo-PsSingleQuoted $m.Name))
    }
    foreach ($m in $rest) {
        $lines += ('Install-Msi -FileName {0}' -f (ConvertTo-PsSingleQuoted $m.Name))
    }
    if ($HasOrgInfo) {
        $lines += @(
            '',
            '# Drop the Umbrella OrgInfo.json where Secure Client consumes it.',
            '# Note: on a client already registered, the drop file is ignored until',
            '# the adjacent "data" directory is cleared (or Umbrella is reinstalled).',
            '$umbrellaDir = Join-Path $env:ProgramData ''Cisco\Cisco Secure Client\Umbrella''',
            'New-Item -ItemType Directory -Force -Path $umbrellaDir | Out-Null',
            'Copy-Item -LiteralPath (Join-Path $here ''OrgInfo.json'') -Destination (Join-Path $umbrellaDir ''OrgInfo.json'') -Force'
        )
    }
    $lines += @(
        '',
        'if ($script:firstFailure -ne 0) { exit $script:firstFailure }',
        'if ($script:rebootRequired) { exit 3010 }',
        'exit 0'
    )
    return ($lines -join "`r`n")
}

function New-UninstallScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns script text; writes nothing itself')]
    param()
    # Resolved from the uninstall registry keys rather than Win32_Product:
    # Win32_Product triggers an MSI consistency check of every installed product
    # on the machine, and matching on the source MSI filename cannot remove a
    # client that a different version (or Cisco's own setup.exe) installed.
    $lines = @(
        '# uninstall.ps1 — generated by secureclient-repack',
        '# Removes every installed Cisco Secure Client module. Core VPN goes last.',
        '$ErrorActionPreference = ''Stop''',
        '$keys = @(',
        '    ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'',',
        '    ''HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*''',
        ')',
        '$entries = @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |',
        '    Where-Object { $_.DisplayName -like ''Cisco Secure Client*'' -and $_.PSChildName -match ''^\{[0-9A-Fa-f-]+\}$'' } |',
        '    Sort-Object -Property PSChildName -Unique)',
        'if (-not $entries) { Write-Output ''nothing to uninstall''; exit 0 }',
        '',
        '# optional modules first, the core client last: every module depends on',
        '# the core VPN, so removing it first would strand the rest',
        ('$ordered = @($entries | Where-Object { ' + $script:NotCoreVpnCondition + ' }) +'),
        ('           @($entries | Where-Object { ' + $script:CoreVpnCondition + ' })'),
        '$rebootRequired = $false',
        '$failed = $false',
        'foreach ($e in $ordered) {',
        '    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x $($e.PSChildName) /qn /norestart"',
        '    switch ($p.ExitCode) {',
        '        0    { Write-Output "removed: $($e.DisplayName)" }',
        '        3010 { Write-Output "removed, reboot required: $($e.DisplayName)"; $rebootRequired = $true }',
        '        1605 { Write-Output "not installed: $($e.DisplayName)" }',
        '        default { Write-Output "FAILED ($($p.ExitCode)): $($e.DisplayName)"; $failed = $true }',
        '    }',
        '}',
        'if ($failed) { exit 1 }',
        'if ($rebootRequired) { exit 3010 }',
        'exit 0'
    )
    return ($lines -join "`r`n")
}

function New-DetectScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns script text; writes nothing itself')]
    param(
        [Parameter(Mandatory)][object[]]$Kept,
        [Parameter(Mandatory)][string]$BundleVersion
    )
    # Detection must be version-aware: reporting "installed" for any Cisco Secure
    # Client at all means an upgrade is never delivered, because the MDM sees the
    # older client already present and skips the install.
    $patterns = @($Kept |
        ForEach-Object { Get-ModuleDisplayNamePattern -Code $_.Code } |
        Where-Object { $_ -and $_ -ne '*AnyConnect VPN*' } |
        Sort-Object -Unique)

    $lines = @(
        '# detect.ps1 — generated by secureclient-repack',
        '# Intune Win32 detection: exit 0 with output when the expected client',
        '# version and modules are present, otherwise exit 1.',
        '# The DisplayName patterns below come from Add/Remove Programs; adjust',
        '# them here if your Cisco build labels a module differently.',
        '$ErrorActionPreference = ''Stop''',
        ('$wantedVersion = ' + (ConvertTo-PsSingleQuoted $BundleVersion)),
        '$keys = @(',
        '    ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'',',
        '    ''HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*''',
        ')',
        '$entries = @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |',
        '    Where-Object { $_.DisplayName -like ''Cisco Secure Client*'' })',
        ('$core = @($entries | Where-Object { ' + $script:CoreVpnCondition + ' })'),
        'if (-not $core) { exit 1 }',
        '',
        '# DisplayVersion may carry a suffix such as 5.1.10.233-k9, so take the',
        '# leading numeric part; a stale second entry must not mask a good one, so',
        '# compare against the highest version present',
        'function ConvertTo-ClientVersion {',
        '    param([string]$Text)',
        '    $m = [regex]::Match(([string]$Text), ''^\d+(\.\d+){0,3}'')',
        '    if (-not $m.Success) { return $null }',
        '    $v = $null',
        '    if ([version]::TryParse($m.Value, [ref]$v)) { return $v }',
        '    return $null',
        '}',
        '$installed = @($core | ForEach-Object { ConvertTo-ClientVersion -Text $_.DisplayVersion } |',
        '    Where-Object { $_ } | Sort-Object -Descending)',
        'if (-not $installed) { exit 1 }',
        '$installed = $installed[0]',
        '$wanted = ConvertTo-ClientVersion -Text $wantedVersion',
        'if ($null -eq $wanted) { exit 1 }',
        'if ($installed -lt $wanted) { exit 1 }'
    )
    # Product codes are exact, so prefer them; DisplayName patterns are a guess at
    # a string Cisco controls and can change between builds.
    $codes = @($Kept |
        Where-Object { -not (Test-PinnedModule -Code $_.Code) } |
        ForEach-Object { if ($_.PSObject.Properties['ProductCode']) { $_.ProductCode } } |
        Where-Object { $_ -match '^\{[0-9A-Fa-f-]+\}$' } |
        Sort-Object -Unique)
    $expectedModules = @($Kept | Where-Object { -not (Test-PinnedModule -Code $_.Code) }).Count

    if ($codes.Count -gt 0 -and $codes.Count -eq $expectedModules) {
        $lines += @(
            '',
            '# every kept module must be present too, so adding one to an existing',
            '# install is still delivered. Matched on product code, which the',
            '# installer itself owns, so no DisplayName guesswork is involved.',
            ('$moduleCodes = @(' + (($codes | ForEach-Object { ConvertTo-PsSingleQuoted $_ }) -join ', ') + ')'),
            '$installedCodes = @($entries | ForEach-Object { $_.PSChildName })',
            'foreach ($code in $moduleCodes) {',
            '    if ($installedCodes -notcontains $code) { exit 1 }',
            '}'
        )
    } elseif ($patterns.Count -gt 0) {
        $lines += @(
            '',
            '# every kept module must be present too, so adding one to an existing',
            '# install is still delivered.',
            '# These DisplayName patterns could not be replaced with product codes',
            '# (the MSIs were not readable at repack time). They come from',
            '# Add/Remove Programs: run this script on one pilot device and adjust',
            '# them here if a module in your build is labelled differently.',
            ('$modulePatterns = @(' + (($patterns | ForEach-Object { ConvertTo-PsSingleQuoted $_ }) -join ', ') + ')'),
            'foreach ($pattern in $modulePatterns) {',
            '    if (-not ($entries | Where-Object { $_.DisplayName -like $pattern })) {',
            '        Write-Output "not detected: no installed product matches $pattern"',
            '        exit 1',
            '    }',
            '}'
        )
    }
    $lines += @(
        '',
        'Write-Output "Cisco Secure Client $installed detected"',
        'exit 0'
    )
    return ($lines -join "`r`n")
}

# ---------- test guard -----------------------------------------------------------
# When dot-sourced with SECURECLIENT_REPACK_TEST set, expose the functions
# above without running the pipeline (used by the Pester suite).
if ($env:SECURECLIENT_REPACK_TEST) { return }

# ---------- 1. locate the predeploy zip ------------------------------------------
if ($Zip) {
    if (-not (Test-Path -LiteralPath $Zip)) { throw "Zip not found: $Zip" }
    $zipPath = (Resolve-Path -LiteralPath $Zip).Path
} else {
    Write-Host "== Locating Secure Client predeploy zip in $SearchDir =="
    if (-not (Test-Path -LiteralPath $SearchDir)) { throw "Search directory not found: $SearchDir" }
    $zips = @(Get-ChildItem -LiteralPath $SearchDir -File -Filter '*.zip' |
        Where-Object { $_.Name -match 'secure.*client|anyconnect' -and $_.Name -match 'predeploy' } |
        Sort-Object Name)
    if ($zips.Count -eq 0) { throw "No Secure Client predeploy zip found in $SearchDir (or pass -Zip <path>)." }
    if ($zips.Count -eq 1) {
        $zipPath = $zips[0].FullName
    } elseif ($Keep -or $Yes) {
        throw "Multiple predeploy zips found in $SearchDir — pass -Zip <path> when running non-interactively."
    } else {
        Write-Host 'Multiple predeploy zips found:'
        for ($i = 0; $i -lt $zips.Count; $i++) { Write-Host ("  {0}) {1}" -f ($i + 1), $zips[$i].Name) }
        do {
            $pick = Read-Host 'Select a zip (number)'
        } until ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $zips.Count)
        $zipPath = $zips[[int]$pick - 1].FullName
    }
}
Write-Host "Using: $zipPath"

if (-not $Output) { $Output = Split-Path -Parent $zipPath }
if (-not (Test-Path -LiteralPath $Output)) { New-Item -ItemType Directory -Force -Path $Output | Out-Null }

$verMatch = [regex]::Match((Split-Path -Leaf $zipPath), '\d+\.\d+\.\d+(\.\d+)?')
$bundleVersion = if ($verMatch.Success) { $verMatch.Value } else { 'custom' }

# ---------- 2. extract and discover the MSIs -------------------------------------
$work = Join-Path ([IO.Path]::GetTempPath()) ('secureclient-repack-' + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host '== Extracting =='
    Expand-ArchiveSafely -Path $zipPath -Destination $work

    $msis = @(Get-ChildItem -Path $work -Recurse -File -Filter '*.msi' | Sort-Object Name)
    if ($msis.Count -eq 0) { throw 'No MSIs found in the predeploy zip.' }

    $unsafe = @($msis | Where-Object { -not (Test-SafeMsiName -Name $_.Name) })
    if ($unsafe) {
        throw ("Refusing MSI filenames that are unsafe to embed in the generated scripts: " +
               (($unsafe | ForEach-Object { $_.Name }) -join ', '))
    }

    $duplicates = @($msis | Group-Object Name | Where-Object { $_.Count -gt 1 })
    if ($duplicates) {
        throw ("The bundle contains repeated MSI filenames, so the wrong copy could be shipped: " +
               (($duplicates | ForEach-Object { $_.Name }) -join ', '))
    }

    $modules = @($msis | ForEach-Object {
        $info = Get-MsiProductInfo -Path $_.FullName
        [pscustomobject]@{
            Name           = $_.Name
            Path           = $_.FullName
            Code           = Get-ModuleCode -Name $_.Name
            ProductCode    = if ($info) { $info.ProductCode } else { $null }
            ProductVersion = if ($info) { $info.ProductVersion } else { $null }
        }
    })
    if (-not ($modules | Where-Object { Test-PinnedModule -Code $_.Code })) {
        throw 'Could not identify the core VPN MSI in the bundle — is this a Secure Client predeploy zip?'
    }

    # ---------- 3. module selection ------------------------------------------------
    if ($Keep) {
        $kept = Select-KeptModule -Modules $modules -KeepSpec $Keep
    } else {
        $state = @{}
        foreach ($m in $modules) { $state[$m.Path] = (Test-PinnedModule -Code $m.Code) }
        while ($true) {
            Write-Host ''
            Write-Host 'Modules in this bundle — choose which to KEEP (pinned = required base):'
            Write-Host ''
            for ($i = 0; $i -lt $modules.Count; $i++) {
                $mark = if ($state[$modules[$i].Path]) { 'x' } else { ' ' }
                Write-Host ("  {0,2}) [{1}] {2}" -f ($i + 1), $mark, (Get-ModuleFriendlyName -Code $modules[$i].Code))
            }
            Write-Host ''
            Write-Host '  toggle: numbers (e.g. 2 6)    a: keep all    n: pinned only    Enter: accept'
            $reply = Read-Host '>'
            if (-not $reply) { break }
            switch -Regex ($reply.Trim()) {
                '^[aA]$' { foreach ($m in $modules) { $state[$m.Path] = $true } }
                '^[nN]$' { foreach ($m in $modules) { $state[$m.Path] = (Test-PinnedModule -Code $m.Code) } }
                default {
                    foreach ($tok in ($reply -split '\s+')) {
                        if ($tok -notmatch '^\d+$') { Write-Host "  ignoring '$tok'"; continue }
                        $idx = [int]$tok - 1
                        if ($idx -lt 0 -or $idx -ge $modules.Count) { Write-Host "  out of range: $tok"; continue }
                        if (Test-PinnedModule -Code $modules[$idx].Code) {
                            Write-Host ("  {0} is a pinned base component and stays selected." -f $modules[$idx].Name)
                        } else {
                            $state[$modules[$idx].Path] = -not $state[$modules[$idx].Path]
                        }
                    }
                }
            }
        }
        $kept = @($modules | Where-Object { $state[$_.Path] })
    }

    $tag = ($kept | ForEach-Object { $_.Code } | Sort-Object -Unique) -join '-'
    Write-Host ''
    Write-Host "Keeping: $tag"
    $umbrellaKept = [bool]($kept | Where-Object { $_.Code -eq 'umbrella' })

    # ---------- 4. Authenticode check ------------------------------------------------
    Write-Host ''
    Write-Host '== Checking MSI signatures =='
    $badlySigned = @()
    $foreignSigner = @()
    foreach ($m in $kept) {
        $sig = Get-AuthenticodeSignature -LiteralPath $m.Path
        if ($sig.Status -eq 'Valid') {
            $subject = [string]$sig.SignerCertificate.Subject
            Write-Host ("  ok      {0} — {1}" -f $m.Name, $subject)
            # a valid signature only proves *someone* trusted signed it, which is
            # not the same as it having come from Cisco. Match the whole O
            # component: a bare substring would also accept an organisation such
            # as "Cisco Systems Consulting".
            if ($subject -notmatch 'O=Cisco Systems, Inc\.($|,)') {
                $foreignSigner += [pscustomobject]@{ Name = $m.Name; Subject = $subject }
            }
        } else {
            Write-Host ("  UNSAFE  {0} — signature status: {1}" -f $m.Name, $sig.Status)
            $badlySigned += $m
        }
    }
    foreach ($f in $foreignSigner) {
        Write-Warning ("{0} is validly signed, but not by Cisco Systems: {1}" -f $f.Name, $f.Subject)
    }
    if ($badlySigned) {
        if ($AllowUnsignedMsi) {
            Write-Warning ("Continuing with {0} MSI(s) that are not validly signed (-AllowUnsignedMsi)." -f $badlySigned.Count)
        } else {
            throw ("These MSIs are not validly signed, so they will not be packaged: " +
                   (($badlySigned | ForEach-Object { $_.Name }) -join ', ') +
                   ". Re-download the bundle from Cisco, or pass -AllowUnsignedMsi if this is a deliberately re-signed internal build.")
        }
    }

    # ---------- 5. OrgInfo.json ------------------------------------------------------
    $orgPath = $null
    if ($umbrellaKept) {
        Write-Host ''
        Write-Host '== Umbrella kept — locating OrgInfo.json =='
        if ($OrgInfo) {
            $orgPath = (Resolve-Path -LiteralPath $OrgInfo).Path
        } else {
            $cands = @(Get-ChildItem -LiteralPath $SearchDir -File -Filter 'orginfo*.json' -ErrorAction SilentlyContinue |
                Sort-Object Name)
            if ($cands.Count -eq 1) {
                $orgPath = $cands[0].FullName
                Write-Host "Found: $orgPath"
            } elseif ($cands.Count -gt 1) {
                if ($Keep -or $Yes) { throw "Multiple OrgInfo files in $SearchDir — pass -OrgInfo <path> when running non-interactively." }
                Write-Host 'Multiple OrgInfo files found:'
                for ($i = 0; $i -lt $cands.Count; $i++) { Write-Host ("  {0}) {1}" -f ($i + 1), $cands[$i].Name) }
                do { $pick = Read-Host 'Select OrgInfo.json (number)' }
                until ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $cands.Count)
                $orgPath = $cands[[int]$pick - 1].FullName
            } elseif ($Keep -or $Yes) {
                Write-Host "No OrgInfo.json found in $SearchDir — skipping. Umbrella will not register until it is deployed separately."
            } else {
                $entered = Read-Host 'Path to OrgInfo.json (or Enter to skip)'
                if ($entered) { $orgPath = (Resolve-Path -LiteralPath $entered.Trim('"', "'")).Path }
                else { Write-Host 'Skipping OrgInfo — Umbrella will not register until it is deployed separately.' }
            }
        }
        if ($orgPath) { Test-OrgInfoFile -Path $orgPath | Out-Null }
    }

    # ---------- 6. emit the deployment folder ----------------------------------------
    $deployName = "SecureClient-$bundleVersion-$tag"
    $deployDir = Join-Path $Output $deployName
    if (Test-Path -LiteralPath $deployDir) {
        if (-not $Force) {
            throw "Output folder already exists: $deployDir (pass -Force to replace it)"
        }
        if ($PSCmdlet.ShouldProcess($deployDir, 'Replace existing deployment folder')) {
            Remove-Item -LiteralPath $deployDir -Recurse -Force
        }
    }
    New-Item -ItemType Directory -Path $deployDir | Out-Null

    foreach ($m in $kept) { Copy-Item -LiteralPath $m.Path -Destination (Join-Path $deployDir $m.Name) }
    if ($orgPath) { Copy-Item -LiteralPath $orgPath -Destination (Join-Path $deployDir 'OrgInfo.json') }

    Set-Content -LiteralPath (Join-Path $deployDir 'install.ps1')   -Value (New-InstallScript -Kept $kept -HasOrgInfo:([bool]$orgPath)) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $deployDir 'uninstall.ps1') -Value (New-UninstallScript) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $deployDir 'detect.ps1')    -Value (New-DetectScript -Kept $kept -BundleVersion $bundleVersion) -Encoding UTF8

    $optional = @($kept | Where-Object { -not (Test-PinnedModule -Code $_.Code) })
    $withCode = @($optional | Where-Object { $_.ProductCode })
    if ($optional.Count -eq 0) {
        Write-Host 'Detection: core client version only.'
    } elseif ($withCode.Count -eq $optional.Count) {
        Write-Host 'Detection: core client version plus each module''s product code.'
    } else {
        Write-Host 'Detection: core client version plus module DisplayName patterns —'
        Write-Host '  the MSI product codes could not be read, so verify detect.ps1 on a pilot device.'
    }

    Write-Host ''
    Write-Host 'Deployment folder contents:'
    Get-ChildItem -LiteralPath $deployDir | ForEach-Object { Write-Host ('  ' + $_.Name) }
    if (-not $Yes) {
        $null = Read-Host 'Folder correct? Enter to continue, Ctrl-C to abort'
    }

    # ---------- 7. optional .intunewin wrap -------------------------------------------
    if ($IntuneWin) {
        $tool = $null
        if ($IntuneWinAppUtil) {
            if (Test-Path -LiteralPath $IntuneWinAppUtil) { $tool = $IntuneWinAppUtil }
            else { throw "IntuneWinAppUtil.exe not found at: $IntuneWinAppUtil" }
        } else {
            $cmd = Get-Command IntuneWinAppUtil.exe -ErrorAction SilentlyContinue
            if ($cmd) { $tool = $cmd.Source }
        }
        if ($tool) {
            Write-Host '== Wrapping into .intunewin =='
            & $tool -c $deployDir -s 'install.ps1' -o $Output -q
            Write-Host ("IntuneWin package written to {0}" -f $Output)
        } else {
            Write-Host 'IntuneWinAppUtil.exe not found on PATH — skipping the .intunewin wrap.'
            Write-Host 'Download it from the Microsoft Win32 Content Prep Tool repository:'
            Write-Host '  https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool'
        }
    }

    # ---------- done -------------------------------------------------------------------
    Write-Host ''
    Write-Host 'DONE.'
    Write-Host "Deployment folder : $deployDir"
    Write-Host ''
    Write-Host 'Next steps:'
    Write-Host '  - Upload as a Win32 app (or wrap with -IntuneWin) using install.ps1,'
    Write-Host '    uninstall.ps1 and detect.ps1.'
    Write-Host '  - install.ps1 returns 3010 when a reboot is required; map that to'
    Write-Host '    "soft reboot" in your MDM so the client finishes cleanly.'
    Write-Host '  - detect.ps1 checks the installed version, so upgrades are delivered.'
    Write-Host '    Verify its DisplayName patterns against a pilot device once.'
    if ($umbrellaKept) {
        Write-Host '  - Umbrella consumes OrgInfo.json on first launch. On a client already'
        Write-Host '    registered, clear the adjacent "data" directory to force re-registration.'
    }
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
