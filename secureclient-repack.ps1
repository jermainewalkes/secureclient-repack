<#
.SYNOPSIS
Repackage the Cisco Secure Client Windows predeploy bundle for MDM deployment.

.DESCRIPTION
Locates the Cisco Secure Client predeploy zip (a bundle of per-module MSIs),
lets you choose which modules to keep (the core VPN MSI is pinned) and emits
a deployment folder containing the kept MSIs plus generated install.ps1,
uninstall.ps1 and detect.ps1 scripts suitable for Intune Win32 apps and
other MDMs. The MSIs are already signed by Cisco, so nothing is re-signed.

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
    Justification = 'Interactive console tool; host output is the interface')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Zip,
    [string]$SearchDir = (Join-Path $HOME 'Downloads'),
    [string]$Keep,
    [string]$OrgInfo,
    [string]$Output,
    [switch]$IntuneWin,
    [string]$IntuneWinAppUtil,
    [switch]$Yes,
    [switch]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.0.0'

if ($Version) {
    Write-Output "secureclient-repack $script:ToolVersion"
    return
}

# ---------- module vocabulary --------------------------------------------------
function Get-ModuleCode {
    param([Parameter(Mandatory)][string]$Name)
    $n = $Name.ToLowerInvariant()
    if ($n -match 'core.*vpn|vpn.*core|anyconnect.*core') { return 'vpn' }
    if ($n -match 'umbrella')                    { return 'umbrella' }
    if ($n -match 'dart')                        { return 'dart' }
    if ($n -match 'iseposture|ise-posture')      { return 'ise' }
    if ($n -match 'nvm|network.?visibility')     { return 'nvm' }
    if ($n -match 'thousandeyes')                { return 'te' }
    if ($n -match 'zta|zero.?trust')             { return 'zta' }
    if ($n -match 'fireamp|amp')                 { return 'amp' }
    if ($n -match 'firewall.?posture|hostscan')  { return 'sfp' }
    if ($n -match 'posture')                     { return 'posture' }
    if ($n -match 'nam|network.?access')         { return 'nam' }
    if ($n -match 'sbl|start.?before')           { return 'sbl' }
    if ($n -match 'websecurity')                 { return 'websecurity' }
    return 'mod'
}

function Get-ModuleFriendlyName {
    param([Parameter(Mandatory)][string]$Code)
    switch ($Code) {
        'vpn'         { 'VPN — Core & AnyConnect (base client, pinned)' }
        'umbrella'    { 'Umbrella Roaming Security' }
        'dart'        { 'DART — Diagnostics & Reporting' }
        'ise'         { 'ISE Posture' }
        'nvm'         { 'Network Visibility Module' }
        'te'          { 'ThousandEyes Endpoint Agent' }
        'zta'         { 'Zero Trust Access' }
        'amp'         { 'AMP Enabler / Secure Endpoint' }
        'sfp'         { 'Secure Firewall Posture' }
        'posture'     { 'Posture' }
        'nam'         { 'Network Access Manager' }
        'sbl'         { 'Start Before Login' }
        'websecurity' { 'Web Security (deprecated)' }
        default       { $Code }
    }
}

function Test-PinnedModule {
    param([Parameter(Mandatory)][string]$Code)
    return $Code -eq 'vpn'
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
    $core  = @($Kept | Where-Object { Test-PinnedModule -Code $_.Code })
    $rest  = @($Kept | Where-Object { -not (Test-PinnedModule -Code $_.Code) })
    $lines = @(
        '# install.ps1 — generated by secureclient-repack',
        '# Installs the kept Cisco Secure Client modules. Core VPN installs first.',
        '$ErrorActionPreference = ''Stop''',
        '$here = Split-Path -Parent $MyInvocation.MyCommand.Path',
        ''
    )
    foreach ($m in ($core + $rest)) {
        $lines += 'Start-Process msiexec.exe -Wait -ArgumentList "/package `"$here\' + $m.Name + '`" /qn /norestart"'
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
    $lines += @('', 'exit 0')
    return ($lines -join "`r`n")
}

function New-UninstallScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns script text; writes nothing itself')]
    param([Parameter(Mandatory)][object[]]$Kept)
    $core = @($Kept | Where-Object { Test-PinnedModule -Code $_.Code })
    $rest = @($Kept | Where-Object { -not (Test-PinnedModule -Code $_.Code) })
    $lines = @(
        '# uninstall.ps1 — generated by secureclient-repack',
        '# Removes the kept Cisco Secure Client modules. Core VPN is removed last.',
        '$ErrorActionPreference = ''Stop''',
        ''
    )
    # Reverse order: optional modules first, core last.
    foreach ($m in ($rest + $core)) {
        $lines += '$app = Get-CimInstance Win32_Product -Filter "Name LIKE ''%Cisco Secure Client%''" | Where-Object { $_.PackageName -eq ''' + $m.Name + ''' }'
        $lines += 'if ($app) { Start-Process msiexec.exe -Wait -ArgumentList "/x $($app.IdentifyingNumber) /qn /norestart" }'
        $lines += ''
    }
    $lines += 'exit 0'
    return ($lines -join "`r`n")
}

function New-DetectScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns script text; writes nothing itself')]
    param()
    $lines = @(
        '# detect.ps1 — generated by secureclient-repack',
        '# Intune Win32 detection: succeeds (exit 0 with output) when the core',
        '# Cisco Secure Client VPN agent is present.',
        '$exe = Join-Path ${env:ProgramFiles(x86)} ''Cisco\Cisco Secure Client\vpnagent.exe''',
        '$reg = Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'', ''HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'' -ErrorAction SilentlyContinue |',
        '    Where-Object { $_.DisplayName -like ''Cisco Secure Client*'' }',
        'if ((Test-Path -LiteralPath $exe) -or $reg) {',
        '    Write-Output ''Cisco Secure Client detected''',
        '    exit 0',
        '}',
        'exit 1'
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
    Expand-Archive -LiteralPath $zipPath -DestinationPath $work -Force

    $msis = @(Get-ChildItem -Path $work -Recurse -File -Filter '*.msi' | Sort-Object Name)
    if ($msis.Count -eq 0) { throw 'No MSIs found in the predeploy zip.' }

    $modules = @($msis | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            Path = $_.FullName
            Code = Get-ModuleCode -Name $_.Name
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
        foreach ($m in $modules) { $state[$m.Name] = (Test-PinnedModule -Code $m.Code) }
        while ($true) {
            Write-Host ''
            Write-Host 'Modules in this bundle — choose which to KEEP (pinned = required base):'
            Write-Host ''
            for ($i = 0; $i -lt $modules.Count; $i++) {
                $mark = if ($state[$modules[$i].Name]) { 'x' } else { ' ' }
                Write-Host ("  {0,2}) [{1}] {2}" -f ($i + 1), $mark, (Get-ModuleFriendlyName -Code $modules[$i].Code))
            }
            Write-Host ''
            Write-Host '  toggle: numbers (e.g. 2 6)    a: keep all    n: pinned only    Enter: accept'
            $reply = Read-Host '>'
            if (-not $reply) { break }
            switch -Regex ($reply.Trim()) {
                '^[aA]$' { foreach ($m in $modules) { $state[$m.Name] = $true } }
                '^[nN]$' { foreach ($m in $modules) { $state[$m.Name] = (Test-PinnedModule -Code $m.Code) } }
                default {
                    foreach ($tok in ($reply -split '\s+')) {
                        if ($tok -notmatch '^\d+$') { Write-Host "  ignoring '$tok'"; continue }
                        $idx = [int]$tok - 1
                        if ($idx -lt 0 -or $idx -ge $modules.Count) { Write-Host "  out of range: $tok"; continue }
                        if (Test-PinnedModule -Code $modules[$idx].Code) {
                            Write-Host ("  {0} is a pinned base component and stays selected." -f $modules[$idx].Name)
                        } else {
                            $state[$modules[$idx].Name] = -not $state[$modules[$idx].Name]
                        }
                    }
                }
            }
        }
        $kept = @($modules | Where-Object { $state[$_.Name] })
    }

    $tag = ($kept | ForEach-Object { $_.Code } | Sort-Object -Unique) -join '-'
    Write-Host ''
    Write-Host "Keeping: $tag"
    $umbrellaKept = [bool]($kept | Where-Object { $_.Code -eq 'umbrella' })

    # ---------- 4. OrgInfo.json ------------------------------------------------------
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

    # ---------- 5. emit the deployment folder ----------------------------------------
    $deployName = "SecureClient-$bundleVersion-$tag"
    $deployDir = Join-Path $Output $deployName
    if (Test-Path -LiteralPath $deployDir) {
        if ($PSCmdlet.ShouldProcess($deployDir, 'Replace existing deployment folder')) {
            Remove-Item -LiteralPath $deployDir -Recurse -Force
        } else {
            throw "Output folder already exists: $deployDir"
        }
    }
    New-Item -ItemType Directory -Path $deployDir | Out-Null

    foreach ($m in $kept) { Copy-Item -LiteralPath $m.Path -Destination (Join-Path $deployDir $m.Name) }
    if ($orgPath) { Copy-Item -LiteralPath $orgPath -Destination (Join-Path $deployDir 'OrgInfo.json') }

    Set-Content -LiteralPath (Join-Path $deployDir 'install.ps1')   -Value (New-InstallScript -Kept $kept -HasOrgInfo:([bool]$orgPath)) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $deployDir 'uninstall.ps1') -Value (New-UninstallScript -Kept $kept) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $deployDir 'detect.ps1')    -Value (New-DetectScript) -Encoding UTF8

    Write-Host ''
    Write-Host 'Deployment folder contents:'
    Get-ChildItem -LiteralPath $deployDir | ForEach-Object { Write-Host ('  ' + $_.Name) }
    if (-not $Yes) {
        $null = Read-Host 'Folder correct? Enter to continue, Ctrl-C to abort'
    }

    # ---------- 6. optional .intunewin wrap -------------------------------------------
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
    Write-Host '  - Core VPN installs first; the remaining MSIs follow automatically.'
    if ($umbrellaKept) {
        Write-Host '  - Umbrella consumes OrgInfo.json on first launch. On a client already'
        Write-Host '    registered, clear the adjacent "data" directory to force re-registration.'
    }
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
