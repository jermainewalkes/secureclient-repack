# Pester tests for secureclient-repack.ps1. The script is dot-sourced with
# SECURECLIENT_REPACK_TEST set, which exposes its functions without running
# the pipeline. No Cisco content is required — module lists are synthetic, but
# the filenames match the real predeploy shape so prefix-driven mismatches are
# actually reachable.

BeforeAll {
    $env:SECURECLIENT_REPACK_TEST = '1'
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'secureclient-repack.ps1')

    $script:SampleModules = @(
        [pscustomobject]@{ Name = 'cisco-secure-client-win-5.1.16.194-core-vpn-predeploy-k9.msi'; Code = 'vpn' },
        [pscustomobject]@{ Name = 'cisco-secure-client-win-5.1.16.194-umbrella-predeploy-k9.msi'; Code = 'umbrella' },
        [pscustomobject]@{ Name = 'cisco-secure-client-win-5.1.16.194-dart-predeploy-k9.msi';     Code = 'dart' },
        [pscustomobject]@{ Name = 'cisco-secure-client-win-5.1.16.194-nvm-predeploy-k9.msi';      Code = 'nvm' }
    )

    # Parses generated script text the way PowerShell itself would, and reports
    # how many syntax errors it found. Returning the count rather than the error
    # collection avoids PowerShell unrolling an empty array to $null, which
    # Set-StrictMode then rejects when .Count is read.
    function script:Get-ScriptParseErrorCount {
        param([Parameter(Mandatory)][string]$Text)
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$null, [ref]$errors)
        if ($null -eq $errors) { return 0 }
        return @($errors).Count
    }
}

AfterAll {
    Remove-Item Env:SECURECLIENT_REPACK_TEST -ErrorAction SilentlyContinue
}

Describe 'Get-ModuleCode' {
    It 'identifies the core VPN MSI' {
        Get-ModuleCode -Name 'cisco-secure-client-win-5.1.16.194-core-vpn-predeploy-k9.msi' | Should -Be 'vpn'
    }
    It 'identifies every optional module Cisco ships' {
        $cases = @{
            'umbrella'     = 'umbrella'
            'dart'         = 'dart'
            'iseposture'   = 'ise'
            'nvm'          = 'nvm'
            'thousandeyes' = 'te'
            'zta'          = 'zta'
            'amp'          = 'amp'
            'nam'          = 'nam'
            'sbl'          = 'sbl'
            'websecurity'  = 'websecurity'
        }
        foreach ($token in $cases.Keys) {
            $name = "cisco-secure-client-win-5.1.16.194-$token-predeploy-k9.msi"
            Get-ModuleCode -Name $name | Should -Be $cases[$token] -Because "$name should map to $($cases[$token])"
        }
    }
    It 'maps plain -posture- to Secure Firewall Posture, not the generic code' {
        # Cisco ships Secure Firewall Posture as "-posture-", so a bundle that
        # contains it must be selectable as sfp
        Get-ModuleCode -Name 'cisco-secure-client-win-5.1.16.194-posture-predeploy-k9.msi' | Should -Be 'sfp'
    }
    It 'distinguishes ISE posture from Secure Firewall Posture' {
        Get-ModuleCode -Name 'cisco-secure-client-win-5.1.16.194-iseposture-predeploy-k9.msi' | Should -Be 'ise'
    }
    It 'accepts the hyphenated spellings of multi-word modules' {
        $cases = @{
            'network-visibility'     = 'nvm'
            'zero-trust'             = 'zta'
            'start-before-login'     = 'sbl'
            'network-access-manager' = 'nam'
            'ise-posture'            = 'ise'
            'firewall-posture'       = 'sfp'
        }
        foreach ($token in $cases.Keys) {
            $name = "cisco-secure-client-win-5.1.16.194-$token-predeploy-k9.msi"
            Get-ModuleCode -Name $name | Should -Be $cases[$token] -Because "$name should map to $($cases[$token])"
        }
    }
    It 'still recognises a module when the name has no version or predeploy marker' {
        # the fallback token must not keep the .msi extension, or the
        # end-of-token boundary can never match
        Get-ModuleCode -Name 'umbrella.msi' | Should -Be 'umbrella'
        Get-ModuleCode -Name 'core-vpn.msi' | Should -Be 'vpn'
    }
    It 'does not match a code against a fragment of the surrounding filename' {
        # every real name contains "client" and "secure"; nothing should latch on
        Get-ModuleCode -Name 'cisco-secure-client-win-5.1.16.194-mystery-predeploy-k9.msi' | Should -Be 'mod'
        Get-ModuleCode -Name 'cisco-secure-client-win-5.1.16.194-ampere-predeploy-k9.msi'  | Should -Be 'mod'
        Get-ModuleCode -Name 'cisco-secure-client-win-5.1.16.194-namespace-predeploy-k9.msi' | Should -Be 'mod'
    }
}

Describe 'Test-SafeMsiName' {
    It 'accepts real predeploy filenames' {
        Test-SafeMsiName -Name 'cisco-secure-client-win-5.1.16.194-core-vpn-predeploy-k9.msi' | Should -BeTrue
    }
    It 'rejects names carrying PowerShell metacharacters' {
        Test-SafeMsiName -Name 'core-vpn$(hostname).msi'   | Should -BeFalse
        Test-SafeMsiName -Name "core-vpn'; iex 'x'.msi"    | Should -BeFalse
        Test-SafeMsiName -Name 'core-vpn`whoami`.msi'      | Should -BeFalse
        Test-SafeMsiName -Name 'core-vpn.msi.exe'          | Should -BeFalse
        Test-SafeMsiName -Name 'sub\dir\core-vpn.msi'      | Should -BeFalse
    }
}

Describe 'ConvertTo-PsSingleQuoted' {
    It 'doubles embedded single quotes' {
        ConvertTo-PsSingleQuoted -Text "it's" | Should -Be "'it''s'"
    }
    It 'produces a literal that evaluates back to the original text' {
        $original = "weird'name`$(1+1).msi"
        $literal  = ConvertTo-PsSingleQuoted -Text $original
        [scriptblock]::Create($literal).Invoke()[0] | Should -Be $original
    }
}

Describe 'Test-PinnedModule' {
    It 'pins only the core VPN module' {
        Test-PinnedModule -Code 'vpn' | Should -BeTrue
        Test-PinnedModule -Code 'umbrella' | Should -BeFalse
        Test-PinnedModule -Code 'dart' | Should -BeFalse
    }
}

Describe 'Select-KeptModule' {
    It 'keeps the pinned core plus the requested codes' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella'
        @($kept).Code | Should -Be @('vpn', 'umbrella')
    }
    It 'accepts a csv of codes with spaces' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella, dart'
        @($kept).Count | Should -Be 3
        @($kept).Code | Should -Contain 'dart'
    }
    It 'keeps everything for all' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'all'
        @($kept).Count | Should -Be 4
    }
    It 'throws on a code not present in the bundle' {
        { Select-KeptModule -Modules $script:SampleModules -KeepSpec 'bogus' } |
            Should -Throw '*no module in this bundle matches*'
    }
}

Describe 'New-InstallScript' {
    It 'installs the core VPN MSI before the optional modules' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $false
        $corePos = $text.IndexOf('core-vpn-predeploy')
        $umbPos  = $text.IndexOf('umbrella-predeploy')
        $corePos | Should -BeGreaterThan -1
        $umbPos  | Should -BeGreaterThan $corePos
    }
    It 'runs msiexec quietly without forcing a restart' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'all'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $false
        $text | Should -Match '/qn /norestart'
    }
    It 'checks the msiexec exit code instead of assuming success' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'all'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $false
        $text | Should -Match '-PassThru'
        $text | Should -Match '\$p\.ExitCode'
    }
    It 'propagates a required reboot as 3010 and a failure as non-zero' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'all'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $false
        $text | Should -Match 'exit 3010'
        $text | Should -Match 'exit \$script:firstFailure'
    }
    It 'returns the real msiexec code when an optional module fails' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'all'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $false
        # a generic 1 would hide the actual reason from the MDM
        $text | Should -Match '\$script:firstFailure = \$p\.ExitCode'
    }
    It 'fails fast when the core module cannot install' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $false
        $text | Should -Match 'Install-Msi -FileName ''[^'']*core-vpn[^'']*'' -Required'
    }
    It 'drops OrgInfo.json to the Umbrella ProgramData path when requested' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $true
        $text | Should -Match ([regex]::Escape('Cisco\Cisco Secure Client\Umbrella'))
        $text | Should -Match 'OrgInfo\.json'
    }
    It 'omits the OrgInfo block when there is no OrgInfo' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'dart'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $false
        $text | Should -Not -Match 'OrgInfo'
    }
    It 'emits a script that parses' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'all'
        $text = New-InstallScript -Kept $kept -HasOrgInfo $true
        Get-ScriptParseErrorCount -Text $text | Should -Be 0
    }
    It 'cannot be broken out of by a hostile MSI filename' {
        # the repack refuses such names outright, but the generator must not be
        # the only thing standing between a bundle and code running as SYSTEM
        $hostile = @(
            [pscustomobject]@{ Name = 'core-vpn$(Write-Output PWNED).msi'; Code = 'vpn' },
            [pscustomobject]@{ Name = "umbrella'; Write-Output PWNED; '.msi"; Code = 'umbrella' }
        )
        $text = New-InstallScript -Kept $hostile -HasOrgInfo $false
        Get-ScriptParseErrorCount -Text $text | Should -Be 0
        # the payload survives only as inert literal text, never as a command
        $text | Should -Not -Match '(?m)^\s*Write-Output PWNED'
        $text | Should -Match ([regex]::Escape('$(Write-Output PWNED)'))
    }
}

Describe 'New-UninstallScript' {
    It 'removes the core VPN module last, under either DisplayName spelling' {
        $text = New-UninstallScript
        $optPos  = $text.IndexOf('-not (')
        $corePos = $text.LastIndexOf('Core VPN')
        $optPos  | Should -BeGreaterThan -1
        $corePos | Should -BeGreaterThan $optPos
        $text | Should -Match '\*Core VPN\*'
    }
    It 'resolves product codes from the uninstall registry, not Win32_Product' {
        $text = New-UninstallScript
        $text | Should -Match 'CurrentVersion\\Uninstall'
        $text | Should -Match 'WOW6432Node'
        $text | Should -Not -Match 'Win32_Product'
    }
    It 'uninstalls quietly by product code and checks the exit code' {
        $text = New-UninstallScript
        $text | Should -Match '/x \$\(\$e\.PSChildName\) /qn /norestart'
        $text | Should -Match '-PassThru'
        $text | Should -Match 'exit 3010'
    }
    It 'emits a script that parses' {
        Get-ScriptParseErrorCount -Text (New-UninstallScript) | Should -Be 0
    }
}

Describe 'New-DetectScript' {
    It 'requires the installed version to be at least the packaged one' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella'
        $text = New-DetectScript -Kept $kept -BundleVersion '5.1.16.194'
        $text | Should -Match ([regex]::Escape("'5.1.16.194'"))
        $text | Should -Match '\$installed -lt \$wanted'
        $text | Should -Match 'exit 1'
        $text | Should -Match 'exit 0'
    }
    It 'requires each kept optional module to be present' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella, dart'
        $text = New-DetectScript -Kept $kept -BundleVersion '5.1.16.194'
        $text | Should -Match '\*Umbrella\*'
        $text | Should -Match '\*Diagnostic\*'
    }
    It 'checks only the core client when nothing else is kept' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'vpn'
        $text = New-DetectScript -Kept $kept -BundleVersion '5.1.16.194'
        $text | Should -Not -Match 'modulePatterns'
    }
    It 'recognises the core client under either DisplayName spelling' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella'
        $text = New-DetectScript -Kept $kept -BundleVersion '5.1.16.194'
        $text | Should -Match '\*AnyConnect VPN\*'
        $text | Should -Match '\*Core VPN\*'
    }
    It 'tolerates a DisplayVersion carrying a suffix' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'vpn'
        $text = New-DetectScript -Kept $kept -BundleVersion '5.1.16.194'
        # 5.1.10.233-k9 must not defeat the comparison
        $text | Should -Match 'ConvertTo-ClientVersion'
        $text | Should -Match [regex]::Escape('^\d+(\.\d+){0,3}')
    }
    It 'compares against the highest installed core version, not the first entry' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'vpn'
        $text = New-DetectScript -Kept $kept -BundleVersion '5.1.16.194'
        $text | Should -Match 'Sort-Object -Descending'
    }
    It 'does not treat the core client as a pattern-matched module' {
        Get-ModuleDisplayNamePattern -Code 'vpn' | Should -BeNullOrEmpty
    }
    It 'emits a script that parses' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'all'
        Get-ScriptParseErrorCount -Text (New-DetectScript -Kept $kept -BundleVersion '5.1.16.194') | Should -Be 0
    }
}

Describe 'Expand-ArchiveSafely' {
    It 'extracts a well-formed archive' {
        $src = Join-Path $TestDrive 'src'
        New-Item -ItemType Directory -Path $src | Out-Null
        Set-Content -LiteralPath (Join-Path $src 'a.msi') -Value 'x'
        $zip = Join-Path $TestDrive 'good.zip'
        Compress-Archive -Path (Join-Path $src '*') -DestinationPath $zip
        $dest = Join-Path $TestDrive 'out-good'
        New-Item -ItemType Directory -Path $dest | Out-Null
        Expand-ArchiveSafely -Path $zip -Destination $dest
        Test-Path -LiteralPath (Join-Path $dest 'a.msi') | Should -BeTrue
    }
    It 'refuses an entry whose path escapes the destination' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = Join-Path $TestDrive 'evil.zip'
        $archive = [IO.Compression.ZipFile]::Open($zip, 'Create')
        try {
            $entry = $archive.CreateEntry('..\escaped.msi')
            $writer = New-Object IO.StreamWriter($entry.Open())
            $writer.Write('x'); $writer.Dispose()
        } finally { $archive.Dispose() }
        $dest = Join-Path $TestDrive 'out-evil'
        New-Item -ItemType Directory -Path $dest | Out-Null
        { Expand-ArchiveSafely -Path $zip -Destination $dest } |
            Should -Throw '*escapes the work directory*'
    }
}

Describe 'Test-OrgInfoFile' {
    It 'accepts a valid OrgInfo.json without warnings' {
        $p = Join-Path $TestDrive 'OrgInfo.json'
        Set-Content -LiteralPath $p -Value '{"organizationId":"1234567","fingerprint":"abc","userId":"7654321"}'
        Test-OrgInfoFile -Path $p -WarningVariable w 3>$null | Should -BeTrue
        @($w).Count | Should -Be 0
    }
    It 'throws on invalid JSON' {
        $p = Join-Path $TestDrive 'OrgInfo.json'
        Set-Content -LiteralPath $p -Value 'not json at all'
        { Test-OrgInfoFile -Path $p } | Should -Throw '*not valid JSON*'
    }
    It 'warns when expected keys are missing' {
        $p = Join-Path $TestDrive 'OrgInfo.json'
        Set-Content -LiteralPath $p -Value '{"organizationId":"1234567"}'
        Test-OrgInfoFile -Path $p -WarningVariable w 3>$null | Should -BeTrue
        @($w).Count | Should -Be 2
    }
    It 'throws when the file does not exist' {
        { Test-OrgInfoFile -Path (Join-Path $TestDrive 'missing.json') } |
            Should -Throw '*not found*'
    }
}
