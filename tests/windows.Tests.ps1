# Pester tests for secureclient-repack.ps1. The script is dot-sourced with
# SECURECLIENT_REPACK_TEST set, which exposes its functions without running
# the pipeline. No Cisco content is required — module lists are synthetic.

BeforeAll {
    $env:SECURECLIENT_REPACK_TEST = '1'
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'secureclient-repack.ps1')

    $script:SampleModules = @(
        [pscustomobject]@{ Name = 'client-win-core-vpn-predeploy-k9.msi';  Code = 'vpn' },
        [pscustomobject]@{ Name = 'client-win-umbrella-predeploy-k9.msi';  Code = 'umbrella' },
        [pscustomobject]@{ Name = 'client-win-dart-predeploy-k9.msi';      Code = 'dart' },
        [pscustomobject]@{ Name = 'client-win-nvm-predeploy-k9.msi';       Code = 'nvm' }
    )
}

AfterAll {
    Remove-Item Env:SECURECLIENT_REPACK_TEST -ErrorAction SilentlyContinue
}

Describe 'Get-ModuleCode' {
    It 'identifies the core VPN MSI' {
        Get-ModuleCode -Name 'client-win-5.1.0.136-core-vpn-predeploy-k9.msi' | Should -Be 'vpn'
    }
    It 'identifies optional modules' {
        Get-ModuleCode -Name 'client-win-5.1.0.136-umbrella-predeploy-k9.msi' | Should -Be 'umbrella'
        Get-ModuleCode -Name 'client-win-5.1.0.136-dart-predeploy-k9.msi' | Should -Be 'dart'
        Get-ModuleCode -Name 'client-win-5.1.0.136-nvm-predeploy-k9.msi' | Should -Be 'nvm'
        Get-ModuleCode -Name 'client-win-5.1.0.136-thousandeyes-predeploy-k9.msi' | Should -Be 'te'
    }
    It 'distinguishes ISE posture from plain posture' {
        Get-ModuleCode -Name 'client-win-5.1.0.136-iseposture-predeploy-k9.msi' | Should -Be 'ise'
        Get-ModuleCode -Name 'client-win-5.1.0.136-posture-predeploy-k9.msi' | Should -Be 'posture'
    }
    It 'falls back to mod for unknown MSIs' {
        Get-ModuleCode -Name 'client-win-5.1.0.136-mystery-predeploy-k9.msi' | Should -Be 'mod'
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
}

Describe 'New-UninstallScript' {
    It 'removes the core VPN module last' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'umbrella'
        $text = New-UninstallScript -Kept $kept
        $corePos = $text.IndexOf('core-vpn-predeploy')
        $umbPos  = $text.IndexOf('umbrella-predeploy')
        $umbPos  | Should -BeGreaterThan -1
        $corePos | Should -BeGreaterThan $umbPos
    }
    It 'uninstalls quietly via msiexec /x' {
        $kept = Select-KeptModule -Modules $script:SampleModules -KeepSpec 'dart'
        $text = New-UninstallScript -Kept $kept
        $text | Should -Match '/x \$\(\$app\.IdentifyingNumber\) /qn /norestart'
    }
}

Describe 'New-DetectScript' {
    It 'detects via the vpnagent binary or the uninstall registry entries' {
        $text = New-DetectScript
        $text | Should -Match 'vpnagent\.exe'
        $text | Should -Match 'CurrentVersion\\Uninstall'
        $text | Should -Match 'exit 0'
        $text | Should -Match 'exit 1'
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
