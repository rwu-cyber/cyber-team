#requires -Version 1

[CmdletBinding()]
param(
    [switch]$RWU,

    [ValidateSet('Harden', 'Lockdown', 'Isolate')]
    [string]$Mode = 'Lockdown',

    [switch]$Aggressive,

    [switch]$PreserveRDP,   
    [switch]$DisableRDP,    # Explicit opt-out from default RDP preservation.
    [switch]$PreserveWinRM,
    [switch]$PreserveSMB,
    [switch]$PreservePrinting,
    [switch]$PreserveDefenderExclusions,

    [string[]]$ManagementIP,

    [switch]$BlockUSBStorage,
    [switch]$DisableWindowsScriptHost,
    [switch]$EnableVBSMemoryIntegrity,
    [switch]$DisableLegacyTLS,

    [switch]$SkipQuickScan,
    [switch]$RunFullScan,
    [switch]$RunOfflineScan,

    [switch]$AirGap,
    [switch]$Reboot,

    [string]$OutputRoot = 'C:\ProgramData\EmergencyLockdown'
)

if (-not $RWU) {
    return
}

if ($DisableRDP -and $PreserveRDP) {
    throw 'Use either -DisableRDP or -PreserveRDP, not both.'
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'BiggerHarden must be run from an elevated PowerShell session when -RWU is used.'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FirewallGroup = 'EmergencyLockdown'
$script:Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:RunRoot = Join-Path $OutputRoot $script:Timestamp
$script:EvidenceRoot = Join-Path $script:RunRoot 'Evidence'
$script:TranscriptRoot = Join-Path $OutputRoot 'Transcripts'
$script:TranscriptPath = Join-Path $script:TranscriptRoot ("Lockdown-{0}.log" -f $script:Timestamp)
$script:FirewallBackup = Join-Path $script:EvidenceRoot 'Firewall-PreChange.wfw'
$script:TranscriptStarted = $false

function Write-Section {
    param([Parameter(Mandatory)][string]$Text)

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}

function Write-Ok {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[OK]   $Text" -ForegroundColor Green
}

function Write-Skip {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[SKIP] $Text" -ForegroundColor Yellow
}

function Write-WarnMessage {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[WARN] $Text" -ForegroundColor Yellow
}

function Write-Fail {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[FAIL] $Text" -ForegroundColor Red
}

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Ensure-RegistryKey {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Set-RegistryDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )

    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-RegistryString {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

function Remove-RegistryValueIfPresent {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    if (Test-Path -LiteralPath $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Safely {
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    try {
        & $Action
        Write-Ok $Description
        return $true
    }
    catch {
        Write-WarnMessage "$Description failed: $($_.Exception.Message)"
        return $false
    }
}

function Save-TextCommand {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][scriptblock]$Command
    )

    $path = Join-Path $script:EvidenceRoot $FileName
    try {
        & $Command 2>&1 | Out-File -FilePath $path -Encoding UTF8 -Width 4096
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath $path -Encoding UTF8
    }
}

function Export-CsvSafely {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][scriptblock]$Command
    )

    $path = Join-Path $script:EvidenceRoot $FileName
    try {
        $data = & $Command
        if ($null -ne $data) {
            $data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        }
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath ($path + '.error.txt') -Encoding UTF8
    }
}

function Stop-AndDisableService {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Reason = ''
    )

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction Stop
        }
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop

        if ($Reason) {
            Write-Ok "Disabled service $Name - $Reason"
        }
        else {
            Write-Ok "Disabled service $Name"
        }
    }
    catch {
        Write-Skip "Service '$Name' unavailable or could not be disabled."
    }
}

function Set-ServiceManualIfPresent {
    param([Parameter(Mandatory)][string]$Name)

    try {
        Set-Service -Name $Name -StartupType Manual -ErrorAction Stop
    }
    catch {
        # Optional service; intentionally quiet.
    }
}

function Disable-OptionalFeatureIfPresent {
    param([Parameter(Mandatory)][string]$FeatureName)

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
        if ($feature.State -ne 'Disabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop | Out-Null
            Write-Ok "Disabled optional feature: $FeatureName"
        }
        else {
            Write-Skip "Optional feature already disabled: $FeatureName"
        }
    }
    catch {
        Write-Skip "Optional feature '$FeatureName' is not present or cannot be managed on this OS."
    }
}

function Invoke-AuditPol {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & "$env:SystemRoot\System32\auditpol.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol.exe failed with exit code $LASTEXITCODE."
    }
}

function Set-EventLogMaximumSize {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][long]$Bytes
    )

    try {
        & "$env:SystemRoot\System32\wevtutil.exe" sl $LogName "/ms:$Bytes" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Event log '$LogName' maximum size set to $([math]::Round($Bytes / 1MB)) MB."
        }
    }
    catch {
        Write-Skip "Could not resize event log '$LogName'."
    }
}

function Export-EventLogSafely {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][string]$FileName
    )

    try {
        $path = Join-Path $script:EvidenceRoot $FileName
        & "$env:SystemRoot\System32\wevtutil.exe" epl $LogName $path /ow:true 2>$null
    }
    catch {
        # Some optional event channels do not exist on every Windows edition.
    }
}

function Set-MpPreferenceValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value
    )

    $cmd = Get-Command Set-MpPreference -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return
    }

    if (-not $cmd.Parameters.ContainsKey($Name)) {
        Write-Skip "Defender parameter '$Name' is not supported on this system."
        return
    }

    try {
        $params = @{ ErrorAction = 'Stop' }
        $params[$Name] = $Value
        Set-MpPreference @params
        Write-Ok "Defender: $Name = $Value"
    }
    catch {
        Write-WarnMessage "Defender '$Name' could not be set: $($_.Exception.Message)"
    }
}

function Configure-Defender {
    param(
        [Parameter(Mandatory)][bool]$IsServer,
        [Parameter(Mandatory)][bool]$UseZeroTolerance
    )

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Skip 'Microsoft Defender cmdlets are unavailable. Defender configuration skipped.'
        return
    }

    Write-Section 'Microsoft Defender Hardening'

    $cloudLevel = 'HighPlus'
    if ($UseZeroTolerance) {
        $cloudLevel = 'ZeroTolerance'
    }

    $settings = [ordered]@{
        DisableRealtimeMonitoring                    = $false
        DisableBehaviorMonitoring                    = $false
        DisableIOAVProtection                        = $false
        DisableScriptScanning                        = $false
        DisableRemovableDriveScanning                = $false
        DisableArchiveScanning                       = $false
        DisableEmailScanning                         = $false
        DisableBlockAtFirstSeen                      = $false
        MAPSReporting                                = 'Advanced'
        SubmitSamplesConsent                         = 'SendAllSamples'
        CloudBlockLevel                              = $cloudLevel
        CloudExtendedTimeout                         = 50
        PUAProtection                                = 1
        EnableNetworkProtection                      = 'Enabled'
        EnableControlledFolderAccess                 = 'Enabled'
        EnableFileHashComputation                    = $true
        CheckForSignaturesBeforeRunningScan          = $true
        SignatureDisableUpdateOnStartupWithoutEngine = $false
    }

    foreach ($entry in $settings.GetEnumerator()) {
        Set-MpPreferenceValue -Name $entry.Key -Value $entry.Value
    }

    if ($IsServer) {
        Set-MpPreferenceValue -Name 'AllowNetworkProtectionOnWinServer' -Value $true
        Set-MpPreferenceValue -Name 'AllowDatagramProcessingOnWinServer' -Value $false
    }
}

function Enable-ASRRules {
    param([Parameter(Mandatory)][bool]$ExchangeServer)

    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Skip 'ASR configuration skipped because Defender cmdlets are unavailable.'
        return
    }

    Write-Section 'Attack Surface Reduction Rules'

    $rules = [ordered]@{
        '56A863A9-875E-4185-98A7-B882C64B5CE5' = 'Block abuse of exploited vulnerable signed drivers'
        '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from LSASS'
        'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
        '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader from creating child processes'
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office applications from creating child processes'
        'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email client and webmail'
        '01443614-CD74-433A-B99E-2ECDC07BFC25' = 'Block low-prevalence or untrusted executable files'
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block execution of potentially obfuscated scripts'
        'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JavaScript or VBScript launching downloaded executables'
        '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office applications from creating executable content'
        '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office applications from injecting code into other processes'
        '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office communication apps from creating child processes'
        'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block process creation originating from PSExec and WMI'
        '33DDEDF1-C6E0-47CB-833E-DE6133960387' = 'Block rebooting machine in Safe Mode'
        'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted and unsigned processes running from USB'
        'C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB' = 'Block use of copied or impersonated system tools'
        '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
        'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Use advanced protection against ransomware'
    }

    if ($ExchangeServer) {
        $rules['A8F5898E-1DC8-49A9-9878-85004B8A61E6'] = 'Block Webshell creation for Exchange servers'
    }

    foreach ($rule in $rules.GetEnumerator()) {
        try {
            Add-MpPreference `
                -AttackSurfaceReductionRules_Ids $rule.Key `
                -AttackSurfaceReductionRules_Actions Enabled `
                -ErrorAction Stop
            Write-Ok "ASR: $($rule.Value)"
        }
        catch {
            Write-WarnMessage "ASR '$($rule.Value)' could not be enabled: $($_.Exception.Message)"
        }
    }
}

function Remove-DefenderExclusionsSafely {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        return
    }

    Write-Section 'Defender Exclusion Cleanup'

    $pref = Get-MpPreference

    $exclusionMap = [ordered]@{
        ExclusionExtension                   = 'ExclusionExtension'
        ExclusionIpAddress                   = 'ExclusionIpAddress'
        ExclusionPath                        = 'ExclusionPath'
        ExclusionProcess                     = 'ExclusionProcess'
        AttackSurfaceReductionOnlyExclusions = 'AttackSurfaceReductionOnlyExclusions'
    }

    foreach ($entry in $exclusionMap.GetEnumerator()) {
        $property = $pref.PSObject.Properties[$entry.Key]
        if (-not $property) {
            continue
        }

        foreach ($value in @($property.Value)) {
            if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
                continue
            }

            try {
                $removeArgs = @{ ErrorAction = 'Stop' }
                $removeArgs[$entry.Value] = $value
                Remove-MpPreference @removeArgs
                Write-Ok "Removed Defender $($entry.Key): $value"
            }
            catch {
                Write-WarnMessage "Could not remove Defender exclusion '$value': $($_.Exception.Message)"
            }
        }
    }
}

function Reset-EmergencyFirewallRules {
    try {
        Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    catch {
        # No previous EmergencyLockdown rules.
    }
}

function New-EmergencyFirewallRule {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][ValidateSet('Inbound', 'Outbound')][string]$Direction,
        [Parameter(Mandatory)][ValidateSet('Allow', 'Block')][string]$Action,
        [string]$Protocol = 'Any',
        [string[]]$LocalPort,
        [string[]]$RemotePort,
        [string[]]$RemoteAddress = @('Any')
    )

    $params = @{
        DisplayName   = $DisplayName
        Group         = $script:FirewallGroup
        Direction     = $Direction
        Action        = $Action
        Protocol      = $Protocol
        Profile       = 'Any'
        Enabled       = 'True'
        RemoteAddress = $RemoteAddress
    }

    if ($LocalPort) {
        $params['LocalPort'] = $LocalPort
    }

    if ($RemotePort) {
        $params['RemotePort'] = $RemotePort
    }

    New-NetFirewallRule @params -ErrorAction Stop | Out-Null
}

function Disable-InboundRulesForPort {
    param(
        [Parameter(Mandatory)][int[]]$Port,
        [Parameter(Mandatory)][ValidateSet('TCP', 'UDP')][string]$Protocol
    )

    $protocolNumbers = @{
        TCP = '6'
        UDP = '17'
    }

    $rules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue

    foreach ($rule in $rules) {
        try {
            $filters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
            foreach ($filter in $filters) {
                $filterProtocol = [string]$filter.Protocol
                if (($filterProtocol -ne $Protocol) -and ($filterProtocol -ne $protocolNumbers[$Protocol])) {
                    continue
                }

                foreach ($targetPort in $Port) {
                    if ([string]$filter.LocalPort -eq [string]$targetPort) {
                        Disable-NetFirewallRule -InputObject $rule -ErrorAction SilentlyContinue | Out-Null
                        break
                    }
                }
            }
        }
        catch {
            # Some firewall rules do not expose a port filter.
        }
    }
}

function Restrict-ManagementPort {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int[]]$Port,
        [Parameter(Mandatory)][ValidateSet('TCP', 'UDP')][string]$Protocol,
        [Parameter(Mandatory)][string[]]$AllowedIP
    )

    Disable-InboundRulesForPort -Port $Port -Protocol $Protocol

    New-EmergencyFirewallRule `
        -DisplayName "EmergencyLockdown-Allow-$Name-$Protocol" `
        -Direction Inbound `
        -Action Allow `
        -Protocol $Protocol `
        -LocalPort ($Port | ForEach-Object { [string]$_ }) `
        -RemoteAddress $AllowedIP

    Write-Ok "$Name restricted to management IP(s): $($AllowedIP -join ', ')"
}

function Configure-BaseFirewall {
    Write-Section 'Windows Firewall'

    Reset-EmergencyFirewallRules

    Set-NetFirewallProfile `
        -Profile Domain,Private,Public `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -AllowUnicastResponseToMulticast False `
        -LogBlocked True `
        -LogAllowed True `
        -LogMaxSizeKilobytes 32767 `
        -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'

    Write-Ok 'Firewall enabled on all profiles; inbound default=Block, outbound default=Allow.'
}

function Add-LockdownFirewallRules {
    param(
        [Parameter(Mandatory)][bool]$KeepRDP,
        [Parameter(Mandatory)][bool]$KeepWinRM,
        [Parameter(Mandatory)][bool]$KeepSMB
    )

    Write-Section 'Emergency Lateral-Movement Firewall Rules'

    # Discovery / name-resolution protocols commonly abused for poisoning or discovery.
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-LLMNR' -Direction Inbound -Action Block -Protocol UDP -LocalPort 5355
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-LLMNR' -Direction Outbound -Action Block -Protocol UDP -RemotePort 5355
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-mDNS' -Direction Inbound -Action Block -Protocol UDP -LocalPort 5353
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-mDNS' -Direction Outbound -Action Block -Protocol UDP -RemotePort 5353
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-SSDP' -Direction Inbound -Action Block -Protocol UDP -LocalPort 1900
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-SSDP' -Direction Outbound -Action Block -Protocol UDP -RemotePort 1900
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-WSD' -Direction Inbound -Action Block -Protocol UDP -LocalPort 3702
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-WSD' -Direction Outbound -Action Block -Protocol UDP -RemotePort 3702

    # RPC endpoint mapper.
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-RPC135' -Direction Inbound -Action Block -Protocol TCP -LocalPort 135

    # SSH/Telnet inbound and outbound lateral movement.
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-SSH' -Direction Inbound -Action Block -Protocol TCP -LocalPort 22
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-SSH' -Direction Outbound -Action Block -Protocol TCP -RemotePort 22
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-Telnet' -Direction Inbound -Action Block -Protocol TCP -LocalPort 23
    New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-Telnet' -Direction Outbound -Action Block -Protocol TCP -RemotePort 23

    if (-not $KeepRDP) {
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-RDP-TCP' -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-RDP-UDP' -Direction Inbound -Action Block -Protocol UDP -LocalPort 3389
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-RDP-TCP' -Direction Outbound -Action Block -Protocol TCP -RemotePort 3389
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-RDP-UDP' -Direction Outbound -Action Block -Protocol UDP -RemotePort 3389
    }

    if (-not $KeepWinRM) {
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-WinRM' -Direction Inbound -Action Block -Protocol TCP -LocalPort 5985,5986
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-WinRM' -Direction Outbound -Action Block -Protocol TCP -RemotePort 5985,5986
    }

    if (-not $KeepSMB) {
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-SMB' -Direction Inbound -Action Block -Protocol TCP -LocalPort 139,445
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-SMB' -Direction Outbound -Action Block -Protocol TCP -RemotePort 139,445
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-In-NetBIOS' -Direction Inbound -Action Block -Protocol UDP -LocalPort 137,138
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Block-Out-NetBIOS' -Direction Outbound -Action Block -Protocol UDP -RemotePort 137,138
    }

    Write-Ok 'Emergency inbound/outbound lateral-movement blocks installed.'
}

function Enable-FullNetworkIsolation {
    Write-Section 'FULL NETWORK ISOLATION'

    New-EmergencyFirewallRule `
        -DisplayName 'EmergencyLockdown-ISOLATE-Block-All-Inbound' `
        -Direction Inbound `
        -Action Block `
        -Protocol Any

    New-EmergencyFirewallRule `
        -DisplayName 'EmergencyLockdown-ISOLATE-Block-All-Outbound' `
        -Direction Outbound `
        -Action Block `
        -Protocol Any

    Write-WarnMessage 'ALL inbound and outbound network traffic is now blocked by Windows Firewall.'
}

function Disable-NetBIOS {
    Write-Section 'Legacy Name Resolution'

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name 'EnableMulticast' `
        -Value 0

    Write-Ok 'LLMNR disabled by policy.'

    try {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'
        foreach ($adapter in $adapters) {
            try {
                Invoke-CimMethod `
                    -InputObject $adapter `
                    -MethodName SetTcpipNetbios `
                    -Arguments @{ TcpipNetbiosOptions = 2 } `
                    -ErrorAction Stop | Out-Null
            }
            catch {
                Write-WarnMessage "NetBIOS could not be disabled on adapter '$($adapter.Description)'."
            }
        }
        Write-Ok 'NetBIOS over TCP/IP disabled on IP-enabled adapters.'
    }
    catch {
        Write-WarnMessage 'Unable to enumerate adapters for NetBIOS hardening.'
    }
}

function Configure-SMB {
    param(
        [Parameter(Mandatory)][bool]$KeepSMB,
        [Parameter(Mandatory)][bool]$IsServer
    )

    Write-Section 'SMB Hardening'

    Disable-OptionalFeatureIfPresent -FeatureName 'SMB1Protocol'
    Disable-OptionalFeatureIfPresent -FeatureName 'SMB1Protocol-Client'
    Disable-OptionalFeatureIfPresent -FeatureName 'SMB1Protocol-Server'

    if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        try {
            Set-SmbClientConfiguration `
                -RequireSecuritySignature $true `
                -EnableInsecureGuestLogons $false `
                -Confirm:$false `
                -ErrorAction Stop
            Write-Ok 'SMB client signing required and insecure guest logons disabled.'
        }
        catch {
            Write-WarnMessage "SMB client hardening failed: $($_.Exception.Message)"
        }
    }

    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        try {
            $smbServerCmd = Get-Command Set-SmbServerConfiguration
            $params = @{
                RequireSecuritySignature = $true
                EnableSecuritySignature  = $true
                EnableSMB1Protocol       = $false
                Confirm                  = $false
                ErrorAction              = 'Stop'
            }

            if ($KeepSMB -and ($Mode -ne 'Harden') -and $smbServerCmd.Parameters.ContainsKey('EncryptData')) {
                $params['EncryptData'] = $true
            }

            if ($smbServerCmd.Parameters.ContainsKey('RejectUnencryptedAccess')) {
                $params['RejectUnencryptedAccess'] = $true
            }

            Set-SmbServerConfiguration @params
            Write-Ok 'SMB server signing enabled; SMB1 disabled.'
        }
        catch {
            Write-WarnMessage "SMB server hardening failed: $($_.Exception.Message)"
        }
    }

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'RestrictNullSessAccess' `
        -Value 1

    if (-not $KeepSMB) {
        Set-RegistryDword `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
            -Name 'AutoShareWks' `
            -Value 0

        if ($IsServer) {
            Set-RegistryDword `
                -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                -Name 'AutoShareServer' `
                -Value 0
        }
    }
}

function Configure-RDPAccess {
    param([Parameter(Mandatory)][bool]$KeepRDP)

    Write-Section 'RDP Availability and Session Protection'

    $rdpSystem = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $rdpPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    if (-not $KeepRDP) {
        Set-RegistryDword -Path $rdpSystem -Name 'fDenyTSConnections' -Value 1
        Stop-AndDisableService -Name 'TermService' -Reason 'Remote Desktop (explicit -DisableRDP)'
        Write-WarnMessage 'RDP explicitly disabled; no inbound RDP allow rules are created.'
        return
    }

    # Keep the listener enabled; require NLA and encrypted transport.
    Set-RegistryDword -Path $rdpSystem -Name 'fDenyTSConnections' -Value 0
    Set-RegistryDword -Path $rdpTcp -Name 'UserAuthentication' -Value 1
    Set-RegistryDword -Path $rdpTcp -Name 'SecurityLayer' -Value 2
    Set-RegistryDword -Path $rdpTcp -Name 'MinEncryptionLevel' -Value 3
    Set-RegistryDword -Path $rdpSystem -Name 'fDisableCdm' -Value 1
    Set-RegistryDword -Path $rdpSystem -Name 'fDisableClip' -Value 1

    # Standard Microsoft RDS policy: allow at most one simultaneous RDP
    # connection, and at most one RDP session per user. The connection limit
    # is chiefly intended for RD Session Host; verify on each target OS.
    Set-RegistryDword -Path $rdpPolicy -Name 'MaxInstanceCount' -Value 1
    Set-RegistryDword -Path $rdpPolicy -Name 'fSingleSessionPerUser' -Value 1

    # Disable remote session shadowing. This is not an administrator-proof
    # disconnect/logoff restriction; local/Domain Admins can still intervene.
    Set-RegistryDword -Path $rdpPolicy -Name 'Shadow' -Value 0

    # Do not impose idle, active or disconnected session time limits. Note:
    # domain GPO may supersede these values on managed systems.
    Set-RegistryDword -Path $rdpPolicy -Name 'MaxIdleTime' -Value 0
    Set-RegistryDword -Path $rdpPolicy -Name 'MaxConnectionTime' -Value 0
    Set-RegistryDword -Path $rdpPolicy -Name 'MaxDisconnectionTime' -Value 0
    Set-RegistryDword -Path $rdpPolicy -Name 'fResetBroken' -Value 0

    try {
        Set-Service -Name TermService -StartupType Automatic -ErrorAction Stop
        Start-Service -Name TermService -ErrorAction Stop
        Write-Ok 'RDP service enabled with NLA, TLS and high encryption.'
    }
    catch {
        Write-WarnMessage "RDP service could not be started: $($_.Exception.Message)"
    }

    $rdpPort = 3389
    try {
        $configuredPort = (Get-ItemProperty -LiteralPath $rdpTcp -Name PortNumber -ErrorAction Stop).PortNumber
        if ($configuredPort -ge 1 -and $configuredPort -le 65535) {
            $rdpPort = [int]$configuredPort
        }
    }
    catch {
        Write-WarnMessage 'Could not read the configured RDP listener port; assuming 3389.'
    }

    # The baseline firewall blocks inbound by default. Create explicit
    # allows for RDP even if the old built-in rules are disabled. A provided
    # -ManagementIP scopes both protocols and disables competing broad rules.
    if ($ManagementIP -and $ManagementIP.Count -gt 0) {
        Restrict-ManagementPort -Name 'RDP' -Port $rdpPort -Protocol TCP -AllowedIP $ManagementIP
        Restrict-ManagementPort -Name 'RDP' -Port $rdpPort -Protocol UDP -AllowedIP $ManagementIP
    }
    else {
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Allow-RDP-TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort @([string]$rdpPort)
        New-EmergencyFirewallRule -DisplayName 'EmergencyLockdown-Allow-RDP-UDP' -Direction Inbound -Action Allow -Protocol UDP -LocalPort @([string]$rdpPort)
        Write-WarnMessage "RDP TCP/UDP $rdpPort allowed from any source. Use -ManagementIP to restrict access."
    }

    Write-Ok 'RDP policy: one simultaneous connection, one session per user, shadowing disabled, no RDS session timeouts.'
    Write-WarnMessage 'Domain-Admin-only takeover is NOT guaranteed: local administrators and users reconnecting with the same credentials may displace a session.'
    Write-WarnMessage 'Domain GPO, RDS role/edition, and existing firewall BLOCK rules can supersede local settings.'
}

function Configure-RemoteAccess {
    param(
        [Parameter(Mandatory)][bool]$KeepWinRM,
        [Parameter(Mandatory)][bool]$KeepSMB,
        [Parameter(Mandatory)][bool]$KeepPrinting
    )

    Write-Section 'Remote Access and High-Risk Services'

    Stop-AndDisableService -Name 'RemoteRegistry' -Reason 'remote registry modification'
    Stop-AndDisableService -Name 'SSDPSRV' -Reason 'SSDP discovery'
    Stop-AndDisableService -Name 'upnphost' -Reason 'UPnP device hosting'
    Stop-AndDisableService -Name 'WebClient' -Reason 'WebDAV client'
    Stop-AndDisableService -Name 'WMPNetworkSvc' -Reason 'media network sharing'
    Stop-AndDisableService -Name 'icssvc' -Reason 'mobile hotspot / connection sharing'

    if ($Mode -ne 'Harden') {
        Stop-AndDisableService -Name 'lmhosts' -Reason 'NetBIOS helper'
    }

    # Disable Remote Assistance regardless of RDP state.
    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
        -Name 'fAllowToGetHelp' `
        -Value 0

    if ($KeepWinRM) {
        try {
            Set-Service -Name WinRM -StartupType Automatic
            Start-Service -Name WinRM -ErrorAction Stop
            Write-Ok 'WinRM preserved.'

            if ($ManagementIP -and $ManagementIP.Count -gt 0) {
                Restrict-ManagementPort -Name 'WinRM' -Port 5985,5986 -Protocol TCP -AllowedIP $ManagementIP
            }
            else {
                Write-WarnMessage 'WinRM preserved without -ManagementIP; existing WinRM firewall scope remains broader.'
            }
        }
        catch {
            Write-WarnMessage "WinRM could not be preserved: $($_.Exception.Message)"
        }
    }
    else {
        try {
            Disable-PSRemoting -Force -ErrorAction SilentlyContinue
        }
        catch {
            # Continue with direct service shutdown.
        }
        Stop-AndDisableService -Name 'WinRM' -Reason 'PowerShell remoting / WS-Man'
    }

    if (-not $KeepSMB) {
        Stop-AndDisableService -Name 'LanmanServer' -Reason 'inbound SMB/file sharing'
    }
    elseif ($ManagementIP -and $ManagementIP.Count -gt 0) {
        Restrict-ManagementPort -Name 'SMB' -Port 139,445 -Protocol TCP -AllowedIP $ManagementIP
        Restrict-ManagementPort -Name 'NetBIOS' -Port 137,138 -Protocol UDP -AllowedIP $ManagementIP
    }

    if (-not $KeepPrinting) {
        Stop-AndDisableService -Name 'Spooler' -Reason 'print spooler attack surface'
    }
}

function Configure-CredentialSecurity {
    param([Parameter(Mandatory)][bool]$IsDC)

    Write-Section 'Credential and Authentication Hardening'

    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLmHash' -Value 1
    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5
    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1
    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1
    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1
    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0
    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0
    Set-RegistryDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 0
    Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1
    Set-RegistryDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' -Name 'AuditLevel' -Value 8

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
        -Name 'AlwaysInstallElevated' `
        -Value 0

    Set-RegistryDword `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
        -Name 'AlwaysInstallElevated' `
        -Value 0

    # Disable built-in Guest account by SID suffix to avoid localization issues.
    try {
        $guest = Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' |
            Where-Object { $_.SID -match '-501$' } |
            Select-Object -First 1

        if ($guest) {
            if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) {
                Disable-LocalUser -Name $guest.Name -ErrorAction Stop
            }
            else {
                & net.exe user $guest.Name /active:no | Out-Null
            }
            Write-Ok 'Built-in Guest account disabled.'
        }
    }
    catch {
        Write-WarnMessage 'Unable to disable built-in Guest account.'
    }

    if ($IsDC) {
        Set-RegistryDword `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
            -Name 'FullSecureChannelProtection' `
            -Value 1
    }

    Write-Ok 'LM/NTLM compatibility, WDigest, LSA protection, anonymous access, and elevation policies hardened.'
}

function Configure-UACAndAutorun {
    Write-Section 'UAC, AutoRun, and Local Elevation'

    $uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegistryDword -Path $uac -Name 'EnableLUA' -Value 1
    Set-RegistryDword -Path $uac -Name 'ConsentPromptBehaviorAdmin' -Value 2
    Set-RegistryDword -Path $uac -Name 'ConsentPromptBehaviorUser' -Value 0
    Set-RegistryDword -Path $uac -Name 'PromptOnSecureDesktop' -Value 1
    Set-RegistryDword -Path $uac -Name 'EnableInstallerDetection' -Value 1

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoAutorun' `
        -Value 1

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoDriveTypeAutoRun' `
        -Value 255

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name 'SafeDllSearchMode' `
        -Value 1

    Write-Ok 'UAC, AutoRun, and DLL search order protections applied.'
}

function Configure-NetworkStack {
    Write-Section 'Network Stack Hardening'

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
        -Name 'DisableIPSourceRouting' `
        -Value 2

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
        -Name 'DisableIPSourceRouting' `
        -Value 2

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
        -Name 'EnableICMPRedirect' `
        -Value 0

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' `
        -Name 'NoNameReleaseOnDemand' `
        -Value 1

    Write-Ok 'IP source routing, ICMP redirect acceptance, and NetBIOS name-release behavior hardened.'
}

function Configure-PowerShellLogging {
    Write-Section 'PowerShell and Process Auditing'

    $scriptBlock = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $moduleLogging = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $moduleNames = Join-Path $moduleLogging 'ModuleNames'
    $transcription = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'

    Set-RegistryDword -Path $scriptBlock -Name 'EnableScriptBlockLogging' -Value 1
    Set-RegistryDword -Path $moduleLogging -Name 'EnableModuleLogging' -Value 1
    Set-RegistryString -Path $moduleNames -Name '*' -Value '*'
    Set-RegistryDword -Path $transcription -Name 'EnableTranscripting' -Value 1
    Set-RegistryDword -Path $transcription -Name 'EnableInvocationHeader' -Value 1
    Set-RegistryString -Path $transcription -Name 'OutputDirectory' -Value $script:TranscriptRoot

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' `
        -Value 1

    try {
        Invoke-AuditPol -Arguments @('/set', '/category:*', '/success:enable', '/failure:enable')
        Write-Ok 'Advanced audit policy enabled for success and failure events.'
    }
    catch {
        Write-WarnMessage "Advanced audit policy configuration failed: $($_.Exception.Message)"
    }

    Set-EventLogMaximumSize -LogName 'Security' -Bytes 268435456
    Set-EventLogMaximumSize -LogName 'System' -Bytes 134217728
    Set-EventLogMaximumSize -LogName 'Application' -Bytes 134217728
    Set-EventLogMaximumSize -LogName 'Microsoft-Windows-PowerShell/Operational' -Bytes 134217728
    Set-EventLogMaximumSize -LogName 'Microsoft-Windows-Windows Defender/Operational' -Bytes 134217728

    Write-Ok 'PowerShell script block/module/transcription logging and process command-line auditing enabled.'
}

function Remove-AccessibilityIFEOHijacks {
    Write-Section 'Accessibility Backdoor Checks'

    $executables = @(
        'sethc.exe',
        'Utilman.exe',
        'osk.exe',
        'Narrator.exe',
        'Magnify.exe'
    )

    foreach ($exe in $executables) {
        $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"

        if (-not (Test-Path -LiteralPath $ifeo)) {
            continue
        }

        try {
            $properties = Get-ItemProperty -LiteralPath $ifeo -ErrorAction Stop
            $debuggerProperty = $properties.PSObject.Properties['Debugger']

            if ($debuggerProperty -and $debuggerProperty.Value) {
                $oldValue = [string]$debuggerProperty.Value
                Remove-ItemProperty -LiteralPath $ifeo -Name 'Debugger' -Force -ErrorAction Stop
                Write-Ok "Removed IFEO Debugger hijack from $exe (was: $oldValue)"
            }
        }
        catch {
            Write-WarnMessage "Unable to inspect IFEO entry for $exe."
        }
    }
}

function Configure-PrintNightmareMitigations {
    Write-Section 'PrintNightmare / Printer Driver Hardening'

    Set-RegistryDword `
        -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' `
        -Name 'RegisterSpoolerRemoteRpcEndPoint' `
        -Value 2

    $pointAndPrint = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    Ensure-RegistryKey $pointAndPrint
    Remove-RegistryValueIfPresent -Path $pointAndPrint -Name 'NoWarningNoElevationOnInstall'
    Remove-RegistryValueIfPresent -Path $pointAndPrint -Name 'UpdatePromptSettings'
    Set-RegistryDword -Path $pointAndPrint -Name 'RestrictDriverInstallationToAdministrators' -Value 1

    Write-Ok 'Printer driver installation restricted to administrators.'
}

function Configure-LDAP {
    param([Parameter(Mandatory)][bool]$IsDC)

    Write-Section 'LDAP and Netlogon Hardening'

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' `
        -Name 'LDAPClientIntegrity' `
        -Value 2

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
        -Name 'FullSecureChannelProtection' `
        -Value 1

    if ($IsDC) {
        Set-RegistryDword `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LDAPServerIntegrity' `
            -Value 2

        Remove-RegistryValueIfPresent `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
            -Name 'vulnerablechannelallowlist'

        Write-Ok 'LDAP client/server signing and Netlogon secure channel protections applied.'
    }
    else {
        Write-Ok 'LDAP client signing and Netlogon secure channel protections applied.'
    }
}

function Configure-TLSHardening {
    Write-Section 'Legacy TLS / SCHANNEL Hardening'

    $disabledProtocols = @('SSL 0', 'SSL 0', 'TLS 0', 'TLS 1')

    foreach ($protocol in $disabledProtocols) {
        foreach ($role in @('Client', 'Server')) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$role"
            Set-RegistryDword -Path $path -Name 'Enabled' -Value 0
            Set-RegistryDword -Path $path -Name 'DisabledByDefault' -Value 1
        }
    }

    foreach ($role in @('Client', 'Server')) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 2\$role"
        Set-RegistryDword -Path $path -Name 'Enabled' -Value 1
        Set-RegistryDword -Path $path -Name 'DisabledByDefault' -Value 0
    }

    foreach ($frameworkPath in @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v0.30319',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v0.30319'
    )) {
        Set-RegistryDword -Path $frameworkPath -Name 'SchUseStrongCrypto' -Value 1
        Set-RegistryDword -Path $frameworkPath -Name 'SystemDefaultTlsVersions' -Value 1
    }

    Write-WarnMessage 'Legacy SSL/TLS protocols disabled. Legacy applications may stop connecting until updated.'
}

function Configure-WindowsScriptHost {
    Write-Section 'Windows Script Host'

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' `
        -Name 'Enabled' `
        -Value 0

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings' `
        -Name 'Enabled' `
        -Value 0

    Write-WarnMessage 'Windows Script Host disabled. VBS/JScript logon or administration scripts will no longer run.'
}

function Configure-USBStorageBlock {
    Write-Section 'USB Mass Storage Lockdown'

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' `
        -Name 'Start' `
        -Value 4

    Set-RegistryDword `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' `
        -Name 'Deny_All' `
        -Value 1

    Write-WarnMessage 'USB mass storage and removable-storage access disabled. USB keyboards/mice are not USBSTOR devices.'
}

function Configure-VBSAndMemoryIntegrity {
    param([Parameter(Mandatory)][bool]$IsDC)

    Write-Section 'VBS / Credential Guard / Memory Integrity'

    if ($IsDC) {
        Write-Skip 'Credential Guard/VBS automatic enablement skipped on a Domain Controller.'
        return
    }

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
        -Name 'EnableVirtualizationBasedSecurity' `
        -Value 1

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
        -Name 'RequirePlatformSecurityFeatures' `
        -Value 1

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
        -Name 'Locked' `
        -Value 0

    Set-RegistryDword `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'LsaCfgFlags' `
        -Value 2

    $hvci = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    Set-RegistryDword -Path $hvci -Name 'Enabled' -Value 1
    Set-RegistryDword -Path $hvci -Name 'Locked' -Value 0

    Write-WarnMessage 'VBS, Credential Guard, and Memory Integrity requested. Reboot required; incompatible drivers can cause failures.'
}

function Write-RecoveryInstructions {
    $recoveryPath = Join-Path $script:RunRoot 'NETWORK-RECOVERY.txt'

    @"
EMERGENCY WINDOWS LOCKDOWN - NETWORK RECOVERY

Run these commands LOCALLY from an elevated Windows PowerShell console.

 Remove only the firewall rules created by this script:

   Get-NetFirewallRule -Group '$script:FirewallGroup' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

 If -AirGap was used, re-enable physical adapters:

   Get-NetAdapter -Physical | Enable-NetAdapter -Confirm:`$false

 To restore the entire PRE-CHANGE Windows Firewall configuration instead:

   netsh advfirewall import "$script:FirewallBackup"

IMPORTANT:
- These commands restore network/firewall access only.
- RDP pre-change registry exports are in Evidence: rdp-session-policies-before.reg
  and rdp-listener-before.reg. Review any proposed restore carefully: importing
  them overwrites entire registry keys, not only changes made by this script.
- Services, Defender settings, registry policies, ASR rules, SMB settings,
  VBS/HVCI, TLS hardening, USB restrictions, and Windows Script Host changes
  remain hardened until manually reverted or restored from management policy.
- The pre-change evidence bundle is stored at:
  $script:EvidenceRoot
"@ | Out-File -FilePath $recoveryPath -Encoding UTF8 -Force

    Write-Ok "Network recovery instructions written to $recoveryPath"
}

function Capture-Evidence {
    Write-Section 'Pre-Change Incident / Evidence Capture'

    Ensure-Directory $script:EvidenceRoot

    Save-TextCommand -FileName 'systeminfo.txt' -Command { systeminfo.exe }
    Save-TextCommand -FileName 'whoami-all.txt' -Command { whoami.exe /all }
    Save-TextCommand -FileName 'ipconfig-all.txt' -Command { ipconfig.exe /all }
    Save-TextCommand -FileName 'route-print.txt' -Command { route.exe print }
    Save-TextCommand -FileName 'arp.txt' -Command { arp.exe -a }
    Save-TextCommand -FileName 'netstat-ano.txt' -Command { netstat.exe -ano }
    Save-TextCommand -FileName 'tasklist-svc.txt' -Command { tasklist.exe /svc }
    Save-TextCommand -FileName 'driverquery.txt' -Command { driverquery.exe /v }
    Save-TextCommand -FileName 'audit-policy.txt' -Command { auditpol.exe /get /category:* }
    Save-TextCommand -FileName 'environment.txt' -Command { Get-ChildItem Env: | Sort-Object Name }

    Export-CsvSafely -FileName 'processes.csv' -Command {
        Get-CimInstance Win32_Process |
            Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine,
                CreationDate
    }

    Export-CsvSafely -FileName 'services.csv' -Command {
        Get-CimInstance Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    }

    Export-CsvSafely -FileName 'startup-commands.csv' -Command {
        Get-CimInstance Win32_StartupCommand |
            Select-Object Name, Command, Location, User
    }

    Export-CsvSafely -FileName 'tcp-connections.csv' -Command {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            Get-NetTCPConnection |
                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        }
    }

    Export-CsvSafely -FileName 'udp-endpoints.csv' -Command {
        if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
            Get-NetUDPEndpoint |
                Select-Object LocalAddress, LocalPort, OwningProcess
        }
    }

    Export-CsvSafely -FileName 'scheduled-tasks.csv' -Command {
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            Get-ScheduledTask |
                Select-Object TaskPath, TaskName, State, Author, Description
        }
    }

    Export-CsvSafely -FileName 'firewall-rules.csv' -Command {
        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
            Get-NetFirewallRule |
                Select-Object DisplayName, Name, Enabled, Direction, Action, Profile, PolicyStoreSource
        }
    }

    Save-TextCommand -FileName 'firewall-profiles.txt' -Command {
        Get-NetFirewallProfile | Format-List *
    }

    # Keep pre-change RDP configuration to support manual recovery.
    foreach ($entry in @(
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; File = 'rdp-session-policies-before.reg' },
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'; File = 'rdp-listener-before.reg' }
    )) {
        try {
            $rdpBackup = Join-Path $script:EvidenceRoot $entry.File
            & reg.exe export $entry.Key $rdpBackup /y 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Registry export returned a nonzero exit code.'
            }
        }
        catch {
            Write-WarnMessage "Could not export pre-change RDP settings ($($entry.Key))."
        }
    }

    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Export-CsvSafely -FileName 'local-users.csv' -Command {
            Get-LocalUser |
                Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires,
                    UserMayChangePassword, SID
        }
    }

    if (Get-Command Get-HotFix -ErrorAction SilentlyContinue) {
        Export-CsvSafely -FileName 'hotfixes.csv' -Command {
            Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn
        }
    }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Save-TextCommand -FileName 'defender-status.txt' -Command {
            Get-MpComputerStatus | Format-List *
        }

        Save-TextCommand -FileName 'defender-preferences.txt' -Command {
            Get-MpPreference | Format-List *
        }

        Save-TextCommand -FileName 'defender-threats.txt' -Command {
            Get-MpThreat | Format-List *
            Get-MpThreatDetection | Format-List *
        }
    }

    if (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        Save-TextCommand -FileName 'smb-client.txt' -Command {
            Get-SmbClientConfiguration | Format-List *
        }
    }

    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Save-TextCommand -FileName 'smb-server.txt' -Command {
            Get-SmbServerConfiguration | Format-List *
        }
    }

    try {
        & netsh.exe advfirewall export $script:FirewallBackup | Out-Null
        Write-Ok "Firewall configuration backed up to $script:FirewallBackup"
    }
    catch {
        Write-WarnMessage 'Could not export pre-change firewall configuration.'
    }

    Export-EventLogSafely -LogName 'Security' -FileName 'Security.evtx'
    Export-EventLogSafely -LogName 'System' -FileName 'System.evtx'
    Export-EventLogSafely -LogName 'Application' -FileName 'Application.evtx'
    Export-EventLogSafely -LogName 'Microsoft-Windows-PowerShell/Operational' -FileName 'PowerShell-Operational.evtx'
    Export-EventLogSafely -LogName 'Microsoft-Windows-Windows Defender/Operational' -FileName 'Defender-Operational.evtx'
    Export-EventLogSafely -LogName 'Microsoft-Windows-SMBClient/Security' -FileName 'SMBClient-Security.evtx'

    Write-Ok "Pre-change evidence captured under $script:EvidenceRoot"
}

function Run-DefenderScans {
    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
        return
    }

    Write-Section 'Defender Scan'

    if (-not $SkipQuickScan) {
        try {
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
            Write-Ok 'Defender quick scan completed.'
        }
        catch {
            Write-WarnMessage "Defender quick scan failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Skip 'Quick scan skipped by request.'
    }

    if ($RunFullScan) {
        try {
            Start-MpScan -ScanType FullScan -ErrorAction Stop
            Write-Ok 'Defender full scan completed.'
        }
        catch {
            Write-WarnMessage "Defender full scan failed: $($_.Exception.Message)"
        }
    }
}

function Disable-NetworkAdaptersForAirGap {
    Write-Section 'Physical-Style Air Gap'

    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object { $_.Status -ne 'Disabled' }

        foreach ($adapter in $adapters) {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            Write-Ok "Disabled physical network adapter: $($adapter.Name)"
        }

        Write-WarnMessage 'Physical network adapters disabled. Re-enable locally with Enable-NetAdapter.'
    }
    catch {
        Write-WarnMessage "Could not disable one or more physical network adapters: $($_.Exception.Message)"
    }
}

function Show-Verification {
    Write-Section 'Verification'

    try {
        Write-Host ''
        Write-Host 'Firewall profiles:' -ForegroundColor Cyan
        Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked |
            Format-Table -AutoSize
    }
    catch {
        Write-WarnMessage 'Unable to display firewall profile verification.'
    }

    try {
        Write-Host ''
        Write-Host 'Emergency firewall rules:' -ForegroundColor Cyan
        Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue |
            Select-Object DisplayName, Direction, Action, Enabled |
            Format-Table -AutoSize
    }
    catch {
        # Optional.
    }

    try {
        Write-Host ''
        Write-Host 'RDP session policies:' -ForegroundColor Cyan
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' |
            Select-Object MaxInstanceCount, fSingleSessionPerUser, Shadow,
                MaxIdleTime, MaxConnectionTime, MaxDisconnectionTime |
            Format-List
        $rdpPort = 3389
        $listenerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $portValue = (Get-ItemProperty -LiteralPath $listenerKey -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
        if ($portValue -ge 1 -and $portValue -le 65535) { $rdpPort = [int]$portValue }
        Write-Host "RDP listener TCP status (port $rdpPort):" -ForegroundColor Cyan
        Get-NetTCPConnection -LocalPort $rdpPort -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, State | Format-Table -AutoSize
    }
    catch {
        Write-WarnMessage 'Unable to verify one or more RDP policy settings.'
    }

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            Write-Host ''
            Write-Host 'Defender status:' -ForegroundColor Cyan
            Get-MpComputerStatus |
                Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                    IoavProtectionEnabled, AntispywareEnabled, NISEnabled |
                Format-List

            Write-Host 'Defender critical preferences:' -ForegroundColor Cyan
            Get-MpPreference |
                Select-Object MAPSReporting, SubmitSamplesConsent, CloudBlockLevel,
                    EnableNetworkProtection, EnableControlledFolderAccess, PUAProtection |
                Format-List
        }
        catch {
            Write-WarnMessage 'Unable to display Defender verification.'
        }
    }

    try {
        Write-Host ''
        Write-Host 'High-risk services:' -ForegroundColor Cyan
        Get-Service -Name WinRM,RemoteRegistry,TermService,LanmanServer,Spooler,WebClient,SSDPSRV,upnphost `
            -ErrorAction SilentlyContinue |
            Select-Object Name, Status, StartType |
            Format-Table -AutoSize
    }
    catch {
        # Optional.
    }

    try {
        Write-Host ''
        Write-Host 'Listening TCP ports:' -ForegroundColor Cyan
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Sort-Object LocalPort |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Format-Table -AutoSize
    }
    catch {
        # Optional.
    }
}

Ensure-Directory $OutputRoot
Ensure-Directory $script:RunRoot
Ensure-Directory $script:EvidenceRoot
Ensure-Directory $script:TranscriptRoot

try {
    Start-Transcript -Path $script:TranscriptPath -Force | Out-Null
    $script:TranscriptStarted = $true
}
catch {
    Write-WarnMessage 'PowerShell transcript could not be started.'
}

try {
    Write-Section 'Emergency Windows Lockdown'

    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $isDC = ($os.ProductType -eq 2)
    $isServer = ($os.ProductType -ne 1)

    $exchangeServer = $false
    try {
        if (Get-Service -Name 'MSExchangeServiceHost' -ErrorAction SilentlyContinue) {
            $exchangeServer = $true
        }
    }
    catch {
        $exchangeServer = $false
    }

    $effectiveAggressive = [bool]$Aggressive
    $effectiveBlockUSB = [bool]($BlockUSBStorage -or $effectiveAggressive)
    $effectiveDisableWSH = [bool]($DisableWindowsScriptHost -or $effectiveAggressive)
    $effectiveEnableVBS = [bool]($EnableVBSMemoryIntegrity -or $effectiveAggressive)
    $effectiveDisableTLS = [bool]($DisableLegacyTLS -or $effectiveAggressive)

    $effectivePreserveRDP = -not [bool]$DisableRDP
    $effectivePreserveSMB = [bool]$PreserveSMB

    # Avoid automatically disabling the Server service on server OS editions unless
    # the operator explicitly requests SMB shutdown through Aggressive mode.
    if ($isServer -and -not $effectiveAggressive -and -not $PreserveSMB) {
        $effectivePreserveSMB = $true
        Write-WarnMessage 'Windows Server detected: SMB service is preserved unless -Aggressive is used.'
    }

    # Domain Controllers require SMB/SYSVOL/NETLOGON for normal AD operation.
    if ($isDC -and -not $PreserveSMB) {
        $effectivePreserveSMB = $true
        Write-WarnMessage 'Domain Controller detected: SMB service preserved to avoid automatically destroying AD service availability.'
    }

    Write-Host "Mode       : $Mode"
    Write-Host "Aggressive : $effectiveAggressive"
    Write-Host "PreserveRDP: $effectivePreserveRDP (default True)"
    Write-Host "Computer   : $env:COMPUTERNAME"
    Write-Host "OS         : $($os.Caption) $($os.Version)"
    Write-Host "Domain     : $($computer.Domain)"
    Write-Host "Server     : $isServer"
    Write-Host "DC         : $isDC"
    Write-Host "Evidence   : $script:EvidenceRoot"

    if ($Mode -eq 'Isolate') {
        Write-WarnMessage 'ISOLATE blocks ALL network traffic including RDP even while the RDP service remains configured.'
    }
    if ($AirGap) {
        Write-WarnMessage 'AirGap disables physical network adapters, preventing RDP access.'
    }

    # Preserve incident evidence BEFORE modifying system state.
    Capture-Evidence
    Write-RecoveryInstructions

    # Refresh Defender intelligence while network connectivity still exists.
    Write-Section 'Defender Intelligence Update'
    if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
        try {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop
            Write-Ok 'Microsoft Defender security intelligence updated.'
        }
        catch {
            Write-WarnMessage "Defender security intelligence update failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Skip 'Defender signature-update cmdlet unavailable.'
    }

    # Baseline firewall before service changes.
    Configure-BaseFirewall

    # Restore/preserve RDP promptly after changing firewall defaults, rather
    # than waiting until the later security scans and service lockdown steps.
    # Isolate and AirGap intentionally block remote access at the end.
    Configure-RDPAccess -KeepRDP $effectivePreserveRDP

    # Defender + ASR.
    Configure-Defender -IsServer $isServer -UseZeroTolerance $effectiveAggressive
    Enable-ASRRules -ExchangeServer $exchangeServer

    if (($Mode -ne 'Harden') -and (-not $PreserveDefenderExclusions)) {
        Remove-DefenderExclusionsSafely
    }
    elseif ($PreserveDefenderExclusions) {
        Write-WarnMessage 'Defender exclusions preserved by request.'
    }

    # Logging and audit before additional containment.
    Configure-PowerShellLogging

    # Protocol/network/credential baseline.
    Disable-NetBIOS
    Configure-NetworkStack
    Configure-SMB -KeepSMB $effectivePreserveSMB -IsServer $isServer
    Configure-CredentialSecurity -IsDC $isDC
    Configure-UACAndAutorun
    Configure-PrintNightmareMitigations
    Configure-LDAP -IsDC $isDC
    Remove-AccessibilityIFEOHijacks

    # Disable insecure optional features.
    Write-Section 'Legacy Optional Features'
    Disable-OptionalFeatureIfPresent -FeatureName 'TFTP'
    Disable-OptionalFeatureIfPresent -FeatureName 'TelnetClient'
    Disable-OptionalFeatureIfPresent -FeatureName 'TelnetServer'
    Disable-OptionalFeatureIfPresent -FeatureName 'SMB1Protocol'

    # Emergency remote-service lockdown.
    if ($Mode -ne 'Harden') {
        Configure-RemoteAccess `
            -KeepWinRM ([bool]$PreserveWinRM) `
            -KeepSMB $effectivePreserveSMB `
            -KeepPrinting ([bool]$PreservePrinting)

        Add-LockdownFirewallRules `
            -KeepRDP $effectivePreserveRDP `
            -KeepWinRM ([bool]$PreserveWinRM) `
            -KeepSMB $effectivePreserveSMB
    }
    else {
        # Still disable clearly unnecessary remote-risk services in baseline mode.
        Stop-AndDisableService -Name 'RemoteRegistry' -Reason 'remote registry modification'
        Stop-AndDisableService -Name 'WebClient' -Reason 'WebDAV client'
    }

    # Compatibility-impacting controls.
    if ($effectiveDisableTLS) {
        Configure-TLSHardening
    }

    if ($effectiveDisableWSH) {
        Configure-WindowsScriptHost
    }

    if ($effectiveBlockUSB) {
        Configure-USBStorageBlock
    }

    if ($effectiveEnableVBS) {
        Configure-VBSAndMemoryIntegrity -IsDC $isDC
    }

    # Keep servicing available in non-isolated modes.
    if ($Mode -ne 'Isolate') {
        Write-Section 'Windows Update Services'
        try {
            Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Set-ServiceManualIfPresent -Name 'BITS'
            Write-Ok 'Windows Update servicing left available.'
        }
        catch {
            Write-WarnMessage 'Windows Update service could not be initialized.'
        }
    }

    # Scan after hardening while network is still available.
    Run-DefenderScans

    # Flush resolver cache after changing name-resolution controls.
    try {
        ipconfig.exe /flushdns | Out-Null
        Write-Ok 'DNS resolver cache flushed.'
    }
    catch {
        Write-WarnMessage 'DNS resolver cache could not be flushed.'
    }

    # Full isolation LAST so Defender update and evidence collection are not cut off.
    if ($Mode -eq 'Isolate') {
        Enable-FullNetworkIsolation
    }

    # Verify state before optional hardware-style air gap.
    Show-Verification

    # Optional NIC disable after verification.
    if ($AirGap) {
        Disable-NetworkAdaptersForAirGap
    }

    Write-Section 'Completed'
    Write-Host "Evidence and backups : $script:RunRoot" -ForegroundColor Green
    Write-Host "Transcript           : $script:TranscriptPath" -ForegroundColor Green
    Write-Host "Firewall backup      : $script:FirewallBackup" -ForegroundColor Green

    if ($Mode -eq 'Isolate') {
        Write-WarnMessage 'Host is in network isolation. EmergencyLockdown firewall block rules must be removed locally to restore traffic.'
    }

    if ($effectiveEnableVBS) {
        Write-WarnMessage 'A reboot is required for VBS/Credential Guard/Memory Integrity changes.'
    }

    if ($RunOfflineScan) {
        if (Get-Command Start-MpWDOScan -ErrorAction SilentlyContinue) {
            Write-WarnMessage 'Starting Microsoft Defender Offline scan. Windows will reboot.'
            Start-MpWDOScan
        }
        else {
            Write-WarnMessage 'Defender Offline scan cmdlet is unavailable.'
        }
    }
    elseif ($Reboot) {
        Write-WarnMessage 'Reboot requested.'
        Restart-Computer -Force
    }
    else {
        Write-Host ''
        Write-Host 'A reboot is recommended after emergency hardening.' -ForegroundColor Yellow
    }
}
catch {
    Write-Fail "Fatal script error: $($_.Exception.Message)"
    Write-Fail "Line: $($_.InvocationInfo.ScriptLineNumber)"
    throw
}
finally {
    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            # Ignore transcript shutdown errors.
        }
    }
}
