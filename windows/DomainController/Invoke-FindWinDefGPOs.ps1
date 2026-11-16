<#
.SYNOPSIS
    Finds Group Policy Objects that disable or weaken Microsoft Defender Antivirus.

.DESCRIPTION
    Run on a Domain Controller (or any machine with the GroupPolicy module / RSAT).
    Scans every GPO in the domain for:
      1. Administrative Template / registry-policy settings under the Defender policy keys
      2. Group Policy Preferences registry items that touch Defender or its services
      3. Security Settings > System Services set to Disabled for Defender-related services
    Also reports where each offending GPO is linked, whether the link is enabled,
    GPO status, and any WMI filter, so you can tell if it actually applies.

.PARAMETER Domain
    DNS name of the domain to scan. Defaults to the current domain.

.PARAMETER OutputPath
    Folder for the CSV output. Defaults to a timestamped folder in the current directory.

.PARAMETER IncludeInfo
    Also list every Defender-related setting found (including harmless ones and
    exclusions) rather than only problem settings.

.EXAMPLE
    .\Find-DefenderBreakingGPOs.ps1

.EXAMPLE
    .\Find-DefenderBreakingGPOs.ps1 -IncludeInfo -OutputPath C:\Temp\DefenderAudit
#>
#Requires -Version 5.1
#Requires -Modules GroupPolicy

[CmdletBinding()]
param(
    [string]$Domain = $env:USERDNSDOMAIN,
    [string]$OutputPath = (Join-Path $PWD ("DefenderGPOAudit_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]$IncludeInfo
)

Import-Module GroupPolicy -ErrorAction Stop

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Registry keys (Computer Configuration) where Defender policies live.
$KeysToScan = @(
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection',
    'HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
)

# Values that are problems when set to a specific number.
$RuleMap = @{
    'DisableAntiSpyware'            = @{ Bad = 1; Sev = 'Critical'; Desc = 'Defender Antivirus turned OFF entirely' }
    'DisableAntiVirus'              = @{ Bad = 1; Sev = 'Critical'; Desc = 'Defender Antivirus turned OFF' }
    'DisableRealtimeMonitoring'     = @{ Bad = 1; Sev = 'Critical'; Desc = 'Real-time protection disabled' }
    'DisableBehaviorMonitoring'     = @{ Bad = 1; Sev = 'High';     Desc = 'Behavior monitoring disabled' }
    'DisableOnAccessProtection'     = @{ Bad = 1; Sev = 'High';     Desc = 'On-access (file open/close) scanning disabled' }
    'DisableIOAVProtection'         = @{ Bad = 1; Sev = 'High';     Desc = 'Scanning of downloads/attachments disabled' }
    'DisableScriptScanning'         = @{ Bad = 1; Sev = 'High';     Desc = 'Script scanning disabled' }
    'ForceDefenderPassiveMode'      = @{ Bad = 1; Sev = 'High';     Desc = 'Defender forced into PASSIVE mode (no real-time blocking)' }
    'DisableRawWriteNotification'   = @{ Bad = 1; Sev = 'Medium';   Desc = 'Raw volume write notification disabled' }
    'DisableBlockAtFirstSeen'       = @{ Bad = 1; Sev = 'Medium';   Desc = 'Block at First Sight disabled' }
    'SpynetReporting'               = @{ Bad = 0; Sev = 'Medium';   Desc = 'Cloud-delivered protection (MAPS) disabled' }
    'DisableRoutinelyTakingAction'  = @{ Bad = 1; Sev = 'Medium';   Desc = 'Automatic remediation of threats disabled' }
    'DisableArchiveScanning'        = @{ Bad = 1; Sev = 'Low';      Desc = 'Archive scanning disabled' }
    'DisableRemovableDriveScanning' = @{ Bad = 1; Sev = 'Low';      Desc = 'Removable drive scanning disabled' }
    'DisableLocalAdminMerge'        = @{ Bad = 1; Sev = 'Low';      Desc = 'Local admin exclusions/settings ignored' }
    'PUAProtection'                 = @{ Bad = 0; Sev = 'Low';      Desc = 'Potentially unwanted app protection disabled' }
    'MpEnablePus'                   = @{ Bad = 0; Sev = 'Low';      Desc = 'Potentially unwanted app protection disabled' }
}

# Services whose startup should never be Disabled.
$DefenderServices = @('WinDefend', 'WdNisSvc', 'WdFilter', 'WdBoot', 'Sense', 'SecurityHealthService')

$SevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Review = 4; Info = 5 }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

$Findings = New-Object 'System.Collections.Generic.List[object]'

function Get-ChildText {
    param($Node, [string]$ChildName)
    $c = $Node.SelectSingleNode("*[local-name()='$ChildName']")
    if ($c) { return $c.InnerText }
    return $null
}

function Add-Finding {
    param($Gpo, $LinkInfo, [string]$Severity, [string]$Category, [string]$Setting, $Value, [string]$Meaning)

    $Findings.Add([pscustomobject]@{
        Severity     = $Severity
        GPOName      = $Gpo.DisplayName
        GPOGuid      = $Gpo.Id
        GpoStatus    = $Gpo.GpoStatus
        Category     = $Category
        Setting      = $Setting
        Value        = $Value
        Meaning      = $Meaning
        LinkedTo     = $LinkInfo.Linked
        AnyLinkEnabled = $LinkInfo.AnyEnabled
        WmiFilter    = $Gpo.WmiFilter.Name
        Modified     = $Gpo.ModificationTime
    })
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "Retrieving GPOs from $Domain ..." -ForegroundColor Cyan
$gpos = Get-GPO -All -Domain $Domain
Write-Host "Found $($gpos.Count) GPOs. Scanning for Defender-related settings..." -ForegroundColor Cyan

$i = 0
foreach ($gpo in $gpos) {
    $i++
    Write-Progress -Activity 'Scanning GPOs' -Status $gpo.DisplayName -PercentComplete (($i / $gpos.Count) * 100)

    # ---- Pull the XML report once (used for links, services and GPP) ----
    $xml = $null
    try {
        $xml = [xml](Get-GPOReport -Guid $gpo.Id -Domain $Domain -ReportType Xml -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not read report for '$($gpo.DisplayName)': $($_.Exception.Message)"
    }

    # ---- Link info ----
    $linkList = @()
    $anyEnabled = $false
    if ($xml) {
        foreach ($l in $xml.SelectNodes("//*[local-name()='LinksTo']")) {
            $path    = Get-ChildText $l 'SOMPath'
            $enabled = Get-ChildText $l 'Enabled'
            $enforce = Get-ChildText $l 'NoOverride'
            if ($enabled -eq 'true') { $anyEnabled = $true }
            $linkList += ("{0} [Enabled={1}, Enforced={2}]" -f $path, $enabled, $enforce)
        }
    }
    $linkInfo = @{
        Linked     = if ($linkList) { $linkList -join '; ' } else { '(not linked)' }
        AnyEnabled = $anyEnabled
    }

    # ---- 1. Registry-based policy (Administrative Templates) ----
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($key in $KeysToScan) {
        $vals = @()
        try {
            $vals = @(Get-GPRegistryValue -Guid $gpo.Id -Domain $Domain -Key $key -ErrorAction Stop)
        }
        catch { continue }   # key not configured in this GPO

        foreach ($v in $vals) {
            if ([string]::IsNullOrEmpty($v.ValueName)) { continue }
            $id = "$($v.FullKeyPath)|$($v.ValueName)"
            if (-not $seen.Add($id)) { continue }

            $setting = "$($v.FullKeyPath)\$($v.ValueName)"
            $isDelete = ("$($v.PolicyState)" -match 'Delete')

            if ($isDelete) {
                Add-Finding $gpo $linkInfo 'Info' 'Registry Policy' $setting '(deleted/cleared)' 'Policy clears this value'
                continue
            }

            if ($RuleMap.ContainsKey($v.ValueName)) {
                $rule = $RuleMap[$v.ValueName]
                $isBad = $false
                try { $isBad = ([int64]$v.Value -eq [int64]$rule.Bad) } catch { }
                if ($isBad) {
                    Add-Finding $gpo $linkInfo $rule.Sev 'Registry Policy' $setting $v.Value $rule.Desc
                    continue
                }
            }

            if ($v.FullKeyPath -match '\\Exclusions\\(Paths|Extensions|Processes|IpAddresses)') {
                Add-Finding $gpo $linkInfo 'Review' 'Registry Policy' $setting $v.Value 'Scan exclusion - verify it is intended'
                continue
            }

            Add-Finding $gpo $linkInfo 'Info' 'Registry Policy' $setting $v.Value 'Defender-related setting (not flagged)'
        }
    }

    if (-not $xml) { continue }

    # ---- 2. Security Settings > System Services ----
    foreach ($s in $xml.SelectNodes("//*[local-name()='SystemServices']")) {
        $svcName = Get-ChildText $s 'Name'
        $mode    = Get-ChildText $s 'StartupMode'
        if ($DefenderServices -contains $svcName) {
            if ($mode -eq 'Disabled') {
                Add-Finding $gpo $linkInfo 'Critical' 'System Services' $svcName $mode "Defender-related service '$svcName' set to Disabled"
            }
            else {
                Add-Finding $gpo $linkInfo 'Info' 'System Services' $svcName $mode 'Defender-related service startup configured'
            }
        }
    }

    # ---- 3. Group Policy Preferences > Registry ----
    foreach ($p in $xml.SelectNodes("//*[local-name()='Registry']/*[local-name()='Properties']")) {
        $key   = $p.GetAttribute('key')
        $name  = $p.GetAttribute('name')
        $val   = $p.GetAttribute('value')
        $type  = $p.GetAttribute('type')
        $act   = $p.GetAttribute('action')

        if ($key -notmatch 'Windows Defender|Microsoft Antimalware|Advanced Threat Protection|Services\\(WinDefend|WdNisSvc|WdFilter|WdBoot|Sense|SecurityHealthService)') { continue }

        $num = $null
        try {
            if ($type -eq 'REG_DWORD') { $num = [Convert]::ToInt64($val, 16) } else { $num = [int64]$val }
        } catch { }

        $setting = "$key\$name (GPP action=$act)"
        $flagged = $false

        if ($act -ne 'D') {   # D = Delete
            if ($key -match 'Services\\' -and $name -eq 'Start' -and $num -eq 4) {
                Add-Finding $gpo $linkInfo 'Critical' 'GPP Registry' $setting $val 'Defender-related service Start=4 (Disabled)'
                $flagged = $true
            }
            elseif ($RuleMap.ContainsKey($name) -and $null -ne $num -and $num -eq [int64]$RuleMap[$name].Bad) {
                Add-Finding $gpo $linkInfo $RuleMap[$name].Sev 'GPP Registry' $setting $val $RuleMap[$name].Desc
                $flagged = $true
            }
            elseif ($key -match '\\Exclusions\\') {
                Add-Finding $gpo $linkInfo 'Review' 'GPP Registry' $setting $val 'Scan exclusion - verify it is intended'
                $flagged = $true
            }
        }
        if (-not $flagged) {
            Add-Finding $gpo $linkInfo 'Info' 'GPP Registry' $setting $val 'Defender-related preference item (not flagged)'
        }
    }
}
Write-Progress -Activity 'Scanning GPOs' -Completed

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$sorted  = $Findings | Sort-Object @{ Expression = { $SevRank[$_.Severity] } }, GPOName
$problems = @($sorted | Where-Object { $_.Severity -ne 'Info' })

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$csvProblems = Join-Path $OutputPath 'Defender_GPO_Problems.csv'
$problems | Export-Csv -Path $csvProblems -NoTypeInformation -Encoding UTF8

if ($IncludeInfo) {
    $csvAll = Join-Path $OutputPath 'Defender_GPO_AllSettings.csv'
    $sorted | Export-Csv -Path $csvAll -NoTypeInformation -Encoding UTF8
}

Write-Host ''
if ($problems.Count -eq 0) {
    Write-Host 'No GPO settings that disable or weaken Defender were found.' -ForegroundColor Green
    Write-Host 'If Defender is still not working, check for a third-party AV (puts Defender in passive mode),'
    Write-Host 'local policy, Tamper Protection, or Intune/MDE-managed settings.'
}
else {
    Write-Host "Found $($problems.Count) potentially problematic setting(s):" -ForegroundColor Yellow
    $problems |
        Select-Object Severity, GPOName, Setting, Value, Meaning, AnyLinkEnabled, LinkedTo |
        Format-Table -AutoSize -Wrap

    Write-Host 'Summary by GPO:' -ForegroundColor Cyan
    $problems | Group-Object GPOName | Sort-Object Count -Descending |
        Select-Object @{ n = 'GPO'; e = { $_.Name } }, Count | Format-Table -AutoSize
}

Write-Host "Results saved to: $OutputPath" -ForegroundColor Cyan
if ($problems | Where-Object { -not $_.AnyLinkEnabled }) {
    Write-Host "Note: some flagged GPOs have no enabled links, so they are not currently applying." -ForegroundColor DarkYellow
}