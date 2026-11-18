<#
.SYNOPSIS
    Host-Detect-RemoteAccess.ps1 - read-only sweep for VNC and other remote-access tools.

.DESCRIPTION
    Replaces Detect-VNC-NECCDC.ps1 and list_vnc_v2.ps1.

    Checks installed programs, services, running processes, scheduled tasks,
    Run/RunOnce keys (every loaded user hive), and listening ports.

    Matches on the file name AND on the executable's version metadata
    (product name, description, original file name, company), so a renamed
    binary such as C:\Users\Public\svc.exe that is really AnyDesk still shows up.

    Read-only: changes nothing, writes nothing to disk, and does not collect
    passwords, config files or connection history. Validate every finding
    before removing anything - some tools may be in scope for scoring/injects.

    Match column:
      Renamed?  - metadata says it is a remote tool but the name does not. Look at these first.
      Confirmed - name and metadata agree.
      Verify    - name or port only; metadata unavailable or inconclusive.

.PARAMETER PassThru
    Also return findings as objects, e.g. | Export-Csv or | Out-GridView.

.EXAMPLE
    .\Host-Detect-RemoteAccess.ps1

.EXAMPLE
    .\Host-Detect-RemoteAccess.ps1 -PassThru | Out-GridView
#>
[CmdletBinding()]
param(
    [switch]$PassThru
)

$ErrorActionPreference = 'SilentlyContinue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator: other users' process paths and some service binaries will be hidden. Re-run elevated for full results."
}

# ---------------------------------------------------------------------------
# Signatures. Patterns are regex and case-insensitive.
#   NamePattern      - installed program name, service display name, ProductName/FileDescription
#   MetaPattern      - optional; used instead of NamePattern for file metadata when NamePattern is too generic
#   PublisherPattern - installed program publisher / file CompanyName ($null = don't use alone)
#   FilePattern      - executable file name (also checked against OriginalFilename metadata)
#   ServicePattern   - service short name
# To add a tool, copy a block and adjust the patterns.
# ---------------------------------------------------------------------------
$Signatures = @(
    # --- VNC family ---
    [pscustomobject]@{ Product = 'RealVNC'
        NamePattern = 'RealVNC|^VNC (Server|Viewer|Connect)'; PublisherPattern = 'RealVNC'
        MetaPattern = 'RealVNC'   # other VNC builds also describe themselves as "VNC Server"
        FilePattern = '^(vncserver|vncviewer|vncagent|vncconfig)\.exe$'; ServicePattern = 'realvnc|^vncserver' }
    [pscustomobject]@{ Product = 'TightVNC'
        NamePattern = 'TightVNC'; PublisherPattern = 'GlavSoft|TightVNC'
        FilePattern = '^(tvnserver|tvnviewer)\.exe$'; ServicePattern = '^tvnserver' }
    [pscustomobject]@{ Product = 'UltraVNC'
        NamePattern = 'UltraVNC'; PublisherPattern = 'UltraVNC|uvnc'
        FilePattern = '^(winvnc|vncviewer|uvnc_service)\.exe$'; ServicePattern = '^(uvnc|winvnc)' }
    [pscustomobject]@{ Product = 'TigerVNC'
        NamePattern = 'TigerVNC'; PublisherPattern = 'TigerVNC'
        FilePattern = '^(winvnc4?|x0vncserver|vncviewer)\.exe$'; ServicePattern = 'tigervnc|winvnc4' }

    # --- Commercial / free remote-access tools ---
    [pscustomobject]@{ Product = 'AnyDesk'
        NamePattern = 'AnyDesk'; PublisherPattern = 'AnyDesk|philandro'
        FilePattern = '^anydesk\.exe$'; ServicePattern = '^AnyDesk' }
    [pscustomobject]@{ Product = 'TeamViewer'
        NamePattern = 'TeamViewer'; PublisherPattern = 'TeamViewer'
        FilePattern = '^(TeamViewer|TeamViewer_Service|tv_w32|tv_x64)\.exe$'; ServicePattern = '^TeamViewer' }
    [pscustomobject]@{ Product = 'ScreenConnect / ConnectWise Control'
        NamePattern = 'ScreenConnect|ConnectWise Control'; PublisherPattern = 'ConnectWise|ScreenConnect'
        FilePattern = '^ScreenConnect\.(ClientService|WindowsClient)\.exe$'; ServicePattern = '^ScreenConnect' }
    [pscustomobject]@{ Product = 'RustDesk'
        NamePattern = 'RustDesk'; PublisherPattern = 'RustDesk|Purslane'
        FilePattern = '^rustdesk\.exe$'; ServicePattern = '^RustDesk' }
    [pscustomobject]@{ Product = 'Splashtop'
        NamePattern = 'Splashtop'; PublisherPattern = 'Splashtop'
        FilePattern = '^(SRService|SRServer|SRManager|SRAgent)\.exe$'; ServicePattern = '^Splashtop' }
    [pscustomobject]@{ Product = 'Radmin'
        NamePattern = 'Radmin'; PublisherPattern = 'Famatech'
        FilePattern = '^(rserver3|radmin)\.exe$'; ServicePattern = '^RServer3' }
    [pscustomobject]@{ Product = 'Ammyy Admin'
        NamePattern = 'Ammyy'; PublisherPattern = 'Ammyy'
        FilePattern = '^(AA_v3|Ammyy_?Admin)\.exe$'; ServicePattern = '^Ammyy' }
    [pscustomobject]@{ Product = 'Chrome Remote Desktop'
        NamePattern = 'Chrome Remote Desktop'; PublisherPattern = $null   # "Google" alone would flag Chrome itself
        FilePattern = '^remoting_(host|desktop)\.exe$'; ServicePattern = '^chromoting' }
    [pscustomobject]@{ Product = 'DWService'
        NamePattern = 'DWAgent|DWService'; PublisherPattern = 'DWService'
        FilePattern = '^dwag(ent|svc)\.exe$'; ServicePattern = '^dwagent' }
    [pscustomobject]@{ Product = 'MeshCentral Agent'
        NamePattern = 'Mesh ?Agent|MeshCentral'; PublisherPattern = $null
        FilePattern = '^MeshAgent\.exe$'; ServicePattern = 'Mesh ?Agent' }
    [pscustomobject]@{ Product = 'NetSupport Manager'
        NamePattern = 'NetSupport'; PublisherPattern = 'NetSupport'
        FilePattern = '^client32\.exe$'; ServicePattern = '^Client32' }
    [pscustomobject]@{ Product = 'Remote Utilities'
        NamePattern = 'Remote Utilities'; PublisherPattern = 'Remote Utilities|Usoris'
        FilePattern = '^(rutserv|rfusclient)\.exe$'; ServicePattern = '^RManService' }
    [pscustomobject]@{ Product = 'LogMeIn'
        NamePattern = 'LogMeIn'; PublisherPattern = 'LogMeIn'
        FilePattern = '^(LogMeIn|LMIGuardianSvc|LogMeInSystray)\.exe$'; ServicePattern = '^(LogMeIn|LMIGuardianSvc)' }
    [pscustomobject]@{ Product = 'Supremo'
        NamePattern = 'Supremo'; PublisherPattern = 'Nanosystems'
        FilePattern = '^Supremo(Service|Helper)?\.exe$'; ServicePattern = '^Supremo' }
    [pscustomobject]@{ Product = 'Parsec'
        NamePattern = '^Parsec'; PublisherPattern = 'Parsec Cloud'
        FilePattern = '^parsecd\.exe$'; ServicePattern = '^Parsec' }
)

# Ports commonly used by these tools. A port alone is NOT proof - always verify the owning process.
$PortHints = @{}
foreach ($p in 5800..5801)   { $PortHints[$p] = 'VNC (web viewer)' }
foreach ($p in 5900..5906)   { $PortHints[$p] = 'VNC' }
foreach ($p in 6783..6785)   { $PortHints[$p] = 'Splashtop' }
foreach ($p in 21118..21119) { $PortHints[$p] = 'RustDesk' }
$PortHints[4899] = 'Radmin'
$PortHints[5405] = 'NetSupport'
$PortHints[5650] = 'Remote Utilities'
$PortHints[5938] = 'TeamViewer'
$PortHints[7070] = 'AnyDesk'
$PortHints[8040] = 'ScreenConnect'
$PortHints[8041] = 'ScreenConnect'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
$Findings  = [System.Collections.Generic.List[object]]::new()
$MetaCache = @{}

function Add-Finding {
    param([string]$Match, [string]$Product, [string]$Check, [string]$Evidence, [string]$Path, [string]$Signer = '-')
    $Findings.Add([pscustomobject]@{
        Match    = $Match
        Product  = $Product
        Check    = $Check
        Evidence = $Evidence
        Path     = $Path
        Signer   = $Signer
    })
}

# Pull the executable path out of a command line (quoted or unquoted).
function Get-ExePath {
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    if ($cmd -match '^"([^"]+)"')           { return $Matches[1] }
    if ($cmd -match '^(.+?\.exe)(\s|$)')    { return $Matches[1] }
    return $cmd
}

function Get-LeafName {
    param([string]$Path)
    if (-not $Path) { return $null }
    return ($Path -split '[\\/]')[-1]
}

# Version metadata for a file, cached per path.
function Get-FileMeta {
    param([string]$Path)
    if (-not $Path) { return $null }
    if ($MetaCache.ContainsKey($Path)) { return $MetaCache[$Path] }
    $meta = $null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $vi = (Get-Item -LiteralPath $Path).VersionInfo
        if ($vi) {
            $meta = [pscustomobject]@{
                ProductName      = $vi.ProductName
                FileDescription  = $vi.FileDescription
                OriginalFilename = $vi.OriginalFilename
                CompanyName      = $vi.CompanyName
            }
        }
    }
    $MetaCache[$Path] = $meta
    return $meta
}

function Get-SignerText {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'Path unavailable' }
    $auth = Get-AuthenticodeSignature -FilePath $Path
    if (-not $auth) { return 'Unknown' }
    $text = "$($auth.Status)"
    if ($auth.SignerCertificate) {
        $text += " - $($auth.SignerCertificate.GetNameInfo('SimpleName', $false))"
    }
    return $text
}

# 'Strong' = product name / description / company matches this tool.
# 'Weak'   = only OriginalFilename matches (shared names like vncviewer.exe are ambiguous).
function Test-MetaMatch {
    param($Sig, $Meta)
    if (-not $Meta) { return $null }
    $pattern = if ($Sig.MetaPattern) { $Sig.MetaPattern } else { $Sig.NamePattern }
    foreach ($field in @($Meta.ProductName, $Meta.FileDescription)) {
        if ($field -and $field -match $pattern) { return 'Strong' }
    }
    if ($Sig.PublisherPattern -and $Meta.CompanyName -and $Meta.CompanyName -match $Sig.PublisherPattern) { return 'Strong' }
    if ($Meta.OriginalFilename -and $Meta.OriginalFilename -match $Sig.FilePattern) { return 'Weak' }
    return $null
}

# Returns which signatures an executable (and optional service) matches, and how strongly.
# Only the best evidence tier is kept: strong metadata beats original-filename metadata,
# which beats name-only matches. This stops a file name shared by several products
# (vncviewer.exe, winvnc.exe) from being credited to all of them.
function Get-SigMatches {
    param([string]$FileName, $Meta, [string]$ServiceName, [string]$DisplayName)

    $results = @(foreach ($sig in $Signatures) {
        $fileMatch = [bool]($FileName -and $FileName -match $sig.FilePattern)
        $nameMatch = [bool](($ServiceName -and $ServiceName -match $sig.ServicePattern) -or
                            ($DisplayName -and $DisplayName -match $sig.NamePattern))
        $metaLevel = Test-MetaMatch -Sig $sig -Meta $Meta

        if (-not ($fileMatch -or $nameMatch -or $metaLevel)) { continue }

        $match = if ($metaLevel -eq 'Strong' -and ($fileMatch -or $nameMatch)) { 'Confirmed' }
                 elseif ($metaLevel -and -not ($fileMatch -or $nameMatch))   { 'Renamed?' }
                 else                                                         { 'Verify' }

        $tier = switch ($metaLevel) { 'Strong' { 2 } 'Weak' { 1 } default { 0 } }
        [pscustomobject]@{ Sig = $sig; Match = $match; Tier = $tier }
    })

    if ($results.Count -eq 0) { return @() }
    $best = ($results | Measure-Object -Property Tier -Maximum).Maximum
    return @($results | Where-Object { $_.Tier -eq $best })
}

# Loaded user hives (logged-on users + the current user), for per-user keys.
$UserHives = @(Get-ChildItem -Path 'Registry::HKEY_USERS' |
    Where-Object { $_.PSChildName -notmatch '_Classes$' } |
    ForEach-Object { "Registry::$($_.Name)" })

# ---------------------------------------------------------------------------
# 1) Installed programs
# ---------------------------------------------------------------------------
Write-Host 'Checking installed programs...' -ForegroundColor Cyan
$UninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
) + ($UserHives | ForEach-Object { "$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" })

foreach ($app in (Get-ItemProperty -Path $UninstallRoots | Where-Object { $_.DisplayName })) {
    foreach ($sig in $Signatures) {
        $nameMatch = [bool]($app.DisplayName -match $sig.NamePattern)
        $pubMatch  = [bool]($sig.PublisherPattern -and $app.Publisher -and $app.Publisher -match $sig.PublisherPattern)
        if ($nameMatch -or $pubMatch) {
            Add-Finding -Match $(if ($nameMatch) { 'Confirmed' } else { 'Verify' }) `
                -Product $sig.Product -Check 'Installed program' `
                -Evidence "$($app.DisplayName) $($app.DisplayVersion) ($($app.Publisher))".Trim() `
                -Path $app.InstallLocation
        }
    }
}

# ---------------------------------------------------------------------------
# 2) Services
# ---------------------------------------------------------------------------
Write-Host 'Checking services...' -ForegroundColor Cyan
foreach ($svc in Get-CimInstance Win32_Service) {
    $exe  = Get-ExePath $svc.PathName
    $meta = Get-FileMeta $exe
    $hits = Get-SigMatches -FileName (Get-LeafName $exe) -Meta $meta -ServiceName $svc.Name -DisplayName $svc.DisplayName
    foreach ($m in $hits) {
        Add-Finding -Match $m.Match -Product $m.Sig.Product -Check 'Service' `
            -Evidence "$($svc.DisplayName) [$($svc.Name)] $($svc.State)/$($svc.StartMode)" `
            -Path $(if ($exe) { $exe } else { $svc.PathName }) -Signer (Get-SignerText $exe)
    }
}

# ---------------------------------------------------------------------------
# 3) Running processes
# ---------------------------------------------------------------------------
Write-Host 'Checking running processes...' -ForegroundColor Cyan
foreach ($proc in Get-CimInstance Win32_Process) {
    $exe  = $proc.ExecutablePath
    $file = if ($exe) { Get-LeafName $exe } else { $proc.Name }
    $hits = Get-SigMatches -FileName $file -Meta (Get-FileMeta $exe)
    foreach ($m in $hits) {
        Add-Finding -Match $m.Match -Product $m.Sig.Product -Check 'Running process' `
            -Evidence "$($proc.Name) (PID $($proc.ProcessId))" `
            -Path $exe -Signer (Get-SignerText $exe)
    }
}

# ---------------------------------------------------------------------------
# 4) Scheduled tasks
# ---------------------------------------------------------------------------
Write-Host 'Checking scheduled tasks...' -ForegroundColor Cyan
foreach ($task in Get-ScheduledTask) {
    foreach ($action in $task.Actions) {
        if (-not $action.Execute) { continue }
        $exe  = Get-ExePath $action.Execute
        $hits = Get-SigMatches -FileName (Get-LeafName $exe) -Meta (Get-FileMeta $exe)
        foreach ($m in $hits) {
            Add-Finding -Match $m.Match -Product $m.Sig.Product -Check 'Scheduled task' `
                -Evidence "$($task.TaskPath)$($task.TaskName) [$($task.State)]" `
                -Path "$($action.Execute) $($action.Arguments)".Trim() -Signer (Get-SignerText $exe)
        }
    }
}

# ---------------------------------------------------------------------------
# 5) Run / RunOnce keys (machine + every loaded user hive)
# ---------------------------------------------------------------------------
Write-Host 'Checking Run/RunOnce keys...' -ForegroundColor Cyan
$RunKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
) + ($UserHives | ForEach-Object {
    "$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "$_\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
})

foreach ($key in $RunKeys) {
    $item = Get-Item -Path $key
    if (-not $item) { continue }
    foreach ($valueName in $item.GetValueNames()) {
        $cmd  = [string]$item.GetValue($valueName)
        $exe  = Get-ExePath $cmd
        $hits = Get-SigMatches -FileName (Get-LeafName $exe) -Meta (Get-FileMeta $exe)
        foreach ($m in $hits) {
            Add-Finding -Match $m.Match -Product $m.Sig.Product -Check 'Run key' `
                -Evidence "$($key -replace '^Registry::', '') : $valueName" `
                -Path $cmd -Signer (Get-SignerText $exe)
        }
    }
}

# ---------------------------------------------------------------------------
# 6) Listening ports
# ---------------------------------------------------------------------------
Write-Host 'Checking listening ports...' -ForegroundColor Cyan
$Listeners = Get-NetTCPConnection -State Listen | Where-Object { $PortHints.ContainsKey([int]$_.LocalPort) }
foreach ($l in $Listeners) {
    $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $($l.OwningProcess)"
    Add-Finding -Match 'Verify' -Product "Port often used by $($PortHints[[int]$l.LocalPort])" -Check 'Listening port' `
        -Evidence "TCP $($l.LocalAddress):$($l.LocalPort) - $($owner.Name) (PID $($l.OwningProcess))" `
        -Path $owner.ExecutablePath -Signer (Get-SignerText $owner.ExecutablePath)
}

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
$MatchOrder = @{ 'Renamed?' = 0; 'Confirmed' = 1; 'Verify' = 2 }
$Results = $Findings |
    Sort-Object Product, Check, Evidence, Path -Unique |
    Sort-Object @{ Expression = { $MatchOrder[$_.Match] } }, Product, Check

Write-Host ''
Write-Host "==== Remote-access sweep: $env:COMPUTERNAME  ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ====" -ForegroundColor Cyan

if ($Results) {
    Write-Host "Indicators found (validate before taking action):`n" -ForegroundColor Yellow
    $Results | Format-Table Match, Product, Check, Evidence, Path, Signer -AutoSize -Wrap | Out-String | Write-Host

    $byMatch = $Results | Group-Object Match | Sort-Object { $MatchOrder[$_.Name] }
    foreach ($g in $byMatch) {
        $color = switch ($g.Name) { 'Renamed?' { 'Red' } 'Confirmed' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  {0,-10} {1}" -f $g.Name, $g.Count) -ForegroundColor $color
    }
    if ($Results | Where-Object Match -eq 'Renamed?') {
        Write-Host "`n'Renamed?' = the binary's metadata says remote-access tool but its name doesn't. Check these first." -ForegroundColor Red
    }
} else {
    Write-Host 'No matching remote-access indicators detected.' -ForegroundColor Green
}

Write-Host "`nScope: listed products, loaded user hives, and known ports only. A clean result does not prove nothing is there."

if ($PassThru) { $Results }
