# NECCDC-oriented VNC detector
# Read-only checks: uninstall registry, services, processes, Authenticode metadata,
# and common VNC listening ports. No configuration/password/history collection.

$ErrorActionPreference = 'SilentlyContinue'

# Keep signatures specific. Extend these patterns if your lab images use other vendors.
$Signatures = @(
    [pscustomobject]@{
        Product = 'RealVNC'
        NamePattern = '(?i)RealVNC|VNC Server|VNC Viewer'
        PublisherPattern = '(?i)RealVNC'
        FilePattern = '(?i)^(vncserver|vncviewer|vncconfig)\.exe$'
        ServicePattern = '(?i)realvnc|vncserver'
    }
    [pscustomobject]@{
        Product = 'TightVNC'
        NamePattern = '(?i)TightVNC'
        PublisherPattern = '(?i)GlavSoft|TightVNC'
        FilePattern = '(?i)^(tvnserver|tvnviewer)\.exe$'
        ServicePattern = '(?i)^tvnserver'
    }
    [pscustomobject]@{
        Product = 'UltraVNC'
        NamePattern = '(?i)UltraVNC'
        PublisherPattern = '(?i)UltraVNC|uvnc'
        FilePattern = '(?i)^(winvnc|vncviewer|uvnc_service)\.exe$'
        ServicePattern = '(?i)^(uvnc|winvnc)'
    }
    [pscustomobject]@{
        Product = 'TigerVNC'
        NamePattern = '(?i)TigerVNC'
        PublisherPattern = '(?i)TigerVNC'
        FilePattern = '(?i)^(winvnc|Xtigervnc|x0vncserver|vncviewer)\.exe$'
        ServicePattern = '(?i)tiger.*vnc|Xtigervnc'
    }
)

$Findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [string]$Product,
        [string]$Source,
        [string]$Evidence,
        [string]$Path,
        [string]$SignatureStatus = 'Not checked'
    )

    $Findings.Add([pscustomobject]@{
        Product         = $Product
        Source          = $Source
        Evidence        = $Evidence
        Path            = $Path
        SignatureStatus = $SignatureStatus
    })
}

# 1) Installed application records from native and 32-bit registry views.
$UninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$InstalledApps = foreach ($root in $UninstallRoots) {
    Get-ItemProperty -Path $root |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, Publisher, DisplayVersion, InstallLocation
}

foreach ($app in $InstalledApps) {
    foreach ($sig in $Signatures) {
        $nameMatch = $app.DisplayName -match $sig.NamePattern
        $publisherMatch = $app.Publisher -and $app.Publisher -match $sig.PublisherPattern

        if ($nameMatch -or $publisherMatch) {
            Add-Finding -Product $sig.Product -Source 'Installed application' `
                -Evidence "$($app.DisplayName) $($app.DisplayVersion)".Trim() `
                -Path $app.InstallLocation
        }
    }
}

# 2) Services: inspect service names, display names, and executable command lines.
$Services = Get-CimInstance Win32_Service
foreach ($svc in $Services) {
    foreach ($sig in $Signatures) {
        if ($svc.Name -match $sig.ServicePattern -or
            $svc.DisplayName -match $sig.NamePattern) {

            $exePath = $null
            if ($svc.PathName -match '^\s*"([^"]+\.exe)"') {
                $exePath = $Matches[1]
            } elseif ($svc.PathName -match '^\s*(.+?\.exe)(?:\s|$)') {
                $exePath = $Matches[1].Trim('"')
            }

            $sigStatus = 'Path unavailable'
            if ($exePath -and (Test-Path -LiteralPath $exePath -PathType Leaf)) {
                $auth = Get-AuthenticodeSignature -FilePath $exePath
                $sigStatus = "$($auth.Status)"
                if ($auth.SignerCertificate) {
                    $sigStatus += " - $($auth.SignerCertificate.Subject)"
                }

                $version = (Get-Item -LiteralPath $exePath).VersionInfo
                $metadata = "$($version.ProductName) $($version.OriginalFilename) $($version.CompanyName)"
                if ($metadata -match $sig.NamePattern -or
                    $metadata -match $sig.PublisherPattern -or
                    [IO.Path]::GetFileName($exePath) -match $sig.FilePattern) {
                    $evidence = "$($svc.DisplayName) [$($svc.Name)] - $($svc.State)"
                    Add-Finding -Product $sig.Product -Source 'Service + executable metadata' `
                        -Evidence $evidence -Path $exePath -SignatureStatus $sigStatus
                } else {
                    # Keep the service indicator visible even if metadata is inconclusive.
                    Add-Finding -Product $sig.Product -Source 'Service name match (verify)' `
                        -Evidence "$($svc.DisplayName) [$($svc.Name)] - $($svc.State)" `
                        -Path $svc.PathName -SignatureStatus $sigStatus
                }
            } else {
                Add-Finding -Product $sig.Product -Source 'Service name match (verify)' `
                    -Evidence "$($svc.DisplayName) [$($svc.Name)] - $($svc.State)" `
                    -Path $svc.PathName -SignatureStatus $sigStatus
            }
        }
    }
}

# 3) Running processes: check filename, executable metadata, and Authenticode status.
$Processes = Get-CimInstance Win32_Process
foreach ($proc in $Processes) {
    $fileName = [IO.Path]::GetFileName($proc.ExecutablePath)
    if (-not $fileName) { $fileName = $proc.Name }

    foreach ($sig in $Signatures) {
        if ($fileName -match $sig.FilePattern) {
            $product = $null
            $sigStatus = 'Path unavailable'

            if ($proc.ExecutablePath -and
                (Test-Path -LiteralPath $proc.ExecutablePath -PathType Leaf)) {
                $file = Get-Item -LiteralPath $proc.ExecutablePath
                $meta = $file.VersionInfo
                $metadataText = "$($meta.ProductName) $($meta.OriginalFilename) $($meta.CompanyName)"
                $auth = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath
                $sigStatus = "$($auth.Status)"
                if ($auth.SignerCertificate) {
                    $sigStatus += " - $($auth.SignerCertificate.Subject)"
                }

                if ($metadataText -match $sig.NamePattern -or
                    $metadataText -match $sig.PublisherPattern) {
                    $product = $sig.Product
                }
            }

            # A matching process name is still useful evidence, but label it for verification
            # if metadata does not independently support the vendor attribution.
            if ($product) {
                Add-Finding -Product $product -Source 'Process + executable metadata' `
                    -Evidence $proc.Name -Path $proc.ExecutablePath -SignatureStatus $sigStatus
            } else {
                Add-Finding -Product $sig.Product -Source 'Process name match (verify)' `
                    -Evidence $proc.Name -Path $proc.ExecutablePath -SignatureStatus $sigStatus
            }
        }
    }
}

# 4) Listening ports commonly associated with VNC. Port alone is not a VNC signature.
$VncPorts = @(5900..5906)
$Listeners = Get-NetTCPConnection -State Listen |
    Where-Object { $_.LocalPort -in $VncPorts }

foreach ($listener in $Listeners) {
    $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)"
    Add-Finding -Product 'Unknown / verify' -Source 'VNC-associated listening port' `
        -Evidence "TCP $($listener.LocalAddress):$($listener.LocalPort), PID $($listener.OwningProcess)" `
        -Path $owner.ExecutablePath
}

# Remove duplicate records and display results.
$Results = $Findings |
    Sort-Object Product, Source, Evidence, Path, SignatureStatus -Unique

if ($Results) {
    Write-Host "`nVNC indicators detected (validate before taking action):`n" -ForegroundColor Yellow
    $Results | Format-Table Product, Source, Evidence, Path, SignatureStatus -AutoSize -Wrap
} else {
    Write-Host 'No matching VNC indicators detected.' -ForegroundColor Green
}

Write-Host "`nScope: common VNC products and ports only. A clean result does not prove VNC is absent."
