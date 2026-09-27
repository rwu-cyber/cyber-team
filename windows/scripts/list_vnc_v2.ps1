# PowerShell Script to Detect VNC Software and Extract Configuration Data
# This script checks for known VNC software and extracts detailed configuration, logins, and connection data

param(
    [string]$ReportPath = "$env:USERPROFILE\Desktop\VNC_Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').txt",
    [switch]$OpenReport,
    [switch]$ConsoleOutput
)

# Define comprehensive list of known VNC and remote desktop software
$VNCApplications = @(
    # RealVNC Suite
    @{ Name = "RealVNC - VNC Server"; Paths = @("C:\Program Files\RealVNC\VNC Server", "C:\Program Files (x86)\RealVNC\VNC Server"); ConfigPaths = @("$env:APPDATA\RealVNC", "$env:PROGRAMDATA\RealVNC") },
    @{ Name = "RealVNC - VNC Viewer"; Paths = @("C:\Program Files\RealVNC\VNC Viewer", "C:\Program Files (x86)\RealVNC\VNC Viewer"); ConfigPaths = @("$env:APPDATA\RealVNC", "$env:PROGRAMDATA\RealVNC") },
    @{ Name = "RealVNC - VNC Connect"; Paths = @("C:\Program Files\RealVNC\VNC Connect", "C:\Program Files (x86)\RealVNC\VNC Connect"); ConfigPaths = @("$env:APPDATA\RealVNC", "$env:PROGRAMDATA\RealVNC") },
    
    # TightVNC
    @{ Name = "TightVNC"; Paths = @("C:\Program Files\TightVNC", "C:\Program Files (x86)\TightVNC"); ConfigPaths = @("$env:APPDATA\TightVNC", "$env:PROGRAMDATA\TightVNC") },
    
    # UltraVNC
    @{ Name = "UltraVNC"; Paths = @("C:\Program Files\UltraVNC", "C:\Program Files (x86)\UltraVNC"); ConfigPaths = @("$env:APPDATA\UltraVNC", "$env:PROGRAMDATA\UltraVNC") },
    
    # TigerVNC
    @{ Name = "TigerVNC"; Paths = @("C:\Program Files\TigerVNC", "C:\Program Files (x86)\TigerVNC"); ConfigPaths = @("$env:APPDATA\.vnc", "$env:HOME\.vnc") },
    
    # Turbo VNC
    @{ Name = "TurboVNC"; Paths = @("C:\Program Files\TurboVNC", "C:\Program Files (x86)\TurboVNC"); ConfigPaths = @("$env:APPDATA\.vnc", "$env:PROGRAMDATA\TurboVNC") },
    
    # LibVNC-based
    @{ Name = "LibVNC"; Paths = @("C:\Program Files\LibVNC", "C:\Program Files (x86)\LibVNC"); ConfigPaths = @("$env:APPDATA\LibVNC") },
    
    # Chrome Remote Desktop
    @{ Name = "Chrome Remote Desktop"; Paths = @("C:\Program Files\Google\Chrome Remote Desktop", "C:\Program Files (x86)\Google\Chrome Remote Desktop"); ConfigPaths = @("$env:APPDATA\Google\Chrome Remote Desktop", "$env:PROGRAMDATA\Google\Chrome Remote Desktop") },
    
    # TeamViewer
    @{ Name = "TeamViewer"; Paths = @("C:\Program Files\TeamViewer", "C:\Program Files (x86)\TeamViewer"); ConfigPaths = @("$env:APPDATA\TeamViewer", "$env:PROGRAMDATA\TeamViewer") },
    
    # AnyDesk
    @{ Name = "AnyDesk"; Paths = @("C:\Program Files\AnyDesk", "C:\Program Files (x86)\AnyDesk"); ConfigPaths = @("$env:APPDATA\AnyDesk", "$env:PROGRAMDATA\AnyDesk") },
    
    # Zoho Assist
    @{ Name = "Zoho Assist"; Paths = @("C:\Program Files\Zoho", "C:\Program Files (x86)\Zoho"); ConfigPaths = @("$env:APPDATA\Zoho", "$env:PROGRAMDATA\Zoho") },
    
    # Splashtop
    @{ Name = "Splashtop"; Paths = @("C:\Program Files\Splashtop", "C:\Program Files (x86)\Splashtop"); ConfigPaths = @("$env:APPDATA\Splashtop", "$env:PROGRAMDATA\Splashtop") },
    
    # Citrix Receiver/Workspace App
    @{ Name = "Citrix Workspace App"; Paths = @("C:\Program Files\Citrix", "C:\Program Files (x86)\Citrix"); ConfigPaths = @("$env:APPDATA\Citrix", "$env:PROGRAMDATA\Citrix") },
    @{ Name = "Citrix Receiver"; Paths = @("C:\Program Files\Citrix Receiver", "C:\Program Files (x86)\Citrix Receiver"); ConfigPaths = @("$env:APPDATA\Citrix", "$env:PROGRAMDATA\Citrix") },
    
    # Ammyy Admin
    @{ Name = "Ammyy Admin"; Paths = @("C:\Program Files\Ammyy", "C:\Program Files (x86)\Ammyy"); ConfigPaths = @("$env:APPDATA\Ammyy", "$env:PROGRAMDATA\Ammyy") },
    
    # Remote Utilities
    @{ Name = "Remote Utilities"; Paths = @("C:\Program Files\Remote Utilities", "C:\Program Files (x86)\Remote Utilities"); ConfigPaths = @("$env:APPDATA\Remote Utilities", "$env:PROGRAMDATA\Remote Utilities") },
    
    # Radmin VNC
    @{ Name = "Radmin VNC"; Paths = @("C:\Program Files\Radmin VNC", "C:\Program Files (x86)\Radmin VNC"); ConfigPaths = @("$env:APPDATA\Famatech", "$env:PROGRAMDATA\Famatech") },
    
    # PC Anywhere
    @{ Name = "Symantec pcAnywhere"; Paths = @("C:\Program Files\pcAnywhere", "C:\Program Files (x86)\pcAnywhere"); ConfigPaths = @("$env:APPDATA\Symantec\pcAnywhere") },
    
    # ConnectWise Control (ScreenConnect)
    @{ Name = "ConnectWise Control"; Paths = @("C:\Program Files\ConnectWise Control", "C:\Program Files (x86)\ConnectWise Control"); ConfigPaths = @("$env:PROGRAMDATA\ConnectWise Control") },
    
    # Supremo
    @{ Name = "Supremo"; Paths = @("C:\Program Files\Supremo", "C:\Program Files (x86)\Supremo"); ConfigPaths = @("$env:APPDATA\Supremo", "$env:PROGRAMDATA\Supremo") },
    
    # AweSun Remote Desktop
    @{ Name = "AweSun Remote Desktop"; Paths = @("C:\Program Files\AweSun", "C:\Program Files (x86)\AweSun"); ConfigPaths = @("$env:APPDATA\AweSun", "$env:PROGRAMDATA\AweSun") },
    
    # Apple Remote Desktop
    @{ Name = "Apple Remote Desktop"; Paths = @("C:\Program Files\Apple Remote Desktop", "C:\Program Files (x86)\Apple Remote Desktop"); ConfigPaths = @("$env:APPDATA\Apple", "$env:PROGRAMDATA\Apple") },
    
    # Microsoft Remote Desktop
    @{ Name = "Microsoft Remote Desktop"; Paths = @("C:\Program Files\Remote Desktop", "C:\Program Files (x86)\Remote Desktop"); ConfigPaths = @("$env:APPDATA\Microsoft\Remote Desktop") },
    
    # Parsec
    @{ Name = "Parsec"; Paths = @("C:\Program Files\Parsec", "C:\Program Files (x86)\Parsec"); ConfigPaths = @("$env:APPDATA\Parsec", "$env:PROGRAMDATA\Parsec") },
    
    # DWService
    @{ Name = "DWService"; Paths = @("C:\Program Files\DWService", "C:\Program Files (x86)\DWService"); ConfigPaths = @("$env:PROGRAMDATA\DWService") },
    
    # RustDesk
    @{ Name = "RustDesk"; Paths = @("C:\Program Files\RustDesk", "C:\Program Files (x86)\RustDesk"); ConfigPaths = @("$env:APPDATA\RustDesk", "$env:PROGRAMDATA\RustDesk") },
    
    # JumpCloud
    @{ Name = "JumpCloud Agent"; Paths = @("C:\Program Files\JumpCloud", "C:\Program Files (x86)\JumpCloud"); ConfigPaths = @("$env:PROGRAMDATA\JumpCloud") },
    
    # GoToMyPC
    @{ Name = "GoToMyPC"; Paths = @("C:\Program Files\GoToMyPC", "C:\Program Files (x86)\GoToMyPC"); ConfigPaths = @("$env:APPDATA\GoToMyPC", "$env:PROGRAMDATA\GoToMyPC") },
    
    # Windows RDP Services
    @{ Name = "Windows RDP Service"; Paths = @("C:\Windows\System32\mstsc.exe"); ConfigPaths = @("$env:APPDATA\Microsoft\Remote Desktop") },
    
    # OpenRDP
    @{ Name = "OpenRDP"; Paths = @("C:\Program Files\OpenRDP", "C:\Program Files (x86)\OpenRDP"); ConfigPaths = @("$env:APPDATA\OpenRDP") },
    
    # VNC Viewer Plus
    @{ Name = "VNC Viewer Plus"; Paths = @("C:\Program Files\RealVNC\VNC Viewer Plus", "C:\Program Files (x86)\RealVNC\VNC Viewer Plus"); ConfigPaths = @("$env:APPDATA\RealVNC") },
    
    # ScreenShare
    @{ Name = "ScreenShare"; Paths = @("C:\Program Files\ScreenShare", "C:\Program Files (x86)\ScreenShare"); ConfigPaths = @("$env:APPDATA\ScreenShare") },
    
    # LogMeIn
    @{ Name = "LogMeIn"; Paths = @("C:\Program Files\LogMeIn", "C:\Program Files (x86)\LogMeIn"); ConfigPaths = @("$env:APPDATA\LogMeIn", "$env:PROGRAMDATA\LogMeIn") },
    
    # Slack (has remote features)
    @{ Name = "Slack Remote"; Paths = @("C:\Users\$env:USERNAME\AppData\Local\slack"); ConfigPaths = @("$env:APPDATA\Slack", "$env:LOCALAPPDATA\slack") },
    
    # Microsoft Teams Remote Assistance
    @{ Name = "Microsoft Teams"; Paths = @("C:\Program Files\Microsoft\Teams", "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Teams"); ConfigPaths = @("$env:APPDATA\Microsoft\Teams", "$env:LOCALAPPDATA\Microsoft\Teams") },
    
    # Bomgar (BeyondTrust)
    @{ Name = "Bomgar"; Paths = @("C:\Program Files\Bomgar", "C:\Program Files (x86)\Bomgar"); ConfigPaths = @("$env:PROGRAMDATA\Bomgar") }
)

# Function to test registry for installed applications
function Test-RegistryForVNC {
    param([string]$AppName)
    
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $found = Get-ChildItem -Path $regPath | 
                Where-Object { $_.GetValue("DisplayName") -like "*$AppName*" } | 
                Select-Object -First 1
            
            if ($found) { return $found }
        }
    }
    
    return $null
}

# Function to find all actual installation paths
function Get-ActualInstallationPath {
    param([string[]]$Paths)
    
    $foundPaths = @()
    
    foreach ($path in $Paths) {
        if (Test-Path $path) {
            $foundPaths += $path
        }
    }
    
    return $foundPaths
}

# Function to get RealVNC configuration
function Get-RealVNCData {
    param([string]$AppPath)
    
    $data = @()
    
    try {
        # Check registry for RealVNC settings
        $regPaths = @(
            "HKCU:\Software\RealVNC",
            "HKLM:\Software\RealVNC",
            "HKLM:\Software\Wow6432Node\RealVNC"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regData) {
                    $data += @{
                        Type = "Registry"
                        Path = $regPath
                        Properties = $regData.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                    }
                }
            }
        }
        
        # Check for connection history
        $historyPath = "$env:APPDATA\RealVNC\vncviewer.log"
        if (Test-Path $historyPath) {
            $lastConnections = Get-Content $historyPath -ErrorAction SilentlyContinue | Select-Object -Last 10
            if ($lastConnections) {
                $data += @{
                    Type = "ConnectionHistory"
                    Path = $historyPath
                    Entries = $lastConnections
                }
            }
        }
        
        # Check for saved connections
        $configPath = "$env:APPDATA\RealVNC\vncviewer.ini"
        if (Test-Path $configPath) {
            $data += @{
                Type = "ConfigFile"
                Path = $configPath
            }
        }
    }
    catch {
        $data += @{
            Type = "Error"
            Message = $_.Exception.Message
        }
    }
    
    return $data
}

# Function to get TeamViewer data
function Get-TeamViewerData {
    param([string]$AppPath)
    
    $data = @()
    
    try {
        # Check registry for TeamViewer ID and settings
        $regPaths = @(
            "HKCU:\Software\TeamViewer",
            "HKLM:\Software\TeamViewer",
            "HKLM:\Software\Wow6432Node\TeamViewer"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regData) {
                    $relevantProps = $regData.PSObject.Properties | Where-Object { 
                        $_.Name -notmatch "^PS" -and ($_.Name -like "*ID*" -or $_.Name -like "*Pass*" -or $_.Name -like "*connect*")
                    }
                    if ($relevantProps) {
                        $data += @{
                            Type = "Registry"
                            Path = $regPath
                            Properties = $relevantProps
                        }
                    }
                }
            }
        }
        
        # Check for TeamViewer logs
        $logPath = "$env:APPDATA\TeamViewer"
        if (Test-Path $logPath) {
            $logFiles = Get-ChildItem -Path $logPath -Filter "*.log" -ErrorAction SilentlyContinue | Select-Object -First 5
            if ($logFiles) {
                $data += @{
                    Type = "LogFiles"
                    Path = $logPath
                    Files = $logFiles
                }
            }
        }
        
        # Check for connections file
        $connectionsFile = "$env:APPDATA\TeamViewer\connections.txt"
        if (Test-Path $connectionsFile) {
            $data += @{
                Type = "ConnectionsFile"
                Path = $connectionsFile
            }
        }
    }
    catch {
        $data += @{
            Type = "Error"
            Message = $_.Exception.Message
        }
    }
    
    return $data
}

# Function to get TightVNC data
function Get-TightVNCData {
    param([string]$AppPath)
    
    $data = @()
    
    try {
        # Check registry for TightVNC settings
        $regPaths = @(
            "HKCU:\Software\TightVNC",
            "HKLM:\Software\TightVNC",
            "HKLM:\Software\Wow6432Node\TightVNC"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regData) {
                    $data += @{
                        Type = "Registry"
                        Path = $regPath
                        Properties = $regData.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                    }
                }
            }
        }
        
        # Check for TightVNC config files
        $configPath = "$env:APPDATA\TightVNC"
        if (Test-Path $configPath) {
            $configFiles = Get-ChildItem -Path $configPath -ErrorAction SilentlyContinue
            if ($configFiles) {
                $data += @{
                    Type = "ConfigFiles"
                    Path = $configPath
                    Files = $configFiles
                }
            }
        }
    }
    catch {
        $data += @{
            Type = "Error"
            Message = $_.Exception.Message
        }
    }
    
    return $data
}

# Function to get UltraVNC data
function Get-UltraVNCData {
    param([string]$AppPath)
    
    $data = @()
    
    try {
        # Check registry for UltraVNC settings
        $regPaths = @(
            "HKCU:\Software\UltraVNC",
            "HKLM:\Software\UltraVNC",
            "HKLM:\Software\Wow6432Node\UltraVNC"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regData) {
                    $data += @{
                        Type = "Registry"
                        Path = $regPath
                        Properties = $regData.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                    }
                }
            }
        }
        
        # Check for password files
        $pwdFile = "$env:APPDATA\UltraVNC\ultravnc.ini"
        if (Test-Path $pwdFile) {
            $data += @{
                Type = "ConfigFile"
                Path = $pwdFile
            }
        }
    }
    catch {
        $data += @{
            Type = "Error"
            Message = $_.Exception.Message
        }
    }
    
    return $data
}

# Function to get Chrome Remote Desktop data
function Get-ChromeRemoteDesktopData {
    param([string]$AppPath)
    
    $data = @()
    
    try {
        # Check Chrome Remote Desktop config
        $configPath = "$env:APPDATA\Google\Chrome Remote Desktop"
        if (Test-Path $configPath) {
            $configs = Get-ChildItem -Path $configPath -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.Extension -in @(".json", ".config", ".ini") }
            if ($configs) {
                $data += @{
                    Type = "ConfigFiles"
                    Path = $configPath
                    Files = $configs
                }
            }
        }
        
        # Check Chrome Remote Desktop registry
        $regPath = "HKCU:\Software\Google\Chrome Remote Desktop"
        if (Test-Path $regPath) {
            $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regData) {
                $data += @{
                    Type = "Registry"
                    Path = $regPath
                    Properties = $regData.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                }
            }
        }
    }
    catch {
        $data += @{
            Type = "Error"
            Message = $_.Exception.Message
        }
    }
    
    return $data
}

# Function to get AnyDesk data
function Get-AnyDeskData {
    param([string]$AppPath)
    
    $data = @()
    
    try {
        # Check AnyDesk config
        $configPath = "$env:APPDATA\AnyDesk"
        if (Test-Path $configPath) {
            $configs = Get-ChildItem -Path $configPath -ErrorAction SilentlyContinue
            if ($configs) {
                $data += @{
                    Type = "ConfigFiles"
                    Path = $configPath
                    Files = $configs
                }
            }
        }
        
        # Check AnyDesk registry
        $regPath = "HKCU:\Software\AnyDesk"
        if (Test-Path $regPath) {
            $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regData) {
                $data += @{
                    Type = "Registry"
                    Path = $regPath
                    Properties = $regData.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                }
            }
        }
    }
    catch {
        $data += @{
            Type = "Error"
            Message = $_.Exception.Message
        }
    }
    
    return $data
}

# Generic function to get configuration data from AppData
function Get-GenericConfigData {
    param([string]$AppName, [string[]]$ConfigPaths)
    
    $data = @()
    
    foreach ($configPath in $ConfigPaths) {
        if (Test-Path $configPath) {
            try {
                # List config files
                $files = Get-ChildItem -Path $configPath -ErrorAction SilentlyContinue | 
                    Where-Object { $_.PSIsContainer -eq $false }
                
                # List subdirectories
                $dirs = Get-ChildItem -Path $configPath -ErrorAction SilentlyContinue | 
                    Where-Object { $_.PSIsContainer -eq $true }
                
                if ($files -or $dirs) {
                    $data += @{
                        Type = "ConfigDirectory"
                        Path = $configPath
                        Files = $files
                        Directories = $dirs
                    }
                }
            }
            catch {
                $data += @{
                    Type = "Error"
                    Path = $configPath
                    Message = $_.Exception.Message
                }
            }
        }
    }
    
    return $data
}

# Function to get file properties
function Get-ApplicationVersion {
    param([string]$Path)
    
    if (Test-Path $path) {
        try {
            $fileInfo = (Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($fileInfo) {
                return $fileInfo.VersionInfo.ProductVersion
            }
        }
        catch {
            return "Unable to determine"
        }
    }
    
    return "Not found"
}

# Function to get file permissions and owner
function Get-FilePermissions {
    param([string]$Path)
    
    $permissions = @()
    
    if (Test-Path $path) {
        try {
            $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
            if ($acl) {
                $permissions += @{
                    Owner = $acl.Owner
                    AccessRules = $acl.Access | Select-Object -First 5 | ForEach-Object {
                        @{
                            Identity = $_.IdentityReference.ToString()
                            Rights = $_.FileSystemRights.ToString()
                            Type = $_.AccessControlType.ToString()
                        }
                    }
                }
            }
        }
        catch {
            $permissions += @{
                Error = $_.Exception.Message
            }
        }
    }
    
    return $permissions
}

# Function to get network connections from event logs
function Get-RemoteConnectionHistory {
    param([string]$AppName)
    
    $connections = @()
    
    try {
        # Look for RDP connections
        $rdpEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($rdpEvents) {
            $connections = $rdpEvents | ForEach-Object {
                @{
                    Time = $_.TimeCreated
                    Message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
                }
            }
        }
    }
    catch {
        # Silently continue if event log not available
    }
    
    return $connections
}

# Format output for better readability
function Format-AppData {
    param($AppName, $AppInfo)
    
    $output = @()
    $output += ""
    $output += "===================================================================================================================="
    $output += " $(($AppName).PadRight(109)) |"
    $output += "===================================================================================================================="
    $output += ""
    
    # Installation paths
    if ($AppInfo.Paths -and $AppInfo.Paths.Count -gt 0) {
        $output += "INSTALLATION LOCATIONS"
        $output += "   " + ("-" * 110)
        foreach ($path in $AppInfo.Paths) {
            $output += "   ➤ $path"
            
            # Version info
            $version = Get-ApplicationVersion -Path $path
            if ($version -ne "Not found" -and $version -ne "Unable to determine") {
                $output += "     Version: $version"
            }
            
            # Permissions
            $perms = Get-FilePermissions -Path $path
            if ($perms.Count -gt 0 -and $perms[0].Owner) {
                $output += "     Owner: $($perms[0].Owner)"
                if ($perms[0].AccessRules) {
                    $output += "     Permissions:"
                    foreach ($rule in $perms[0].AccessRules) {
                        $output += "       • $($rule.Identity): $($rule.Rights) ($($rule.Type))"
                    }
                }
            }
        }
        $output += ""
    }
    
    # Registry information
    if ($AppInfo.RegFound) {
        $regData = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName -like "*$AppName*" } | Select-Object -First 1
        
        if ($regData) {
            $output += "REGISTRY INFORMATION"
            $output += "   " + ("-" * 110)
            if ($regData.DisplayVersion) { $output += "   Version: $($regData.DisplayVersion)" }
            if ($regData.InstallDate) { $output += "   Install Date: $($regData.InstallDate)" }
            if ($regData.Publisher) { $output += "   Publisher: $($regData.Publisher)" }
            if ($regData.InstallLocation) { $output += "   Install Location: $($regData.InstallLocation)" }
            $output += ""
        }
    }
    
    # Configuration data
    if ($AppInfo.ConfigData -and $AppInfo.ConfigData.Count -gt 0) {
        $output += "CONFIGURATION & DATA"
        $output += "   " + ("-" * 110)
        
        foreach ($config in $AppInfo.ConfigData) {
            switch ($config.Type) {
                "Registry" {
                    $output += "   Registry Settings: $($config.Path)"
                    if ($config.Properties) {
                        foreach ($prop in $config.Properties) {
                            $output += "      • $($prop.Name): $($prop.Value)"
                        }
                    }
                }
                "ConnectionHistory" {
                    $output += "   Connection History: $($config.Path)"
                    if ($config.Entries) {
                        $output += "      Recent connections:"
                        foreach ($entry in $config.Entries) {
                            $output += "      • $entry"
                        }
                    }
                }
                "ConfigFile" {
                    $output += "   Configuration File: $($config.Path)"
                }
                "ConfigFiles" {
                    $output += "   Configuration Directory: $($config.Path)"
                    if ($config.Files) {
                        $output += "      Files:"
                        foreach ($file in $config.Files) {
                            $size = if ($file.Length) { "{0:N0} bytes" -f $file.Length } else { "N/A" }
                            $output += "      • $($file.Name) ($size, Modified: $($file.LastWriteTime))"
                        }
                    }
                }
                "LogFiles" {
                    $output += "   Log Files: $($config.Path)"
                    if ($config.Files) {
                        foreach ($file in $config.Files) {
                            $output += "      • $($file.FullName) (Modified: $($file.LastWriteTime))"
                        }
                    }
                }
                "ConnectionsFile" {
                    $output += "   Connections File: $($config.Path)"
                }
                "ConfigDirectory" {
                    $output += "   Configuration Directory: $($config.Path)"
                    if ($config.Files) {
                        $output += "      Files:"
                        foreach ($file in $config.Files) {
                            $size = if ($file.Length) { "{0:N0} bytes" -f $file.Length } else { "N/A" }
                            $output += "      • $($file.Name) ($size, Modified: $($file.LastWriteTime))"
                        }
                    }
                    if ($config.Directories) {
                        $output += "      Directories:"
                        foreach ($dir in $config.Directories) {
                            $output += "      • $($dir.Name)/"
                        }
                    }
                }
                "Error" {
                    $output += "   Error: $($config.Message)"
                    if ($config.Path) {
                        $output += "      Path: $($config.Path)"
                    }
                }
            }
        }
        $output += ""
    }
    
    # Connection history
    if ($AppInfo.Connections -and $AppInfo.Connections.Count -gt 0) {
        $output += "RECENT CONNECTION ACTIVITY"
        $output += "   " + ("-" * 110)
        foreach ($conn in $AppInfo.Connections) {
            $output += "   • $($conn.Time): $($conn.Message)"
        }
        $output += ""
    }
    
    return $output
}

# Initialize report
$report = @()
$report += "===================================================================================================================="
$report += "                         VNC & REMOTE DESKTOP SOFTWARE DETECTION REPORT                                           "
$report += "===================================================================================================================="
$report += ""
$report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Computer: $env:COMPUTERNAME"
$report += "User: $env:USERNAME"
$sysArch = if ([System.Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
$report += "Architecture: $sysArch"
$report += ""
$report += "=" * 115
$report += ""

# Check each VNC application
$foundApps = @()
$missingApps = @()

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Scanning for VNC and Remote Desktop Software...             " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This may take a few moments..." -ForegroundColor Yellow
Write-Host ""

$progressCount = 0
foreach ($app in $VNCApplications) {
    $progressCount++
    $appName = $app.Name
    $paths = $app.Paths
    $configPaths = $app.ConfigPaths
    
    Write-Progress -Activity "Scanning for Remote Desktop Software" -Status "Checking $appName" -PercentComplete (($progressCount / $VNCApplications.Count) * 100)
    
    # Check registry
    $regFound = Test-RegistryForVNC -AppName $appName
    
    # Check file system
    $installedPaths = Get-ActualInstallationPath -Paths $paths
    $fsFound = $installedPaths.Count -gt 0
    
    # Check if found in either location
    if ($regFound -or $fsFound) {
        Write-Host "  Found: $appName" -ForegroundColor Green
        
        # Get configuration data
        $configData = $null
        switch -Wildcard ($appName) {
            "*RealVNC*" {
                $configData = Get-RealVNCData -AppPath ($installedPaths[0])
            }
            "*TeamViewer*" {
                $configData = Get-TeamViewerData -AppPath ($installedPaths[0])
            }
            "*TightVNC*" {
                $configData = Get-TightVNCData -AppPath ($installedPaths[0])
            }
            "*UltraVNC*" {
                $configData = Get-UltraVNCData -AppPath ($installedPaths[0])
            }
            "*Chrome Remote*" {
                $configData = Get-ChromeRemoteDesktopData -AppPath ($installedPaths[0])
            }
            "*AnyDesk*" {
                $configData = Get-AnyDeskData -AppPath ($installedPaths[0])
            }
            default {
                # Generic extraction for other apps
                if ($configPaths) {
                    $configData = Get-GenericConfigData -AppName $appName -ConfigPaths $configPaths
                }
            }
            
        }
        
        # Get connection history
        $connections = Get-RemoteConnectionHistory -AppName $appName
        
        $foundApps += @{ 
            Name = $appName
            Paths = $installedPaths
            RegFound = $regFound
            ConfigPaths = $configPaths
            ConfigData = $configData
            Connections = $connections
        }
        
        # Format and add to report
        $formattedOutput = Format-AppData -AppName $appName -AppInfo @{
            Paths = $installedPaths
            RegFound = $regFound
            ConfigData = $configData
            Connections = $connections
        }
        $report += $formattedOutput
    }
    else {
        $missingApps += $appName
    }


Write-Progress -Activity "Scanning for Remote Desktop Software" -Completed
}
# Summary section
$report += ""
$report += "===================================================================================================================="
$report += "                                                   SUMMARY                                                        "
$report += "===================================================================================================================="
$report += ""
$report += "Applications Scanned: $($VNCApplications.Count)"
$report += "Applications Detected: $($foundApps.Count)"
$report += "Applications Not Found: $($missingApps.Count)"
$report += ""

if ($foundApps.Count -eq 0) {
    Write-Host ""
    Write-Host "---------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  No VNC or remote desktop software detected on this system." -ForegroundColor Yellow
    Write-Host "---------------------------------------------------------------" -ForegroundColor Yellow
    $report += "RESULT: No VNC or remote desktop software detected on this system."
}
else {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "           Detected Applications ($($foundApps.Count))        " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    $foundApps | ForEach-Object { 
        Write-Host "  $($_.Name)" -ForegroundColor Green
    }
    
    $report += "RESULT: VNC/Remote Desktop software detected on this system."
    $report += ""
    $report += "Detected Applications:"
    $foundApps | ForEach-Object {
        $report += "  $($_.Name)"
    }
}

$report += ""
$report += "=" * 115
$report += ""
$report += "Report saved to: $ReportPath"
$report += ""
$report += "===================================================================================================================="
$report += "                                               END OF REPORT                                                       "
$report += "===================================================================================================================="

# Save report to file
try {
    $report -join "`n" | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    Write-Host ""
    Write-Host "---------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "   Report saved to: $ReportPath" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    
    # Display console output if requested
    if ($ConsoleOutput) {
        Write-Host ""
        Write-Host "---------------------------------------------------------------" -ForegroundColor White
        Write-Host "                    CONSOLE OUTPUT                             " -ForegroundColor White
        Write-Host "---------------------------------------------------------------" -ForegroundColor White
        $report | ForEach-Object { Write-Host $_ }
    }
    
    # Open report if requested
    if ($OpenReport) {
        Write-Host "Opening report..." -ForegroundColor Yellow
        Invoke-Item -Path $ReportPath
    }
}
catch {
    Write-Host "Error saving report: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Displaying report on screen instead:" -ForegroundColor Yellow
    Write-Host ""
    $report -join "`n" | Write-Host
}