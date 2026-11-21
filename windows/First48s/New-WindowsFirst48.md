# Windows First 48 (2026–2027)



## Ground rules

- **Never touch black team or scoring accounts.**
- Log in with your own account (team DA, or a local admin on non-domain machines) and test it before changing any other account.
- Disable first, delete later. Save a copy before deleting anything.
- Don't type passwords into commands. Use `Read-Host -AsSecureString`.
- Log every change in the team log (format in [Injects and Docs](#injects-and-docs)).

---

# Setup


1. Get the scripts:

- Am I a DC? 4 or 5 = DC
```
(Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
```
- Copy and paste Github link

```
https://github.com/rwu-cyber/cyber-team/archive/refs/heads/main.zip
```
```
cd Downloads\cyber-team-main\cyber-team-main\windows\scripts


./Host-Invoke-RemoveSSH.ps1
```

Scripts starting with `Host-` run on client machines. Scripts starting with `DC-` run on the Domain Controller only.
2. Run scripts from the admin window. Right-click "Run with PowerShell" does **not** run as admin.

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

3. Start logging:

```powershell
mkdir C:\IR -Force | Out-Null
Start-Transcript C:\IR\log-$env:COMPUTERNAME.txt -Append
```

4. On domain machines, log in with your team DA account (Domain Controller D2). 



---

# Hosts


## H1: Local accounts


```powershell
Get-LocalUser | Format-Table Name, Enabled, LastLogon
Get-LocalGroupMember Administrators

Disable-LocalUser Guest, Administrator
Disable-LocalUser <name>                          # anything else you don't need
Remove-LocalGroupMember Administrators <name>     # anyone who shouldn't be admin
```

Reset the password on every account you keep. First check that no service runs as that account (`Get-CimInstance Win32_Service | Select Name, StartName`).

```powershell
Set-LocalUser -Name <username> -Password (Read-Host "New password" -AsSecureString)
```

**Script option (domain-joined clients only):** these disable **every** local account on the machine, with no exceptions.

- `./Host-Invoke-RemoveLocalUsers.ps1` disables them all. Despite the name, it doesn't delete anything.
- `./Host-Invoke-DisableLocalAccounts.ps1` disables them all **and** sets every password to the same one.

Before running either:

- Be logged in with your **domain** account, and test that it works.
- Run `Get-LocalUser` and check for black team or scoring accounts. If there are any, **don't use the scripts**. Do H1 by hand instead.
- Check that no service runs as a local account (command above).
- **Never run on the DC or a non-domain machine.** You'll lock yourself out.

## H2: Connections and sessions

1.  `netstat -anob` 
2. Look for:
    - `powershell.exe`, `cmd.exe`, `rundll32.exe`, or `mshta.exe` holding a connection
    - Programs running from `Temp`, `AppData`, or `Downloads`
    - Connections to IPs outside your network
3. Log the PID, program, and IP. Then kill it and block the IP:

```powershell
Stop-Process -Id <PID> -Force
New-NetFirewallRule -DisplayName "Block <IP>" -Direction Outbound -RemoteAddress <IP> -Action Block
```

If it comes back, something is restarting it. Check H4.

## H3: Processes

1. Run the **Process script**. It saves everything to `C:\IR\processes.csv` and prints only flagged processes.
2. Check **ShellFromService** first, then **Unsigned + BadPath**, then any PID that also showed up in H2.
3. Save a copy (`Copy-Item <path> C:\IR\samples\`), then `Stop-Process -Id <PID> -Force`.
4. Run `./Host-Detect-RemoteAccess.ps1` to find VNC, AnyDesk, TeamViewer and other remote-access tools. Check `Renamed?` results first. It only reports, so remove things by hand once you've confirmed they shouldn't be there.

`LOLBin` on its own is normal. Only worry if the command line or parent looks wrong.

## H4: Scheduled tasks and startup items

Don't nuke all the tasks. Run `./Host-localAutoRunSchedTask.ps1` to save a list of tasks, Run keys and startup programs to `Desktop\WindowsInventory`. Back the tasks up with the **Task backup script**, then:

```powershell
Get-ScheduledTask | ? TaskPath -notlike '\Microsoft\*' | Select TaskName, State, @{n='Runs';e={$_.Actions.Execute}}
Disable-ScheduledTask -TaskName "<name>"
```

Delete (`Unregister-ScheduledTask`) only once you're sure it's bad.

Also check:

- `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
- Services running a program outside `C:\Windows` or `Program Files`
- `sethc.exe` and `utilman.exe` in `System32` should be signed by Microsoft

## H5: Firewall

1. Turn it on and turn off SMBv1:

```powershell
Set-NetFirewallProfile -All -Enabled True
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

2. List every inbound allow rule, including ones pushed by GPO:

```powershell
Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow |
    Select DisplayName, PolicyStoreSourceType,
        @{n='Port';e={($_ | Get-NetFirewallPortFilter).LocalPort}},
        @{n='From';e={($_ | Get-NetFirewallAddressFilter).RemoteAddress}} |
    Sort Port | Format-Table -AutoSize
```

3. Disable rules that allow **Any** port from **Any** address, or open a port no scored service uses:

```powershell
Disable-NetFirewallRule -DisplayName "<rule name>"
```

If `PolicyStoreSourceType` says `GroupPolicy`, **hand it to Jacob** (Group Policy G6). Otherwise it comes back.



# Defender and Scans


## V1: Enumerate every machine

1. Run the **Enumeration script** on each machine. It saves hostname, OS, IP/MAC, admins, users, programs, roles, shares, listening ports, sessions, and time to `C:\IR\enum-<hostname>.txt`.
2. Once team domain accounts work 

```powershell
$pcs = (Get-ADComputer -Filter 'Enabled -eq $true').Name
Invoke-Command -ComputerName $pcs -FilePath .\enum.ps1 | Out-File C:\IR\enum-all.txt
```

This needs WinRM, which is on by default on Windows Server. Machines that don't answer need to be done by hand.

3. Copy all results to the team share.
4. If the time is wrong anywhere, run `w32tm /resync`. Wrong time breaks domain logins.

**Network inventory (if the rules allow it):** scan your own subnet from a team machine to find every host and open port:

```powershell
nmap -sV -T4 <your-subnet>/24 -oN C:\IR\nmap.txt
```

Compare the results to the machine list you were given. Report anything unexpected to the team.

## V2: Defender on every machine

1. Check every domain machine at once:

```powershell
Invoke-Command -ComputerName $pcs {
    Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled
} | Select PSComputerName, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled | Format-Table
```

2. On any machine showing `False`, turn it back on:

```powershell
Set-Service WinDefend -StartupType Automatic; Start-Service WinDefend
Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableScriptScanning $false
```

3. If it keeps turning off, a GPO is doing it. **Tell Jacob**.

## V3: Exclusions

```powershell
Get-MpPreference | Select Exclusion* | Format-List | Tee-Object C:\IR\exclusions.txt
Remove-MpPreference -ExclusionPath "<path>"
```

**Bad exclusions:** a whole drive (`C:\`), user-writable folders (`Temp`, `ProgramData`, `C:\Users\Public`), `.exe` or `.ps1`, or `powershell.exe`.

## V4: Scans

```powershell
Update-MpSignature
Start-MpScan -ScanType QuickScan                            # every machine, first hour
Start-MpScan -ScanType CustomScan -ScanPath "<folder>"      # after removing an exclusion
Get-MpThreatDetection | Export-Csv C:\IR\detections.csv -NoTypeInformation
```

Run a full scan (`-ScanType FullScan`) during quiet periods. It's slow. Tell Jeff about any detection so he can check that machine's processes and connections.


# Scripts

Save each as a `.ps1` and run it from the admin window.

### Enumeration script (V1)

Save as `enum.ps1`.

```powershell
mkdir C:\IR -Force | Out-Null
$out = "C:\IR\enum-$env:COMPUTERNAME.txt"

function Section($Name, [scriptblock]$Cmd) {
    Write-Host "`n==== $Name ====" -ForegroundColor Green
    "`n==== $Name ====" | Out-File $out -Append
    $result = & $Cmd 2>&1 | Out-String -Width 250
    $result
    $result | Out-File $out -Append
}

Section "Hostname"        { $env:COMPUTERNAME }
Section "OS"              { Get-CimInstance Win32_OperatingSystem | Select Caption, Version, LastBootUpTime }
Section "IP / MAC"        { ipconfig /all }
Section "Administrators"  { Get-LocalGroupMember Administrators -EA SilentlyContinue }
Section "Local users"     { Get-LocalUser -EA SilentlyContinue | Select Name, Enabled, LastLogon, Description }
Section "Programs"        {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                     HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object DisplayName | Select DisplayName, DisplayVersion, Publisher | Sort DisplayName
}
Section "Roles"           {
    if (Get-Command Get-WindowsFeature -EA SilentlyContinue) {
        Get-WindowsFeature | Where-Object Installed | Select -Expand Name
    } else { "Not a server" }
}
Section "Shares"          { Get-SmbShare }
Section "Listening ports" {
    Get-NetTCPConnection -State Listen |
        Select LocalPort, OwningProcess, @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
        Sort LocalPort
}
Section "Sessions"        { quser }
Section "Time"            { Get-Date; w32tm /query /source }

Write-Host "`nSaved to $out" -ForegroundColor Cyan
```

### Connection script (H2)

```powershell
$procs = Get-CimInstance Win32_Process | Group-Object ProcessId -AsHashTable -AsString
Get-NetTCPConnection -State Established, Listen | Where-Object RemoteAddress -notin '127.0.0.1','::1' |
  ForEach-Object {
    $p = $procs[[string]$_.OwningProcess]
    [pscustomobject]@{
      State = $_.State; Remote = "$($_.RemoteAddress):$($_.RemotePort)"; Port = $_.LocalPort
      PID = $_.OwningProcess; Name = $p.Name; Path = $p.ExecutablePath; CmdLine = $p.CommandLine
    }
  } | Sort-Object State, Name | Tee-Object -Variable c | Format-Table -AutoSize
$c | Export-Csv C:\IR\connections.csv -NoTypeInformation
```

### Process script (H3)

```powershell
$all  = Get-CimInstance Win32_Process
$byId = $all | Group-Object ProcessId -AsHashTable -AsString
$badPaths = 'AppData','\Temp\','ProgramData','Users\Public','Downloads'
$lolbins  = 'powershell','pwsh','cmd','rundll32','regsvr32','mshta','wscript','cscript','certutil'

$report = foreach ($p in $all) {
  $path   = $p.ExecutablePath
  $sig    = if ($path) { (Get-AuthenticodeSignature $path -EA 0).Status }
  $parent = $byId[[string]$p.ParentProcessId].Name
  $flags  = @()
  if ($sig -and $sig -ne 'Valid') { $flags += 'Unsigned' }
  if ($badPaths | ? { $path -like "*$_*" }) { $flags += 'BadPath' }
  if ($lolbins -contains ($p.Name -replace '\.exe$')) { $flags += 'LOLBin' }
  if ($p.CommandLine -match '-enc|FromBase64|IEX|DownloadString|hidden') { $flags += 'SuspiciousCmd' }
  if ($parent -match 'w3wp|sqlservr|httpd|tomcat|java' -and $p.Name -match 'cmd|powershell') { $flags += 'ShellFromService' }
  [pscustomobject]@{ PID = $p.ProcessId; Name = $p.Name; Parent = $parent; Flags = $flags -join ','
                     Path = $path; CmdLine = $p.CommandLine }
}
$report | Export-Csv C:\IR\processes.csv -NoTypeInformation
$report | ? Flags | Format-Table PID, Name, Parent, Flags, Path -AutoSize
```

### Task backup script (H4)

```powershell
mkdir C:\IR\tasks -Force | Out-Null
Get-ScheduledTask | ForEach-Object {
  $file = ($_.TaskPath + $_.TaskName) -replace '[\\/:*?"<>|]','_'
  Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-File "C:\IR\tasks\$file.xml"
}
```

### Admin groups script (D3)

```powershell
'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Group Policy Creator Owners',
'DnsAdmins','Cert Publishers','Key Admins','Enterprise Key Admins','Account Operators',
'Backup Operators','Server Operators','Print Operators','RAS and IAS Servers' | ForEach-Object {
    $g = $_
    Get-ADGroupMember $g -EA SilentlyContinue | Select @{n='Group';e={$g}}, SamAccountName, objectClass
} | Format-Table -AutoSize
```

### Kerberos fix script (D5)

```powershell
Import-Module ActiveDirectory

# krbtgt is skipped on purpose: never change its SPN
$accounts = Get-ADUser -Filter * -Properties ServicePrincipalName, DoesNotRequirePreAuth |
    Where-Object { ($_.ServicePrincipalName -or $_.DoesNotRequirePreAuth) -and $_.SamAccountName -ne 'krbtgt' }

foreach ($a in $accounts) {
    $name = $a.SamAccountName
    Write-Host "`n$name" -ForegroundColor Yellow

    if ($a.DoesNotRequirePreAuth) {
        Set-ADAccountControl $name -DoesNotRequirePreAuth $false
        Write-Host "  Pre-auth is now required" -ForegroundColor Green
    }

    if ($a.ServicePrincipalName) {
        Write-Host "  SPNs: $($a.ServicePrincipalName -join ', ')"
        $answer = Read-Host "  Remove SPNs? Only say y if no service uses this account (y/n)"
        if ($answer -eq 'y') {
            Set-ADUser $name -Clear ServicePrincipalName
            Write-Host "  SPNs removed" -ForegroundColor Green
        } else {
            Write-Host "  Kept. Give this account a long password (25+ characters)." -ForegroundColor Cyan
        }
    }
}
```

### GPO search script (G1)

Paste this once, then use `Find-GPOSetting '<text>'` as many times as you need.

```powershell
function Find-GPOSetting($Pattern) {
    Get-GPO -All | ForEach-Object {
        if ((Get-GPOReport -Guid $_.Id -ReportType Xml) -match $Pattern) { $_.DisplayName }
    }
}
```

### cpassword check (G3)

Lists any GPO file in SYSVOL that has a saved password.

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include *.xml |
    Select-String -Pattern 'cpassword' -List | Select Path
```


### Notes
```powershell
powershell.exe -ExecutionPolicy Bypass -File
```

```powershell
Get-NetFirewallRule -DisplayName "SSH" | Get-NetFirewallPortFilter | Where-Object {$_.LocalPort -eq 22}
```

### Big Harden

Run biggerharden (Should be the last thing you run during comp)
```powershell
./bigger-harden/BiggerHarden.ps1
```