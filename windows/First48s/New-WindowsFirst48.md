# Windows First 48 (2026–2027)

Everyone does **Setup** first. Then go to your section. Run everything in an **admin PowerShell window**. Scripts are at the bottom.

| Section                                               | Owner    |
| ----------------------------------------------------- | -------- |
| [Setup](#setup)                                       | Everyone |
| [Hosts](#hosts)                                       | Jeff     |
| [Domain Controller and AD](#domain-controller-and-ad) | Jeff     |
| [Group Policy](#group-policy)                         | Jacob    |
| [Defender and Scans](#defender-and-scans)             | Vin      |
| [Injects and Docs](#injects-and-docs)                 | Everyone |

**Handoffs** (tell the other person when you're done):

- **Jacob → Vin:** once the "Team - Defender On" GPO is linked, Vin checks Defender on every machine.
- **Jacob → Jeff:** if a firewall rule comes from a GPO, Jacob fixes it in the GPO, not Jeff on the host.
- **Jeff → Vin:** once team accounts work, Vin can run enumeration remotely from the DC.
- **Everyone:** log every change so we can build inject responses from it.

## Ground rules

- **Never touch black team or scoring accounts.**
- Log in with your own account (team DA, or a local admin on non-domain machines) and test it before changing any other account.
- Disable first, delete later. Save a copy before deleting anything.
- Don't type passwords into commands. Use `Read-Host -AsSecureString`.
- Log every change in the team log (format in [Injects and Docs](#injects-and-docs)).

---

# Setup

**Owner:** Everyone, on every machine you log into

1. Get the scripts:

```powershell
git clone https://github.com/rwu-cyber/cyber-team.git
cd cyber-team
git checkout dev-neccdc-2026   # update if there's a new branch this season
```

2. Run scripts from the admin window. Right-click "Run with PowerShell" does **not** run as admin.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\<script-name>.ps1
```

3. Start logging:

```powershell
mkdir C:\IR -Force | Out-Null
Start-Transcript C:\IR\log-$env:COMPUTERNAME.txt -Append
```

4. On domain machines, log in with your team DA account (Domain Controller D2). 



---

# Hosts

**Owner:** Jeff

## H1: Local accounts

Skip on the DC. It has no local accounts.

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

## H2: Connections and sessions

1. Run the **Connection script** (or `netstat -anob` for a quick look). Run `quser` to see who's logged in, and `logoff <id>` to kick a session.
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

`LOLBin` on its own is normal. Only worry if the command line or parent looks wrong.

## H4: Scheduled tasks and startup items

Don't nuke all the tasks. Back them up with the **Task backup script**, then:

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

---

# Domain Controller and AD

**Owner:** Jeff. Do Setup and Hosts H2–H5 on the DC first.

## D1: Check AD users

```powershell
Get-ADUser -Filter * -Properties whenCreated, LastLogonDate, PasswordNeverExpires, PasswordNotRequired, AdminCount, Description |
    Select SamAccountName, Enabled, whenCreated, LastLogonDate, PasswordNeverExpires, PasswordNotRequired, AdminCount, Description |
    Sort whenCreated -Descending | Tee-Object -Variable u | Format-Table -AutoSize
$u | Export-Csv C:\IR\ad-users.csv -NoTypeInformation
```

**Look for:**

- Accounts created recently (top of the list)
- `AdminCount` = 1 on accounts that aren't in an admin group now
- `PasswordNotRequired` = True
- Passwords written in the `Description` field

## D2: Make team domain admin accounts

```powershell
foreach ($u in 'vin-da','jeff-da','jacob-da') {   # one per team member
    New-ADUser $u -AccountPassword (Read-Host "Password for $u" -AsSecureString) -Enabled $true
    Add-ADGroupMember "Domain Admins"   -Members $u
    Add-ADGroupMember "Protected Users" -Members $u
}
```

Have each person log in with theirs before moving on. Protected Users blocks NTLM and cached logins for these accounts. **Never add** service, computer, or black team accounts to it.

## D3: Clean up admin groups

List members with the **Admin groups script**, then remove anyone who isn't your team or black team:

```powershell
Remove-ADGroupMember "<group>" -Members <name> -Confirm:$false
```

| Group | Should contain |
| --- | --- |
| Domain Admins, Group Policy Creator Owners, DnsAdmins | Your team and black team only |
| Enterprise Admins, Schema Admins | Empty, or only the built-in Administrator |
| Account, Backup, Server, Print Operators | Empty |
| Key Admins, Enterprise Key Admins | Empty |
| Cert Publishers | Your CA servers' computer accounts |
| RAS and IAS Servers | Your NPS or VPN servers' computer accounts |

## D4: Disable accounts that shouldn't have access

Company employee accounts usually don't need to log in during the competition. **Check the rules and with black team first**, because scoring sometimes logs in as a user.

```powershell
$keep = 'vin-da','jeff-da','jacob-da','<blackteam>','<scored accounts>'
$targets = Get-ADUser -Filter 'Enabled -eq $true' | Where-Object SamAccountName -notin $keep
$targets | Select SamAccountName | Export-Csv C:\IR\disabled-users.csv -NoTypeInformation   # save who you disabled
$targets | Disable-ADAccount -WhatIf    # preview first, then remove -WhatIf
```

To re-enable everyone if something breaks:

```powershell
Import-Csv C:\IR\disabled-users.csv | ForEach-Object { Enable-ADAccount $_.SamAccountName }
```

## D5: Fix Kerberos settings and machine quota

1. Run the **Kerberos fix script**. It turns pre-authentication back on and asks before removing SPNs. Keep SPNs on accounts that a real service uses (IIS, SQL, file server), and give those accounts long passwords (25+ characters) instead.
2. Stop regular users from adding computers to the domain:

```powershell
Set-ADDomain (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}
Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota   # should say 0
```

## D6: DC firewall

Do Hosts H5 on the DC. **Don't block these ports on a DC:** 53 (DNS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP), 445 (SMB), 464 (password changes), 3268/3269 (Global Catalog), and 49152–65535 (dynamic RPC).

## D7: Certificates (CA server)

Copy the `.csr` from the Linux box (WinSCP works), submit it, then copy the `.cer` back:

```powershell
certreq -submit -attrib "CertificateTemplate:WebServer" <machine-ip>.csr <machine-ip>.cer
```

---

# Group Policy

**Owner:** Jacob. Work on the DC, or any machine with Group Policy Management installed.

## G1: Back up and filter GPOs

1. Back up every GPO before changing any:

```powershell
mkdir C:\IR\gpo-backup -Force | Out-Null
Backup-GPO -All -Path C:\IR\gpo-backup
Get-GPOReport -All -ReportType Html -Path C:\IR\All-GPOs.html
```

2. See what's there, newest changes first:

```powershell
Get-GPO -All | Sort ModificationTime -Descending | Select DisplayName, ModificationTime, GpoStatus
```

3. See which GPOs apply to the whole domain and to the DCs:

```powershell
$dn = (Get-ADDomain).DistinguishedName
(Get-GPInheritance -Target $dn).InheritedGpoLinks | Select DisplayName, Enforced, Order
(Get-GPInheritance -Target "OU=Domain Controllers,$dn").InheritedGpoLinks | Select DisplayName, Enforced, Order
```

4. Search GPOs for a setting with the **GPO search script**. For example, `Find-GPOSetting 'Windows Defender'` lists every GPO that touches Defender.

For a deeper review, try [GPOZaurr](https://github.com/EvotecIT/GPOZaurr).

## G2: Fix Defender in Group Policy

**How it usually gets turned off:** a GPO sets one of these.

| Where | Setting |
| --- | --- |
| Administrative Templates → Windows Components → Microsoft Defender Antivirus | **Turn off Microsoft Defender Antivirus** = Enabled |
| Same folder → Real-time Protection | **Turn off real-time protection** = Enabled |
| Same folder → Exclusions | Folders, extensions, or processes added |
| Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` | `DisableAntiSpyware` = 1 |
| Registry: `...\Windows Defender\Real-Time Protection` | `DisableRealtimeMonitoring` = 1 |

**Fix it:**

1. Find the GPO: `Find-GPOSetting 'Windows Defender'`
2. Edit it in `gpmc.msc` and set those settings to **Not Configured**. If the whole GPO is bad, unlink it.
3. Make a team GPO that forces Defender on across the domain:

```powershell
$dn = (Get-ADDomain).DistinguishedName
New-GPO -Name "Team - Defender On" | New-GPLink -Target $dn -Enforced Yes
Set-GPRegistryValue -Name "Team - Defender On" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -ValueName DisableAntiSpyware -Type DWord -Value 0
Set-GPRegistryValue -Name "Team - Defender On" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName DisableRealtimeMonitoring -Type DWord -Value 0
```

4. Push it out: `Invoke-GPUpdate -Computer <name> -Force`, or run `gpupdate /force` on each machine.
5. **Hand off to Vin** to confirm Defender is on everywhere (V2).

## G3: Check the 5 most dangerous GPO settings

| # | Problem | Find it | Fix it |
| --- | --- | --- | --- |
| 1 | **Passwords saved in GPOs** (Group Policy Preferences `cpassword`) | **cpassword check** script | Delete that preference item or GPO, then change that account's password |
| 2 | **Non-admins can edit GPOs**, especially ones linked to DCs | **GPO permissions script** | `Set-GPPermission -Name "<GPO>" -TargetName "<who>" -TargetType Group -PermissionLevel None` |
| 3 | **Defender turned off or excluded** by GPO | `Find-GPOSetting 'Windows Defender'` | G2 above |
| 4 | **GPO adds accounts to local Administrators** (Restricted Groups or Local Users and Groups) | `Find-GPOSetting 'RestrictedGroups\|LocalUsersAndGroups'` | Remove the extra members from the GPO setting |
| 5 | **Startup scripts or scheduled tasks pushed by GPO**, especially from folders non-admins can write to | `Find-GPOSetting 'Scripts\|ScheduledTasks'` | Remove anything you didn't expect. Scripts should only live in SYSVOL |

## G4: Extra settings for the Default Domain Controllers Policy

- **Stop plaintext passwords in memory:** set `UseLogonCredential` to `0` under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`.
- **Turn off Print Spooler on DCs.** DCs don't need it.
- **Reapply policy even if it hasn't changed:** go to Administrative Templates → System → Group Policy and turn on "Process even if the Group Policy objects have not changed" for registry and security policy. That way a local change can't quietly undo your GPO.

## G5: Restrict shutdown

Do this in a GPO linked to the domain so it covers every machine. In `gpmc.msc`:

1. Go to **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment**.
2. Set **Shut down the system** and **Force shutdown from a remote system** to **Administrators** only.
3. Under **Security Options**, set **Shutdown: Allow system to be shut down without having to log on** to **Disabled**.

## G6: Firewall rules from GPOs

Jeff hands these over from H5. Find them with `Find-GPOSetting 'Firewall'`, then edit or remove the bad rules in the GPO under **Computer Configuration → Policies → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security**.

---

# Defender and Scans

**Owner:** Vin

## V1: Enumerate every machine

1. Run the **Enumeration script** on each machine. It saves hostname, OS, IP/MAC, admins, users, programs, roles, shares, listening ports, sessions, and time to `C:\IR\enum-<hostname>.txt`.
2. Once team domain accounts work (Jeff, D2), run it on every domain machine at once from the DC:

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

3. If it keeps turning off, a GPO is doing it. **Tell Jacob** (G2).

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

---

# Injects and Docs

**Owner:** Everyone

## I1: Track every inject

Keep one tracker for the whole competition:

| # | Received | Due | Title | Owner | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | 9:15 | 10:15 | Example: add a user | Jeff | Done |

**Workflow:**

1. Log the inject as soon as it arrives.
2. Assign an owner based on the sections above.
3. Owner does the work and takes screenshots.
4. Someone writes the response, and someone else reads it before it goes out.
5. Submit before the due time, even if it's not perfect.

## I2: Response template

Write for a manager, not a technician. Keep it short and professional. Use the template on GitHub: `cyber-team/<path-to-template>`.


## I3: Team change log

Everyone logs changes in this format. It's what everyone uses to answer injects and what the team uses to undo mistakes.

| Time | Machine | Who | Change | Why |
| --- | --- | --- | --- | --- |
| 9:42 | DC01 | Jeff | Disabled user `bsmith` | Not on keep list |

## I4: Keep this doc current

After each practice, update steps that didn't work and add anything new. Check the git branch name before each competition.

---

# Checklists

**Everyone (Setup)**

- [ ] Scripts downloaded, logging started
- [ ] My account (DA or local admin) tested
- [ ] Inject tracker and change log started

**Jeff (Hosts)**

- [ ] Local accounts disabled, passwords reset
- [ ] Connections and processes checked
- [ ] Scheduled tasks and startup items checked
- [ ] Firewall on, SMBv1 off, inbound rules reviewed

**Jeff (DC and AD)**

- [ ] AD users reviewed
- [ ] Team DA accounts made and tested
- [ ] Admin groups cleaned
- [ ] Employee accounts disabled (after checking with black team)
- [ ] Kerberos fix run, machine quota set to 0

**Jacob (Group Policy)**

- [ ] GPOs backed up and reviewed
- [ ] Defender GPO fixed, "Team - Defender On" linked, Vin told
- [ ] Top 5 dangerous settings checked
- [ ] DC policy extras set
- [ ] Shutdown restricted
- [ ] GPO firewall rules fixed

**Vin (Defender and Scans)**

- [ ] Every machine enumerated, results on team share
- [ ] Defender on everywhere, exclusions cleaned
- [ ] Quick scan run on every machine

---

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

### GPO permissions script (G3)

Lists anyone outside the admin groups who can edit a GPO.

```powershell
$ok = 'Domain Admins','Enterprise Admins','SYSTEM'
Get-GPO -All | ForEach-Object {
    $gpo = $_
    Get-GPPermission -Guid $gpo.Id -All |
        Where-Object { $_.Permission -in 'GpoEdit','GpoEditDeleteModifySecurity' -and $_.Trustee.Name -notin $ok } |
        Select @{n='GPO';e={$gpo.DisplayName}}, @{n='Who';e={$_.Trustee.Name}}, Permission
} | Format-Table -AutoSize
```

---

# Sources

- [Group Policy security audit guide](https://www.decryptiondigest.com/blog/group-policy-security-audit-gpo-hardening-guide): GPO edit rights, scripts on writable paths
- [Varonis: Defender turned off by Group Policy](https://www.varonis.com/blog/windows-defender-turned-off-by-group-policy/): Defender policy settings and registry keys
- [NVISO: common AD misconfigurations](https://blog.nviso.eu/2023/10/26/most-common-active-directory-misconfigurations-and-default-settings-that-put-your-organization-at-risk/): GPO reprocessing, Print Spooler on DCs, machine account quota
- [GroupPolicy.biz: removing cpassword values](https://grouppolicy.biz/2014/05/remove-cpassword-values-active-directory/): passwords in Group Policy Preferences
- [CISA: disable WDigest credential caching](https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0087): WDigest setting
- [Team STIG notes, Windows Server 2019](https://www.notion.so/Overview-of-STIG-Applicability-Windows-Server-2019-948673ead6c44d46b5aae9b594669843?pvs=21)
