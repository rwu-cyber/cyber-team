Windows first 48 2025-2026

 Windows

First steps:

# **How to download scripts from github**
  
- First download git
    
- In PowerShell, make sure you are in the directory where you downloaded git
    
- (Copy and paste the following commands) 
    
```powershell
git clone https://github.com/rwu-cyber/cyber-team.git
```

```powershell
cd cyber-team
```

```powershell
git checkout dev-neccdc-2026
```
  

Then, just right-click the command in file explorer to run the script in Admin PowerShell

**

# First 48

Below is a list of things that should be completed as soon as you log onto a machine

- Get the host name
- Get the IP configuration, including MAC address
- Gather all packages (installed programs) (”Add or remove programs”)
- Get the server OS and version
- If it is a server, get the type and roles and features
- View the active connections, i.e., SSH, TCP, and RDP
- Check the system time

## Enumeration

The enumeration command should be run on all machines when you first login


```powershell
Write-host "================================================"-ForegroundColor Blue
write-host "Hostname:" -ForegroundColor Green
Write-host "================================================"-ForegroundColor Blue
$env:COMPUTERNAME
write-host ""

Write-host "================================================"-ForegroundColor Blue
Write-host "Administrators:"-ForegroundColor Green
Write-host "================================================"-ForegroundColor Blue
Get-LocalGroupMember -name "Administrators" | Out-Host


Write-host "================================================"-ForegroundColor Blue
write-host "Ip information:"-ForegroundColor Green
Write-host "================================================"-ForegroundColor Blue
ipconfig /all | Out-Host


Write-host "================================================"-ForegroundColor Blue
write-host "Downloaded programs:"-ForegroundColor Green
Write-host "================================================"-ForegroundColor Blue
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize


Write-host "================================================"-ForegroundColor Blue
write-host "Capabilities:"-ForegroundColor Green
Write-host "================================================"-ForegroundColor Blue
Get-WindowsCapability -Online | Where-Object State -eq 'Installed'

```





### IP Address, Host Name, and MAC address

- `$env:COMPUTERNAME` → Host name
- `ipconfig`→ IP address information, MAC address

### General

- `Get-Package | Select-Object Name, Version, ProviderName` → Getting all programs for Server 2016 - 2022
- `Get-CimInstance -ClassName Win32_Product | Select-Object Name, Vendor, Version` → Getting all programs for Server 2012
- `(Get-WmiObject Win32_OperatingSystem).Caption` → Get server version and OS
- `Get-windowsFeature | Where-Object { $_.InstallState -eq "Installed"} | Select-Object -ExpandProperty DisplayName` → Getting installed Windows features
- `Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"} | Select-Object -ExpandProperty Name` → Getting installed Windows capabilities
- `Get-FileShare | Select-Object -ExpandProperty Name` → Getting file shares

### Connections

- `Get-NetTCPConnection | Where-Object { $_.State -eq "Listen"} | Select-Object LocalPort` → Getting local listening ports
- `Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshd.exe'" | Get-CimAssociatedInstance -Association Win32_SessionProcess | Get-CimAssociatedInstance -Association Win32_LoggedOnUser | Where-Object {$_.Name -ne 'SYSTEM'}` → finding currently active SSH sessions
- `quser /server:<server-name>`  OR `quser` - Find certain connections
- `logoff <id>` Logoff a particular session discovered in quser

### Local Accounts

- `Get-CimInstance -ClassName Win32_UserAccount` → Getting local accounts on Windows 7, Server 2012
- `Get-LocalUser | Select-Object Name, Enabled, Description` → Getting local accounts on Windows 10, Server 2016 - 2022

### Time

`Net Time` → Checking which server the time is coming from

`Net Time \\hackmepower.local /SET /YES` → This command sgetetsNe the time with that of the domain

## Remediation

### Resetting a local user password

```powershell
#Code skeleton
Set-LocalUser -Name <User Account Name> -Password (ConvertTo-SecureString -AsPlainText "<Your Password>" -Force)

#Code with real example
Set-LocalUser -Name MrHappyFace -Password (ConvertTo-SecureString -AsPlainText "password1234!@#$" -Force)

# Notes on the above code
Ensure you replace the text inside the carats and the carat characters themselves. The carats are just placeholders
```

## Disable and remove PowerShell history

```powershell
del "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" # Delete current file

Set-Content -Path $Profile -Value "Set-PSReadlineOption -HistorySaveStyle SaveNothing" # Disable saving history

```

# Certificates

# Web Server Configuration

```bash
# Find running service 
service apache2 status
# Install openssl 
sudo apt-get install openssl
# Set up cert 
mkdir ~/certs
cd ~/certs
openssl genrsa -out <name>.key 2048
openssl req -new -sha256 -key <name>.key -out <name>.csr

```

# CA Configuration

Copy the .csr file from Linux to Windows (I recommend WinSCP for this)

```powershell
# Req CA 
certreq -submit -attrib "CertificateTemplate:WebServer" <machine-ip>.csr <machine-ip>.cer
```

[Overview of STIG Applicability Windows Server 2019](https://www.notion.so/Overview-of-STIG-Applicability-Windows-Server-2019-948673ead6c44d46b5aae9b594669843?pvs=21)

ossec-agent 

- ossec.conf



# Domain

[](https://github.com/rwu-cyber/cyber-team/blob/dev-neccdc-2026/WindowsFirst48DC.md#domain)

1. **create new domain admin**
2. **Add domain admins to protected users**
3. Machine Account Quota, Kerberoastable, Asreproastable, set long ass passwords on DA accounts.

```powershell
# Individually maybe not this line
Add-ADGroupMember -Identity "Protected Users" -Members "Domain Admins"
```

Kick everyone but yourself and blackteam out of the following:

- Domain admins
- Enterprise admins
- Schema admins
- Group Policy Creator Owners
- DNS Admins
- Cert Publishers

2. Idk

- Enterprise Key Admins
- Key Admins
- RAS and IAS Servers (computes, remote access services?)

# Potentially make it harder to get restart cycled

[](https://github.com/rwu-cyber/cyber-team/blob/dev-neccdc-2026/WindowsFirst48DC.md#potentially-make-it-harder-to-get-restart-cycled)

1. Disable Shutdown & Reboot for Non-Admins

- Modify Group Policy:Restrict `Shut down the system` to only essential accounts.

```
gpedit.msc -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
```

2. Restrict Shut down the system to only essential accounts.

```
Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Shutdown: Allow system to be shut down without having to log on
```

3. Registry key to remove shutdown/restart button on login screen

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ShutdownWithoutLogon /t REG_DWORD /d 0 /f
```

# Dump all Current GPOs

[](https://github.com/rwu-cyber/cyber-team/blob/dev-neccdc-2026/WindowsFirst48DC.md#dump-all-current-gpos)

```powershell
Get-GPOReport -All -ReportType Html -Path "C:\Temp\All-GPOs.html"
```

2. GPOZaurr [https://github.com/EvotecIT/GPOZaurr](https://github.com/EvotecIT/GPOZaurr)

- [https://evotec.xyz/the-only-command-you-will-ever-need-to-understand-and-fix-your-group-policies-gpo/](https://evotec.xyz/the-only-command-you-will-ever-need-to-understand-and-fix-your-group-policies-gpo/)

# SPN Query for accounts vulnerable to Kerberoasting and ASREPRoastable

[](https://github.com/rwu-cyber/cyber-team/blob/dev-neccdc-2026/WindowsFirst48DC.md#spn-query-for-accounts-vulnerable-to-kerberoasting-and-asreproastable)

```powershell
Import-Module ActiveDirectory

# Find both Kerberoastable and ASREPRoastable accounts
Get-ADUser -Filter * -Properties ServicePrincipalName, DoesNotRequirePreAuth | 
Where-Object { $_.ServicePrincipalName -or $_.DoesNotRequirePreAuth -eq $true } |
Select-Object Name, SamAccountName, ServicePrincipalName, DoesNotRequirePreAuth
```

```powershell
Import-Module ActiveDirectory

# Get all vulnerable accounts (Kerberoastable and ASREPRoastable)
$VulnerableAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName, DoesNotRequirePreAuth | 
    Where-Object { $_.ServicePrincipalName -or $_.DoesNotRequirePreAuth -eq $true }

foreach ($Account in $VulnerableAccounts) {
    Write-Host "Fixing account: $($Account.SamAccountName)" -ForegroundColor Yellow

    # Fix ASREPRoastable accounts by disabling "DoesNotRequirePreAuth"
    if ($Account.DoesNotRequirePreAuth -eq $true) {
        Set-ADUser -Identity $Account.SamAccountName -DoesNotRequirePreAuth $false
        Write-Host " -> Disabled 'DoesNotRequirePreAuth' for $($Account.SamAccountName)" -ForegroundColor Green
    }

    # Fix Kerberoastable accounts by removing SPNs (if not needed) | Regular user accounts shouldn't need but if an account is running a service like IIS, SQL Server, or a File Server it's needed.
    if ($Account.ServicePrincipalName) {
        Write-Host " -> Checking SPNs for $($Account.SamAccountName): $($Account.ServicePrincipalName)"
        
        # Ask the user before removing SPNs
        $confirmation = Read-Host "Remove all SPNs for $($Account.SamAccountName)? (Y/N)"
        if ($confirmation -match "^[Yy]$") {
            Set-ADUser -Identity $Account.SamAccountName -Clear ServicePrincipalName
            Write-Host " -> Removed SPNs from $($Account.SamAccountName)" -ForegroundColor Green
        } else {
            Write-Host " -> Skipped SPN removal for $($Account.SamAccountName)" -ForegroundColor Red
        }
    }

    # Enforce AES encryption (Optional, but recommended)
    Set-ADUser -Identity $Account.SamAccountName -Replace @{msDS-SupportedEncryptionTypes=24}
    Write-Host " -> Enforced AES encryption for $($Account.SamAccountName)" -ForegroundColor Green
}

Write-Host "Fixing process completed!" -ForegroundColor Cyan

```

# Set Machine Account Quota to 0

[](https://github.com/rwu-cyber/cyber-team/blob/dev-neccdc-2026/WindowsFirst48DC.md#set-machine-account-quota-to-0)

```powershell
Set-ADDomain -Identity "yourdomain.com" -MachineAccountQuota 0
```

Confirm Changes:

```powershell
Get-ADDomain -Identity "yourdomain.com" | Select-Object MachineAccountQuota
```