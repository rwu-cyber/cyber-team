# Domain
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
1. Disable Shutdown & Reboot for Non-Admins
  - Modify Group Policy:Restrict ```Shut down the system``` to only essential accounts.
```plaintext
gpedit.msc -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
 ```
2. Restrict Shut down the system to only essential accounts.
```plaintext
Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Shutdown: Allow system to be shut down without having to log on
```
3. Registry key to remove shutdown/restart button on login screen
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ShutdownWithoutLogon /t REG_DWORD /d 0 /f
```
# Dump all Current GPOs
```powershell
Get-GPOReport -All -ReportType Html -Path "C:\Temp\All-GPOs.html"
```

2. GPOZaurr
https://github.com/EvotecIT/GPOZaurr
  - https://evotec.xyz/the-only-command-you-will-ever-need-to-understand-and-fix-your-group-policies-gpo/

# SPN Query for accounts vulnerable to Kerberoasting and ASREPRoastable
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
```powershell
Set-ADDomain -Identity "yourdomain.com" -MachineAccountQuota 0
```
Confirm Changes:
```powershell
Get-ADDomain -Identity "yourdomain.com" | Select-Object MachineAccountQuota
```
