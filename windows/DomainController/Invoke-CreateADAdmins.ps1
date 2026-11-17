<#
.SYNOPSIS
    Creates domain administrator accounts for the Windows team with randomly
    generated passwords (nothing hardcoded).

.DESCRIPTION
    Run on a Domain Controller as a Domain Admin. For each username it:
      - skips the account if it already exists (it never resets existing accounts)
      - generates a cryptographically random password
      - creates the user in the default Users container, enabled, and set to
        change password at first logon
      - adds the user to Domain Admins (looked up by well-known SID, so it
        works regardless of language or renamed group)
    Generated passwords are shown once at the end. Optionally save them to a
    locked-down CSV with -ExportPath.

.PARAMETER Usernames
    Accounts to create. Defaults to JBarber, JMcna, Vrat.

.PARAMETER PasswordLength
    Length of generated passwords (minimum 14, default 24).

.PARAMETER ExportPath
    Optional CSV path for the generated credentials. The file is restricted to
    the current user. Delete it once the passwords are handed out.

.EXAMPLE
    .\New-WindowsTeamAdmins.ps1

.EXAMPLE
    .\New-WindowsTeamAdmins.ps1 -Usernames JBarber,JMcna,Vrat -PasswordLength 28 -ExportPath C:\Temp\creds.csv
#>
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [string[]]$Usernames = @('JBarber', 'JMcna', 'Vrat'),
    [ValidateRange(14, 128)]
    [int]$PasswordLength = 24,
    [string]$ExportPath
)

Import-Module ActiveDirectory -ErrorAction Stop

# ---------------------------------------------------------------------------
# Password generation (cryptographically secure, no modulo bias)
# ---------------------------------------------------------------------------
$script:Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

function Get-SecureRandomInt {
    param([int]$Max)   # returns 0 .. Max-1
    $bytes = New-Object byte[] 4
    $limit = [uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$Max)
    do {
        $script:Rng.GetBytes($bytes)
        $n = [BitConverter]::ToUInt32($bytes, 0)
    } while ($n -ge $limit)
    return [int]($n % [uint32]$Max)
}

function New-RandomPassword {
    param([int]$Length = 24)

    # Ambiguous characters (0/O, 1/l/I) are left out so passwords are easy to read out.
    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!@#$%^&*-_=+?'
    )
    $all = $sets -join ''

    # Guarantee at least one character from each set, fill the rest from all sets.
    $chars = New-Object 'System.Collections.Generic.List[char]'
    foreach ($set in $sets) { $chars.Add($set[(Get-SecureRandomInt $set.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[(Get-SecureRandomInt $all.Length)]) }

    # Fisher-Yates shuffle so the guaranteed characters aren't always first.
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-SecureRandomInt ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return -join $chars
}

# ---------------------------------------------------------------------------
# Domain info
# ---------------------------------------------------------------------------
$domainInfo = Get-ADDomain
$domain     = $domainInfo.DNSRoot
$targetOU   = $domainInfo.UsersContainer

# Domain Admins is always RID 512 - look it up by SID rather than by name.
$domainAdmins = Get-ADGroup -Identity ("{0}-512" -f $domainInfo.DomainSID.Value)

# ---------------------------------------------------------------------------
# Create accounts
# ---------------------------------------------------------------------------
$results = foreach ($username in $Usernames) {
    $username = $username.Trim()

    if (Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue) {
        Write-Warning "User '$username' already exists - skipping (password not changed)."
        [pscustomobject]@{ Username = $username; Password = ''; Status = 'Skipped (already exists)' }
        continue
    }

    $plain  = New-RandomPassword -Length $PasswordLength
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force

    try {
        New-ADUser `
            -Name $username `
            -SamAccountName $username `
            -UserPrincipalName "$username@$domain" `
            -DisplayName $username `
            -Path $targetOU `
            -AccountPassword $secure `
            -ChangePasswordAtLogon $true `
            -Enabled $true `
            -ErrorAction Stop

        Add-ADGroupMember -Identity $domainAdmins -Members $username -ErrorAction Stop

        Write-Host "Created '$username' and added to $($domainAdmins.Name)." -ForegroundColor Green
        [pscustomobject]@{ Username = $username; Password = $plain; Status = 'Created' }
    }
    catch {
        Write-Error "Failed to create '$username': $($_.Exception.Message)"
        [pscustomobject]@{ Username = $username; Password = ''; Status = "Failed: $($_.Exception.Message)" }
    }
    finally {
        $plain = $null
        $secure = $null
    }
}

$script:Rng.Dispose()

# ---------------------------------------------------------------------------
# Show / export credentials
# ---------------------------------------------------------------------------
$created = @($results | Where-Object { $_.Status -eq 'Created' })

Write-Host ''
if ($created.Count -gt 0) {
    Write-Host 'Generated credentials (shown once - record them securely now):' -ForegroundColor Yellow
    $created | Format-Table Username, Password -AutoSize

    if ($ExportPath) {
        $created | Select-Object Username, Password | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        # Lock the file down to the current user only.
        & icacls.exe $ExportPath /inheritance:r /grant:r "${env:USERDOMAIN}\${env:USERNAME}:(R,W)" | Out-Null
        Write-Host "Credentials saved to $ExportPath (restricted to your account). Delete it after use." -ForegroundColor Yellow
    }
}

Write-Host 'Summary:' -ForegroundColor Cyan
$results | Select-Object Username, Status | Format-Table -AutoSize

$results = $null
$created = $null