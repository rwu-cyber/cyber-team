#Create a PowerShell Script that creates an Active Directory domain administrative account for each member of the Windows team.
#This script should take a list of usernames as input and create a new user account in Active Directory with the appropriate permissions.


# Loop through each username and create the user account
# Import the AD module (if not already loaded)
Import-Module ActiveDirectory

# Define the list of usernames

$userInfo = @{
    "vrat" = "TToD8nRbj1QUXorPl67fMXQ5"
    "Jbar" = "pFSn759l5fr6yZwKEdFxOpysxtE!"
    "KP"   = "iS7wjL8hwwmkQKY7q2OQxj0B98ge3G"
    "Jared"= "WYLeOBKL6k1nU8b4m67D0ry5Stt1Sajx7"
    "Arob" = "cPe9dCFRcha79IQ0QgWVmA0uyUMMu899j6oXhWx"
}


# Automatically detect the current domain
$domain = (Get-ADDomain).DNSRoot  # e.g., "example.com"

# Automatically detect the default Users OU or create a path dynamically
$defaultOU = (Get-ADDomain).UsersContainer  # usually "CN=Users,DC=example,DC=com"

# Optionally get the domain's NetBIOS name (for groups like "Domain Admins")
$netbios = (Get-ADDomain).NetBIOSName

foreach ($user in $userInfo.GetEnumerator()) {
    # Build a standard display name
    $username = $user.Key
    $password = $user.Value

    # Create the user
    New-ADUser `
        -Name $username `
        -SamAccountName $username `
        -UserPrincipalName "$username@$domain" `
        -GivenName $username `
        -Surname "User" `
        -DisplayName $username `
        -Path $defaultOU `
        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false `
        -Enabled $true

    # Add the user to the Domain Admins group dynamically
    $domainAdminsDN = (Get-ADGroup -Filter { Name -eq "Domain Admins" }).DistinguishedName

    Add-ADGroupMember -Identity $domainAdminsDN -Members $username

    Write-Host "Created user $username and added to Domain Admins group."

}