#Create a PowerShell Script that creates an Active Directory domain administrative account for each member of the Windows team.
#This script should take a list of usernames as input and create a new user account in Active Directory with the appropriate permissions.


# Loop through each username and create the user account
# Import the AD module (if not already loaded)
Import-Module ActiveDirectory

# Define the list of usernames

$userInfo = @{
    "vrat" = "password123"
    "Jbar" = "securePass!"
    "KP"   = "dgfudifkgrjfvi"
    "Jared"= "dgujbriekrbjked"
    "Arob" = "dfiehfigbdjvifdguf8"
}


# Automatically detect the current domain
$domain = (Get-ADDomain).DNSRoot  # e.g., "example.com"

# Automatically detect the default Users OU or create a path dynamically
$defaultOU = (Get-ADDomain).UsersContainer  # usually "CN=Users,DC=example,DC=com"

# Optionally get the domain's NetBIOS name (for groups like "Domain Admins")
$netbios = (Get-ADDomain).NetBIOSName

foreach ($username in $userInfo.Keys) {
    # Build a standard display name
    $displayName = "$($username.Substring(0,1).ToUpper())$($username.Substring(1))"

    # Create the user
    New-ADUser `
        -Name $userinfo[$username] `
        -SamAccountName $username `
        -UserPrincipalName "$username@$domain" `
        -GivenName $username `
        -Surname "User" `
        -DisplayName $displayName `
        -Path $defaultOU `
        -AccountPassword (ConvertTo-SecureString $userInfo[$username] -AsPlainText -Force) `
        -ChangePasswordAtLogon $false `
        -Enabled $true

    # Add the user to the Domain Admins group dynamically
    $domainAdminsDN = (Get-ADGroup -Filter { Name -eq "Domain Admins" }).DistinguishedName

    Add-ADGroupMember -Identity $domainAdminsDN -Members $username

    Write-Host "Created user $username and added to Domain Admins group."

}
