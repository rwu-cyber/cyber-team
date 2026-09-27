#This Script creates 10 Test accounts in Active Directory and adds them to a bunch of different security groups for testing purposes.
#Created by Jacob Barber November 3 2025
Import-Module ActiveDirectory
# Define the number of test users to create
$numTestUsers = 10
# Define a base username for the test users
$baseUsername = "TestUser"
# Define a strong password for the test users
$testUserPassword = "T3stP@ssw0rd!"
# Define the default Users OU or create a path dynamically
$defaultOU = (Get-ADDomain).UsersContainer  # usually "CN=Users,DC=example,DC=com"

#defines the name of the groups to clean
$AdminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Group Policy Creator Owners", "DNSAdmins", "Cert Publishers", 
                    "Enterprise Key Admins", "Key Admins", "Administrators", "RAS and IAS Servers")
#defintes the groups as DN so they are useable
$AdminGroupsDN = $AdminGroups | ForEach-Object { (Get-ADGroup -Filter { Name -eq $_ }).DistinguishedName }


# Create test users
for ($i = 1; $i -le $numTestUsers; $i++) {
    $username = "$baseUsername$i"
    # Create the user
    New-ADUser `
        -Name $username `
        -SamAccountName $username `
        -UserPrincipalName "$username@$( (Get-ADDomain).DNSRoot )" `
        -GivenName "Test" `
        -Surname "User$i" `
        -DisplayName "$username" `
        -Path $defaultOU `
        -AccountPassword (ConvertTo-SecureString $testUserPassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false `
        -Enabled $true

    Write-Host "Created test user $username"
    $ranint = Get-Random -Minimum 0 -Maximum ($AdminGroupsDN.Count - 1)
    Add-ADGroupMember -Identity $AdminGroupsDN[$ranint] -Members $username
}