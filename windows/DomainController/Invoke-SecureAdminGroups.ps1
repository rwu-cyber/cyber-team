#The Purpose of this script is to remove all members from Domain Admins, Enterprise Admins, Schema Admins, GPCO, DNS Admins and cert Publishers
# Besides the accounts created in Invoke-CreateADAdmins.ps1
#Created by Jacob Barber November 3 2025

Import-Module ActiveDirectory

#defines the name of the groups to clean
$groupsToClean = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Group Policy Creator Owners", "DNSAdmins", "Cert Publishers", 
                    "Enterprise Key Admins", "Key Admins", "Administrators", "RAS and IAS Servers")
#defintes the groups as DN so they are useable
$groupsToCleanDN = $groupsToClean | ForEach-Object { (Get-ADGroup -Filter { Name -eq $_ }).DistinguishedName }
#defines the protected users that should not be removed
$protectedUsers = @("vrat", "Jbar", "KP", "Jared", "Arob", "black_team")
foreach ($groupDN in $groupsToCleanDN) {
    # Get current members of the group
    $members = Get-ADGroupMember -Identity $groupDN | Where-Object { $_.objectClass -eq 'user' }

    foreach ($member in $members) {
        # Check if the member is in the protected users list
        if ($protectedUsers -contains $member.SamAccountName) {
            Write-Host "Skipping protected user $($member.SamAccountName) in group $groupDN"
            continue
        }

        # Remove the member from the group
        Remove-ADGroupMember -Identity $groupDN -Members $member.SamAccountName -Confirm:$false
        Write-Host "Removed user $($member.SamAccountName) from group $groupDN"
    }
}