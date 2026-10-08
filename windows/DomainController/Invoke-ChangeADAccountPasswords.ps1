# Import the Active Directory module
Import-Module ActiveDirectory

# List of users to exclude from password reset
$excludeUsers = @("black_team", "vrat", "Jbar", "KP", "Jared", "Arob")  # add any usernames you want to skip

# Get all enabled AD users
$users = Get-ADUser -Filter {Enabled -eq $true} -Properties SamAccountName

# Loop through each user and reset their password
foreach ($user in $users) {
    # Skip users in the exclusion list
    if ($excludeUsers -contains $user.SamAccountName) {
        Write-Host "Skipping password reset for $($user.SamAccountName)"
        continue
    }

    # Generate a strong random password (adjust length and complexity as needed)
    $newPassword = -join ((33..126) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

    # Convert the new password to a secure string
    $securePassword = ConvertTo-SecureString -AsPlainText $newPassword -Force

    # Set the new password and force password change at next logon
    Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset
    Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true
    #disable the account
    Disable-ADAccount -Identity $user.SamAccountName

    Write-Host "Password reset for $($user.SamAccountName). User must change password at next logon."
}
# End of script