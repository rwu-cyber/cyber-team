#Create a PowerShell script that disables and changes the password of every local Windows account on a non-domain controller Windows machine.

# Get a list of all local user accounts
$localUsers = Get-LocalUser

foreach ($user in $localUsers) {
    # Disable the user account
    Disable-LocalUser -Name $user.Name

    # Change the password
    $newPassword = ConvertTo-SecureString "NewP@ssw0rd" -AsPlainText -Force
    Set-LocalUser -Name $user.Name -Password $newPassword

    Write-Host "Disabled account $($user.Name) and changed password."
}
