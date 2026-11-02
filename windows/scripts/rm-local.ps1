#Requires -RunAsAdministrator
# Remove all local accounts and disable those that cannot be removed
Get-LocalUser | ForEach-Object {

    $User = $_
    Write-Host "Removing local account: $($User.Name)"
    try {
        Remove-LocalUser -SID $User.SID -ErrorAction Stop
        Write-Host "Successfully removed $($User.Name)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to remove $($User.Name). Attempting to disable..."

        try {
            Disable-LocalUser -SID $User.SID -ErrorAction Stop
            Write-Host "Successfully disabled $($User.Name)" -ForegroundColor Yellow
        }
        catch {
            Write-Warning "Failed to disable $($User.Name): $($_.Exception.Message)"
        }
    }
}


Write-Host "`nRemaining Local Accounts:" -ForegroundColor Cyan
Get-LocalUser | Select-Object Name, Enabled, SID