# List Windows firewall and defender exclusions

Write-Host "Windows defender exclusions" -ForegroundColor Red
(Get-MpPreference) | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress | Format-List



Write-Host "Firewall exclusions" -ForegroundColor Red
Get-NetFirewallRule -Action Allow -Enabled True | Format-Table Name, DisplayName, Direction, Profile