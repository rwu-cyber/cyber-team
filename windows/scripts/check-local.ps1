# Check for processes
Write-Host "All Processes:" -ForegroundColor Red
Get-Process | Out-GridView


Write-Host "Highlighted Processes:" -ForegroundColor Red
Get-Process | Where-Object {$_.Path} | Select-Object Name, Id, Path, @{Name="Description"; Expression={(Get-Item $_.Path).VersionInfo.FileDescription}}, @{Name="Company"; Expression={(Get-Item $_.Path).VersionInfo.CompanyName}}, @{Name="Elevated"; Expression={$_.Path -ne $null -and (Get-Process -Id $_.Id -IncludeUserName).UserName -match "SYSTEM|Administrator"}} | Format-Table -AutoSize
