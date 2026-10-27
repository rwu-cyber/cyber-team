#Requires -Modules GroupPolicy, ActiveDirectory
# Run as Domain/Enterprise Admin on a DC
param(
    [string]$GpoName = "Restrict-Shutdown",
    [switch]$IncludeLocalAdmins   # adds BUILTIN\Administrators; leave off for strictest lockdown
)

$domain  = Get-ADDomain
$forest  = Get-ADForest
$rootSid = (Get-ADDomain $forest.RootDomain).DomainSID.Value
$eaSid   = "$rootSid-519"                       # Enterprise Admins
$daSid   = "$($domain.DomainSID.Value)-512"     # Domain Admins (safety net if EA isn't in this domain)

$sids = @("*$eaSid", "*$daSid")
if ($IncludeLocalAdmins) { $sids += "*S-1-5-32-544" }
$sidList = $sids -join ","

# 1. Create GPO (or reuse)
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $GpoName }
$guid = "{$($gpo.Id.ToString().ToUpper())}"

# 2. Write GptTmpl.inf (must be UTF-16 LE)
$secEditDir = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$guid\Machine\Microsoft\Windows NT\SecEdit"
New-Item -ItemType Directory -Path $secEditDir -Force | Out-Null

@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeShutdownPrivilege = $sidList
SeRemoteShutdownPrivilege = $sidList
"@ | Out-File -FilePath "$secEditDir\GptTmpl.inf" -Encoding Unicode -Force

# 3. Register the Security CSE + bump version so clients process it
$gpoDN  = "CN=$guid,CN=Policies,CN=System,$($domain.DistinguishedName)"
$adObj  = Get-ADObject $gpoDN -Properties versionNumber, gPCMachineExtensionNames
$newVer = [int]$adObj.versionNumber + 1          # low 16 bits = computer version
$cse    = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
$ext    = $adObj.gPCMachineExtensionNames
if ($ext -notlike "*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*") { $ext = "$ext$cse" }
Set-ADObject $gpoDN -Replace @{ versionNumber = $newVer; gPCMachineExtensionNames = $ext }

$ini = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$guid\GPT.INI"
(Get-Content $ini) -replace 'Version=\d+', "Version=$newVer" | Set-Content $ini

# 4. Link to domain root AND Domain Controllers OU (the DC OU has its own
#    shutdown right in Default Domain Controllers Policy that would override the root link)
New-GPLink -Name $GpoName -Target $domain.DistinguishedName -Enforced Yes -ErrorAction SilentlyContinue | Out-Null
New-GPLink -Name $GpoName -Target "OU=Domain Controllers,$($domain.DistinguishedName)" -Enforced Yes -Order 1 -ErrorAction SilentlyContinue | Out-Null

# 5. Push it out
Get-ADComputer -Filter * | ForEach-Object {
    Invoke-GPUpdate -Computer $_.Name -Force -RandomDelayInMinutes 0 -ErrorAction SilentlyContinue
}