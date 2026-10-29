#Requires -Version 5.1
#Requires -RunAsAdministrator
param(
    [string]$Manager,
    [string]$Version,
    [string]$PasswordFile,
    [switch]$Yes,
    [switch]$NoFirewall
)
# new agents only, using the same defaults as the linux script
$ErrorActionPreference = 'Stop'
$work = $null
$password = ''
$log = Join-Path $env:ProgramData 'wazuh-agent-install.log'
try {
    $programFiles = ${env:ProgramFiles(x86)}
    if (!$programFiles) { $programFiles = $env:ProgramFiles }
    $agent = Join-Path $programFiles 'ossec-agent'
    if ((Get-Service WazuhSvc -ErrorAction SilentlyContinue) -or (Test-Path "$agent\ossec.conf")) {
        throw 'Wazuh is already installed or configured.'
    }
    if (!$Manager) {
        if ($Yes) { throw 'Supply -Manager for unattended installs.' }
        $Manager = Read-Host 'Manager IP/DNS'
    }
    if ($Manager -notmatch '^[A-Za-z0-9:][A-Za-z0-9.:-]*$') { throw 'Invalid manager address.' }
    if ($env:COMPUTERNAME -notmatch '^[A-Za-z0-9_.-]{2,128}$') { throw 'Invalid computer name.' }
    if ($Version -and $Version -notmatch '^4\.[0-9]+\.[0-9]+$') { throw 'Version must be 4.x.y.' }

    # keep the password out of command lines and installer logs
    if ($PasswordFile) {
        $password = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $PasswordFile).Path).TrimEnd([char[]]"`r`n")
        if (!$password -or $password -match '[\r\n]') { throw 'Password file must contain one nonempty line.' }
    } elseif (!$Yes) {
        $secret = Read-Host 'Enrollment password (Enter for none)' -AsSecureString
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
        try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secret.Dispose() }
    }
    if (!$Version) { Write-Host 'Using latest agent; manager must be equally new. Use -Version for older managers.' }
    Write-Host "$env:COMPUTERNAME -> $Manager | TCP 1514/1515 | firewall: $(!$NoFirewall)"
    if (!$Yes -and (Read-Host 'Install and apply these settings? [y/N]') -notmatch '^(y|yes)$') { return }
    $addresses = @([Net.Dns]::GetHostAddresses($Manager) | ForEach-Object { $_.IPAddressToString } | Sort-Object -Unique)
    if (!$addresses.Count) { throw 'Cannot resolve manager address.' }

    # use the official download and reject unsigned or unexpected packages
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (!$Version) {
        $release = Invoke-RestMethod 'https://api.github.com/repos/wazuh/wazuh/releases/latest' -TimeoutSec 30
        $Version = $release.tag_name -replace '^v', ''
        if ($Version -notmatch '^4\.[0-9]+\.[0-9]+$') { throw 'Could not find a stable Wazuh 4.x release.' }
    }
    $work = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $work | Out-Null
    $msi = Join-Path $work 'wazuh-agent.msi'
    Write-Host "Installing Wazuh agent $Version..."
    Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi" -OutFile $msi -UseBasicParsing -TimeoutSec 120
    $signature = Get-AuthenticodeSignature -FilePath $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '\bWazuh\b') {
        throw 'The MSI does not have a valid Wazuh signature.'
    }
    $arguments = "/i `"$msi`" /qn /norestart /L*v `"$log`" WAZUH_MANAGER=`"$Manager`" WAZUH_REGISTRATION_SERVER=`"$Manager`" WAZUH_AGENT_NAME=`"$env:COMPUTERNAME`""
    $process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) { throw "MSI failed ($($process.ExitCode)). See $log" }
    if ($process.ExitCode -eq 3010) { Write-Warning 'Windows requested a reboot.' }
    if (!(Test-Path "$agent\ossec.conf")) { throw "Agent configuration not found in $agent" }
    $service = Get-Service WazuhSvc
    if ($service.Status -ne 'Stopped') { Stop-Service WazuhSvc }

    if ($password) {
        # only system and administrators should be able to read this file
        $passwordPath = Join-Path $agent 'authd.pass'
        $acl = [System.Security.AccessControl.FileSecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
            $identity = [System.Security.Principal.SecurityIdentifier]::new($sid)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
        }
        # create the protected file before writing the password
        New-Item -ItemType File -Path $passwordPath -Force | Out-Null
        Set-Acl -LiteralPath $passwordPath -AclObject $acl
        [IO.File]::WriteAllText($passwordPath, $password + "`n", ([System.Text.UTF8Encoding]::new($false)))
        $config = [System.Xml.XmlDocument]::new()
        $config.PreserveWhitespace = $true
        $config.Load("$agent\ossec.conf")
        $client = $config.SelectSingleNode('/ossec_config/client')
        if (!$client) { throw 'Unexpected agent configuration layout.' }
        $enrollment = $client.SelectSingleNode('enrollment')
        if (!$enrollment) { $enrollment = $client.AppendChild($config.CreateElement('enrollment')) }
        foreach ($entry in (@{ enabled = 'yes'; authorization_pass_path = $passwordPath }).GetEnumerator()) {
            $node = $enrollment.SelectSingleNode($entry.Key)
            if (!$node) { $node = $enrollment.AppendChild($config.CreateElement($entry.Key)) }
            $node.InnerText = $entry.Value
        }
        $config.Save("$agent\ossec.conf")
    }
    $password = $null

    # agents connect out, so leave inbound ports alone
    if (!$NoFirewall) {
        $ruleName = 'Wazuh-Agent-Outbound'
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            Set-NetFirewallRule -Name $ruleName -Direction Outbound -Action Allow -Enabled True -Profile Any -Protocol TCP -RemotePort 1514,1515 -RemoteAddress $addresses | Out-Null
        } else {
            New-NetFirewallRule -Name $ruleName -DisplayName 'Wazuh agent outbound' -Direction Outbound -Action Allow -Enabled True -Profile Any -Protocol TCP -RemotePort 1514,1515 -RemoteAddress $addresses | Out-Null
        }
    }
    Set-Service WazuhSvc -StartupType Automatic
    Start-Service WazuhSvc
    # a running service does not mean it has connected to the manager
    for ($n = 0; $n -lt 12; $n++) {
        $state = Get-Content "$agent\wazuh-agent.state" -ErrorAction SilentlyContinue
        if ($state -match '^status=[''"]?connected[''"]?$') {
            Write-Host "Connected: $env:COMPUTERNAME -> $Manager"
            return
        }
        Start-Sleep -Seconds 5
    }
    throw "Installed, but not connected yet. Check $agent\ossec.log and manager ports/password/version."
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    $password = $null
    if ($work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
