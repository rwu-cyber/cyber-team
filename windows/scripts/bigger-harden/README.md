# BiggerHarden

This guide describes the `BiggerHarden.ps1` script as supplied on October 28, 2026. Run it in an elevated Windows PowerShell session.

## Complete Parameter Reference

| Parameter | Description | Default when omitted |
|---|---|---|
| `-Mode Harden` | Hardens Windows without emergency lateral-movement firewall rules or broad remote-service shutdown. | Not selected |
| `-Mode Lockdown` | Performs emergency hardening, service shutdown, and targeted lateral-movement port blocking. | **Selected** |
| `-Mode Isolate` | Applies Lockdown, then blocks all inbound and outbound traffic, including RDP. | Not selected |
| `-Aggressive` | Adds USB storage blocking, Windows Script Host disabling, VBS/HVCI and Credential Guard requests, and a legacy TLS hardening attempt; switches Defender cloud protection to Zero Tolerance. | Off |
| `-PreserveRDP` | Legacy compatibility; RDP is already enabled and allowed by default in Harden and Lockdown. | Already preserved |
| `-DisableRDP` | Stops/disables TermService and disables RDP. Cannot be combined with `-PreserveRDP`. | Off |
| `-PreserveWinRM` | Keeps WinRM/PowerShell Remoting from being disabled in Lockdown or Isolate. | Disabled in Lockdown/Isolate |
| `-PreserveSMB` | Keeps SMB/file-sharing service running and prevents script-created SMB block rules. | Off on workstations; SMB preserved automatically on Windows Server (including DCs, unless Aggressive changes non-DC server behavior) |
| `-PreservePrinting` | Avoids stopping the Print Spooler in Lockdown or Isolate. | Spooler disabled in Lockdown/Isolate |
| `-PreserveDefenderExclusions` | Does not remove existing Microsoft Defender exclusions. | Exclusions removed in Lockdown/Isolate; already retained in Harden |
| `-ManagementIP <IP>[,<IP>...]` | Scopes new RDP TCP/UDP allow rules to specified source IPs; scopes preserved WinRM and SMB rules as applicable. | RDP allowed from all source IPs |
| `-BlockUSBStorage` | Disables USBSTOR and restricts removable storage. | Off |
| `-DisableWindowsScriptHost` | Disables Windows Script Host, affecting VBScript/JScript through WSH. | Off |
| `-EnableVBSMemoryIntegrity` | Requests VBS, Credential Guard and HVCI, where supported; skipped on domain controllers. Reboot generally needed. | Off |
| `-DisableLegacyTLS` | Invokes legacy SSL/TLS registry hardening. **Current implementation uses incorrect protocol names and needs repair.** | Off |
| `-SkipQuickScan` | Skips the default Defender quick scan. | Quick scan runs |
| `-RunFullScan` | Runs a Defender full scan in addition to the quick scan unless `-SkipQuickScan` is given. | Off |
| `-RunOfflineScan` | Requests a Defender Offline scan at the end, which restarts Windows. Takes precedence over `-Reboot`. | Off |
| `-AirGap` | Disables physical network adapters after hardening and verification; RDP becomes inaccessible. | Off |
| `-Reboot` | Forces a restart at the end unless `-RunOfflineScan` is selected. | No automatic restart |
| `-OutputRoot <Path>` | Root directory for evidence, logs, transcripts, firewall backup, and network recovery instructions. | `C:\ProgramData\EmergencyLockdown` |

**Note:** `-Mode Harden`, `-Mode Lockdown` and `-Mode Isolate` are values of one parameter, not additional parameters. The script has **20 parameters** in total.

## What happens with only `-RWU`

Command:

```powershell
.\BiggerHarden.ps1 -RWU
```

The script runs **Lockdown mode** (not Aggressive and not Isolate), with the following behavior:

1. **Captures evidence first:** exports system, process, network, service, firewall, scheduled task, auditing and Defender information; event logs; registry exports of RDP policy/listener; a firewall backup; and recovery instructions. Saves a dated run folder beneath `C:\ProgramData\EmergencyLockdown` and attempts to start a PowerShell transcript.
2. **Attempts to update Defender:** refreshes Microsoft Defender intelligence where available, then enables core Defender protections, high-plus cloud protection, PUA protection, network protection, Controlled Folder Access and many attack-surface-reduction (ASR) rules, including rules intended to impede malicious Office scripts, credential theft and ransomware. Removes existing Defender exclusions in Lockdown.
3. **Enables and configures Windows Firewall:** all three profiles are enabled, default inbound action is Block and default outbound action is Allow. Windows Firewall logging is enabled. Explicitly blocks LLMNR (UDP 5355), mDNS (UDP 5353), SSDP (UDP 1900), WSD (UDP 3702), inbound RPC endpoint mapper (TCP 135), SSH (TCP 22, inbound/outbound), Telnet (TCP 23, inbound/outbound), WinRM (TCP 5985/5986, inbound/outbound), and SMB/NetBIOS on non-server workstations (TCP 139/445, UDP 137/138, inbound/outbound).
4. **Preserves RDP:** enables the Remote Desktop service, creates inbound TCP and UDP allow rules for the configured listener port (usually 3389) from **any source IP**, requires NLA/TLS with high encryption, sets one RDP connection and one session per user policy, disables session shadowing and removes policy-enforced RDP idle/active/disconnected timeouts. These policies do **not** guarantee protection against session replacement by local administrators or users reconnecting with the same credentials. Domain GPO and existing firewall block rules may override them.
5. **Hardens local accounts and credentials:** disables the built-in Guest account where possible; restricts anonymous access and legacy credential storage, enables LSA protection and WDigest credential safeguards, configures UAC elevation requirements, disables AutoRun, and hardens DLL search behavior.
6. **Hardens protocols and services:** disables LLMNR and NetBIOS over TCP/IP, disables SMBv1, requires SMB signing, rejects insecure SMB guest logons, tightens LDAP/Netlogon policy and print-driver installation, disables TFTP and Telnet optional features, and removes IFEO Debugger accessibility-program hijacks where found. Stops Remote Registry, SSDP, UPnP, WebClient, WinRM, Print Spooler, and several other risky services. Workstation SMB server service is disabled; Windows Server SMB is preserved by default, including on domain controllers.
7. **Strengthens logging:** enables PowerShell script-block, module, and transcription logging, process command-line logging and broad success/failure audit policy, and increases key event log limits.
8. **Maintains updates and scans:** leaves Windows Update available, runs a Defender quick scan when supported, flushes the DNS cache, and displays firewall, RDP, service, port and Defender verification information.
9. **Does not add optional aggressive controls:** no default USB mass-storage ban, Windows Script Host shutdown, VBS/HVCI enablement, or legacy TLS hardening attempt; no full/offline scan; no automatic reboot; no full network isolation or adapter disablement.

## Important operational cautions

- **RDP exposure:** without `-ManagementIP`, RDP is explicitly permitted from any source. On an exposed or shared network this increases attack surface.
- **No Domain-Admin-only session takeover:** the script attempts one concurrent RDP connection, but cannot enforce that only a Domain Admin can displace an existing user.
- **Domain controller disruption:** Lockdown blocks inbound TCP 135 and other network protocols that may be needed for Active Directory/RPC even when it preserves the SMB service. Do not assume it is domain-controller-safe.
- **TLS flag defect:** the TLS hardening function writes policy paths named `SSL 0`, `TLS 0`, `TLS 1`, and `TLS 2`, rather than supported SCHANNEL protocol names such as `TLS 1.0` and `TLS 1.2`. Fix and test before using `-DisableLegacyTLS` or `-Aggressive`.
- **Policy and product restrictions:** some changes may be overridden by domain policy, Tamper Protection, or Windows edition limitations. Controlled Folder Access and ASR rules can break legitimate applications.
- **Recovery:** the script writes `NETWORK-RECOVERY.txt` and a pre-change firewall backup, but restoring network settings does not revert Defender, service, account, or registry hardening.

## Example commands

```powershell
# Default emergency lockdown with RDP preserved
.\BiggerHarden.ps1

# Better for remote administration: restrict inbound RDP to your client IP
.\BiggerHarden.ps1 -ManagementIP 10.0.2.2

# Less disruptive baseline hardening
.\BiggerHarden.ps1 -Mode Harden

# Lockdown while retaining PowerShell remoting, SMB and printing
.\BiggerHarden.ps1 -PreserveWinRM -PreserveSMB -PreservePrinting

# Complete network containment; requires local recovery
.\BiggerHarden.ps1 -Mode Isolate
```
