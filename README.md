# PowerShell & Windows System Enumeration Notes

Structured reference for enumerating and understanding Windows systems using both legacy CMD and modern PowerShell (WMI/CIM).

Focus: system introspection, privilege awareness, and environment analysis for cybersecurity use cases.

---

## 🧠 Approach

Two perspectives:

- **CMD (Legacy)** → quick, widely available
- **PowerShell (Modern)** → deeper, structured, scriptable

---

# 🖥️ 1. System Identification

## Windows Version

**CMD**
```bash
ver
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

PowerShell

(Get-CimInstance Win32_OperatingSystem).Caption
(Get-CimInstance Win32_OperatingSystem).Version
NT Kernel Version

CMD

ver

PowerShell

[System.Environment]::OSVersion.Version
(Get-CimInstance Win32_OperatingSystem).Version
🌐 2. Environment & Context
Environment Variables

CMD

set

PowerShell

Get-ChildItem Env:
Current User

CMD

whoami
echo %USERNAME%

PowerShell

whoami
$env:USERNAME
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
🔐 3. Privileges & Group Membership
Groups

CMD

whoami /groups
net user %USERNAME%

PowerShell

whoami /groups
Get-LocalGroupMember -Group "Administrators"
Privileges
whoami /priv
📦 4. Installed Software
CMD (Legacy)
wmic product get name,version

⚠️ Slow and unreliable in modern systems.

PowerShell (Preferred)
Get-CimInstance Win32_Product | Select Name, Version

Better method (registry-based):

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select DisplayName, DisplayVersion, Publisher, InstallDate
⚙️ 5. Processes & Services
CMD
tasklist
net start
sc query
PowerShell
Get-Process
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-CimInstance Win32_Process
🌐 6. Network Information
CMD
ipconfig /all
netstat -ano
PowerShell
Get-NetIPAddress
Get-NetIPConfiguration
Get-NetTCPConnection
🧩 7. Active Directory Context
Domain Info
(Get-CimInstance Win32_ComputerSystem).Domain
Domain Controllers
nltest /dclist:domain.local
AD User Info (RSAT Required)
Get-ADUser $env:USERNAME -Properties *
🛰️ 8. WMI vs CIM
Key Difference
Get-WmiObject → legacy (DCOM-based)
Get-CimInstance → modern (WSMan-based, remote-friendly)
Common Classes
Win32_OperatingSystem
Win32_ComputerSystem
Win32_LogicalDisk
Win32_NetworkAdapterConfiguration
Win32_UserAccount
Win32_Group
Win32_Process
Win32_Service
🧠 9. Learning Focus

Core areas to understand:

OS & kernel version
Identity & privileges
Installed software
Running processes & services
Network configuration
🚀 10. Remote Enumeration
$sess = New-CimSession -ComputerName TARGET
Get-CimInstance Win32_OperatingSystem -CimSession $sess



