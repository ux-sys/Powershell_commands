🔴1. Active Directory Cheatsheet
# Active Directory Enumeration Cheatsheet

Practical reference for enumerating Windows and Active Directory environments from a local admin or helpdesk perspective.

Focus: safe, read-only recon techniques used in CTFs, labs, and real-world assessments.

---

## 🔹 1. Initial Access Context (Works Anywhere)

Understand your current identity and environment.

### Identity & Context
```bash
whoami
whoami /groups
whoami /priv
System & Domain Info
echo %USERDOMAIN%
echo %LOGONSERVER%
net config workstation
hostname
systeminfo
🔹 2. Local Enumeration
Users
net user
net user Administrator
Groups
net localgroup
net localgroup Administrators
🔹 3. Domain Enumeration (AD Required)
Users
net user Bob /domain
Groups
net group /domain
net group "Domain Admins" /domain
Computers
dsquery computer -limit 10
Organizational Units
dsquery ou -limit 0
Get-ADOrganizationalUnit -Filter * | Select Name, DistinguishedName
Domain & Forest
nltest /dsgetdc:domain.local
nltest /domain_trusts
netdom query fsmo
Domain Controllers
nltest /dclist:domain.local
🔹 4. Group Policy Enumeration
gpresult /r
gpresult /h gpo.html
🔹 5. Service Account Discovery
net user /domain | findstr svc
🥖 Local Breadcrumb Recon (No Domain Access Required)

Used to identify AD presence, lateral movement paths, and misconfigurations.

🔎 Domain Awareness
(Get-WmiObject Win32_ComputerSystem).Domain
nltest /dsgetdc:yourdomain.local
nltest /trusted_domains
systeminfo | findstr /B /C:"Domain"
🖥 Local Users & Privileges
net localgroup administrators
net user
📜 Cached Credentials
reg query "HKLM\SECURITY\Cache"
🌐 Network & PXE Clues
ipconfig /all
Get-WmiObject Win32_NetworkAdapterConfiguration |
Where-Object {$_.IPEnabled -eq $true} |
Select Description,IPAddress,DefaultIPGateway,DHCPServer
🩹 Patch & System State
wmic qfe list brief /format:table
Get-HotFix | Select Description, HotFixID, InstalledOn
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
🔐 Services & Auto-Logon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

Get-WmiObject Win32_Service |
Where-Object { $_.StartName -like "*\*" } |
Select Name, StartName
🗂 File System Recon
net use
dir C:\ /s /b | findstr /i "web.config app.config .ps1 .bat .vbs"
🧭 Why This Matters
Domain + cached creds → lateral movement potential
Outdated patches → known exploit paths
PXE/DHCP → infrastructure exposure
Services with DOMAIN accounts → privilege escalation vectors
🛰️ WMI & CIM Recon

Modern vs legacy system interrogation.

Key Difference
Get-WmiObject → legacy
Get-CimInstance → modern, faster, remote-friendly
System Info
Get-CimInstance Win32_ComputerSystem
Get-CimInstance Win32_OperatingSystem
Networking
Get-CimInstance Win32_NetworkAdapterConfiguration |
Where-Object {$_.IPEnabled -eq $true}
Patches
Get-CimInstance Win32_QuickFixEngineering
Users & Sessions
Get-CimInstance Win32_UserAccount
Get-CimInstance Win32_LoggedOnUser
Services & Processes
Get-CimInstance Win32_Service
Get-CimInstance Win32_Process
Storage
Get-CimInstance Win32_LogicalDisk
Get-CimInstance Win32_DiskDrive
🎯 Learning Focus

Core areas to understand:

OS version & kernel
Identity & privileges
Installed software
Processes & services
Network configuration


