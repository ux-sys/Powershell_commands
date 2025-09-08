# 🖥️ Active Directory Query Cheatsheet

A practical cheatsheet for querying and exploring AD from a **helpdesk or local admin** perspective.  
Commands are grouped into **Local (always works)** vs **Domain (needs AD access/RSAT)**.  

---

## 🔹 Basics — Works Anywhere
##powershell
whoami                     # current user
whoami /groups             # groups you belong to
whoami /priv               # privileges
echo %USERDOMAIN%          # your domain (PC name if not domain-joined)
echo %LOGONSERVER%         # DC that authenticated you
net config workstation     # domain/workstation info
🔹 Users
powershell
Copy code
net user                   # local users
net user Administrator     # details for specific local user

# Domain (AD required)
net user Bob /domain       # AD user info
🔹 Groups
powershell
Copy code
net localgroup             # local groups
net localgroup Administrators   # members of local admin group

# Domain (AD required)
net group /domain               # list AD groups
net group "Domain Admins" /domain   # see DA members
🔹 Computers
powershell
Copy code
hostname                   # local machine name
systeminfo                 # OS & domain info

# Domain (RSAT required)
dsquery computer -limit 10
🔹 Organizational Units (OUs)
powershell
Copy code
# RSAT required
dsquery ou -limit 0

# PowerShell AD module required
Get-ADOrganizationalUnit -Filter * | Select Name, DistinguishedName
🔹 Domain & Forest
powershell
Copy code
# Domain only
nltest /dsgetdc:domain.local   # get DC info
nltest /domain_trusts          # domain trusts
netdom query fsmo              # FSMO role holders
🔹 Group Policy (GP)
powershell
Copy code
gpresult /r                    # applied GPOs (text)
gpresult /h gpo.html           # export GPO report (HTML)
🔹 Domain Controllers (DCs)
powershell
Copy code
nltest /dclist:domain.local
🔹 Service Accounts
powershell
Copy code
# Common pattern — look for "svc" accounts
net user /domain | findstr svc
Copy code
# Common pattern — look for "svc" accounts
net user /domain | findstr svc










# 🥖 Local Breadcrumbs Cheatsheet (for Pentest Recon)

These are safe **query-only commands** you can run with **local admin** (no domain creds needed).  
They help you spot Active Directory clues, PXE hints, patch levels, and potential recon breadcrumbs.  

---

## 🔎 1. Domain / AD Awareness
Check if the host is domain-joined and where it talks:
```powershell
# Domain membership
(Get-WmiObject Win32_ComputerSystem).Domain

# Which DC this system uses
nltest /dsgetdc:yourdomain.local

# Trusted domains (if any)
nltest /trusted_domains

# Domain role of this system
systeminfo | findstr /B /C:"Domain"
🖥 2. Local Users & Groups
See who has local admin rights (often cached Domain Admins show up here):

powershell
Copy code
# Local admins group
net localgroup administrators

# Local users
net user
📜 3. Cached Credentials & Secrets
Check if domain logins have been cached locally:

powershell
Copy code
# Cached logons (hashes only, no clear-text)
reg query "HKLM\SECURITY\Cache"
Presence = this box had domain users log in before → possible lateral move.

🌐 4. Network & PXE Clues
powershell
Copy code
# DHCP info (PXE/TFTP server may show in options 66/67)
ipconfig /all

# Network adapter configs
Get-WmiObject Win32_NetworkAdapterConfiguration | `
  Where-Object {$_.IPEnabled -eq $true} | `
  Select Description,IPAddress,DefaultIPGateway,DHCPServer
🩹 5. Patch Level (Outdated vs “Chunky” Cumulative Patches)
Installed patches:
powershell
Copy code
wmic qfe list brief /format:table
# OR
Get-HotFix | Select-Object Description, HotFixID, InstalledOn
OS build version:
powershell
Copy code
# Windows build info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Registry check
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
👉 If build number is way behind (e.g., 1909 vs 22H2), machine is missing cumulative rollups.
👉 If build is current but missing KBs, it’s just outdated hotfixes.

🔐 6. Service Accounts & Auto-Logon
Look for domain accounts running as services:

powershell
Copy code
# Auto-logon creds (if enabled)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Services running with domain accounts
Get-WmiObject Win32_Service | `
  Where-Object { $_.StartName -like "*\*" } | `
  Select Name, StartName
🗂 7. File System Clues
powershell
Copy code
# Network drive mappings
net use

# Search for config files with creds
dir C:\ /s /b | findstr /i "web.config app.config .ps1 .bat .vbs"
🧭 Why This Matters
Domain + cached creds → AD is active and in play.

Old patch builds → host may be vulnerable to known exploits (EternalBlue, PrintNightmare).

PXE DHCP options → confirms PXE/TFTP infra in use.

Services with DOMAIN\user → possible lateral movement path.










# 🛰️ WMI & CIM Recon Cheatsheet

Quick reference for using **WMI** (`Get-WmiObject`) and **CIM** (`Get-CimInstance`) in PowerShell.  
These are safe **read-only queries** for system & AD breadcrumbs.

---

## 🖥 System Info
```powershell
# Computer system details (domain, manufacturer, model)
Get-WmiObject Win32_ComputerSystem
Get-CimInstance Win32_ComputerSystem

# Operating system details
Get-WmiObject Win32_OperatingSystem
Get-CimInstance Win32_OperatingSystem
🌐 Networking
powershell
Copy code
# IPs, DHCP, and DNS servers
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
🩹 Patches & Hotfixes
powershell
Copy code
# Installed updates (KBs)
Get-WmiObject Win32_QuickFixEngineering
Get-CimInstance Win32_QuickFixEngineering
🔐 Users & Logins
powershell
Copy code
# Local user accounts
Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
Get-CimInstance Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }

# Who is logged in
Get-WmiObject Win32_LoggedOnUser
Get-CimInstance Win32_LoggedOnUser
⚙️ Services & Processes
powershell
Copy code
# Running services
Get-WmiObject Win32_Service | Select Name, StartName, State
Get-CimInstance Win32_Service | Select Name, StartName, State

# Running processes
Get-WmiObject Win32_Process | Select ProcessId, Name, ExecutablePath
Get-CimInstance Win32_Process | Select ProcessId, Name, ExecutablePath
💾 Storage
powershell
Copy code
# Logical drives
Get-WmiObject Win32_LogicalDisk
Get-CimInstance Win32_LogicalDisk

# Physical disks
Get-WmiObject Win32_DiskDrive
Get-CimInstance Win32_DiskDrive
📌 Notes
Get-WmiObject is older; Get-CimInstance is newer & faster.

Both usually need local admin to see services, processes, and some configs.

Queries are read-only (safe for recon).

Great for breadcrumb hunting:

Services using DOMAIN\account

Old patches

DHCP/DNS pointing to AD infra

yaml
Copy code






---
I want to learn more about wmi cim to query windows and learn about local settings and eventually AD.
So here seems to be the important stuff:
Windows version
NT kernel version
environment variables 
what user I am
what groups I belong to on the local machine and what privileges they grant and what's normal

what important software is installed
process & services running
network info


I know  a few commands for these, but I want the old cmd way and the new powershell way
ChatGPT said:

Great goals — understanding WMI (Windows Management Instrumentation) and CIM (Common Information Model) is key to mastering system introspection in Windows, both locally and across domains (including AD environments).

You're right to split this into:

The "old way": Using classic CMD tools (systeminfo, net, tasklist, etc.)

The "new way": Using PowerShell with WMI (via Get-WmiObject, now deprecated) and CIM (Get-CimInstance, the modern preferred way)

Let’s break your goals down into a task list, with both CMD and PowerShell methods shown for each.

✅ 1. Windows Version

CMD:

ver
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"


PowerShell:

(Get-CimInstance -ClassName Win32_OperatingSystem).Caption
(Get-CimInstance -ClassName Win32_OperatingSystem).Version

✅ 2. NT Kernel Version

CMD:

ver


PowerShell:

[System.Environment]::OSVersion.Version
(Get-CimInstance -ClassName Win32_OperatingSystem).Version

✅ 3. Environment Variables

CMD:

set


PowerShell:

Get-ChildItem Env:

✅ 4. Current User Info

CMD:

whoami
echo %USERNAME%


PowerShell:

whoami
$env:USERNAME
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name

✅ 5. Group Membership & Privileges

CMD:

whoami /groups
net user %USERNAME%


PowerShell:

whoami /groups  # Still works here
(Get-LocalUser -Name $env:USERNAME).PrincipalSource
Get-LocalGroupMember -Group "Administrators"


To see privileges (like SeDebugPrivilege, etc.):

whoami /priv

✅ 6. Installed Software

CMD:

wmic product get name,version


⚠️ This is slow and unreliable in modern Windows. Better to use PowerShell.

PowerShell:

Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version
# Better: Use the registry for more accurate results:
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

✅ 7. Running Processes & Services

CMD:

tasklist
net start
sc query


PowerShell:

Get-Process
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-CimInstance -ClassName Win32_Process

✅ 8. Network Information

CMD:

ipconfig /all
netstat -ano


PowerShell:

Get-NetIPAddress
Get-NetIPConfiguration
Get-NetTCPConnection

Bonus: Active Directory Context

Once you're in an AD environment:

Get current domain:

(Get-CimInstance Win32_ComputerSystem).Domain


Who is the domain controller:

nltest /dclist:yourdomain.local


AD user info (if RSAT is installed):

Get-ADUser $env:USERNAME -Properties *

🧠 Suggested Learning Path

Understand WMI vs CIM:

Get-WmiObject is older; replaced by Get-CimInstance (which uses WSMan instead of DCOM).

CIM is more firewall-friendly and works remotely better.

Explore Namespaces and Classes:

Most of what you want is in: root\cimv2

Use: Get-CimClass or Get-WmiObject -List to explore

Learn Key WMI/CIM Classes:

Win32_OperatingSystem

Win32_ComputerSystem

Win32_LogicalDisk

Win32_NetworkAdapterConfiguration

Win32_UserAccount

Win32_Group

Win32_Process

Win32_Service

Win32_Product (for installed software)

🚀 Pro Tip: Use CIM Sessions for Remote Queries

Once you're ready:

$sess = New-CimSession -ComputerName REMOTE-PC
Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $sess


Would you like a PowerShell cheat sheet or interactive lab exercises to help practice this hands-on?




