# Win-SACL-ObjectAccess
Accelerate the process of setting SACLs on folders and registry entries for auditing purpose
## Table of contents
* [General info](#general-info)
* [Usage](#usage)

## General info
ORGINIAL FUNCTIONS FOUND @ https://giuoco.org/security/configure-file-and-registry-auditing-with-powershell/
CREDITS: Aaron Giuoco<br>
Here are two PowerShell functions that can help you configure the SACLs on files and registry keys much faster.
The first function, AddAuditToFile, is used to add auditing to a File or Folder object.
AddAuditToRegKey is the name of the second function. 
	
## Usage
Simply just copy and paste the script into a powershell script.

```
AddAuditToFile “C:\test_dir”
AddAuditToRegKey “HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run”
```

<b>NOTE: The registry hive must be followed with a colon.  So HKLM: as in the example above.</b>
## Notes

These functions are extremely useful in configuring a windows machine for auditing object access in sensitive folders and registry entries for example:

https://www.criticalstart.com/windows-security-event-logs-what-to-monitor/

Run at startup keys: 

    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    AddAuditToRegKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" 
    AddAuditToRegKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 

Startup folder items:  

    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    AddAuditToRegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    AddAuditToRegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

Automatic service startups: 

    AddAuditToRegKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    AddAuditToRegKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices"

Policy-driven startup programs: 

    AddAuditToRegKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

User Logon Program Launch – within “load” value: 

    AddAuditToRegKey "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"

Autocheck launch – within BootExecute value 

    AddAuditToRegKey "HKLM:\System\CurrentControlSet\Control\Session Manager"
