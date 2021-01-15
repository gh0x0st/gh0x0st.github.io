---
title: Validating Sophos Tamper Protection is functioning
published: true
layout: post
tags:
 - defsec
---
![Alt text](https://github.com/gh0x0st/Test-SophosEndpointDefense/blob/master/Screenshots/logo_3.png?raw=true "Logo 3")

**GitHub Repository**: [https://github.com/gh0x0st/Test-SophosEndpointDefense](https://github.com/gh0x0st/Test-SophosEndpointDefense)

# Test-SophosEndpointDefense

Traditionally, as an administrator on a system, you can expect to have the ability to make changes to your system; the same goes to a hacker who has compromised an admin account. When you look for an Endpoint Protection Solution, you need to keep this in mind in the event an account with elevated privileges is compromised. 

With Sophos Central, in order to protect the integrity of their installation, and ultimately your security in the event of a compromise or trigger-happy IT Staff, they have incorporated a component called Sophos Endpoint Defense (SED), which is an extension of Sophos Tamper Protection (STP). 

What this control does is ensure that your Sophos Client stays running unless Sophos Tamper Protection, is disabled from the Administrative Console, or a through a randomly generated (and unique) password for that device is entered. 

__With Tamper Protection enabled, the following are blocked:__

* Stopping services from the Services UI
* Kill services from the Task Manager UI
* Change Service Configuration from the Services UI
* Stop Services / edit service configuration from the command line
* Uninstallation of the Sophos Central Client
* Reinstall of the Sophos Central Client
* Kill processes from the Task Manager UI (desired)
* Delete or modify protected files or folders
* Delete or modify protected registry keys 

## Validation
With any security control, you should always ensure that you are __testing your controls__. You should never assume that they're working as intended; ensure your duties include time to validate these controls on a regular basis. The last position you want to be in is in the middle of a security incident only to find out that something wasn't enabled or working as intended.

## A Programmatic Approach
We can plan a scripted approach into testing this control, we simply need to attempt one of the blocked actions. You need to be careful here. Let's say you test by stopping Sophos Anti-Virus and it works, but you don't have the logic to turn it back on, then you just disable the protection on that server.

To get what we need, while being safe, I'll show how you can test these by either attempting to write a file to Sophos ProgramData folder or see if a named service is set to allow a stop, without actually stopping it. With a file write, it should come back with an access denied if SED is working properly. With the service piece, there is a property we can query called CanStop that will tell us if we have the ability to do so.

_File Write Snippet_
```powershell
Try
{
    [System.IO.FileSystemInfo]$File = New-Item "C:\ProgramData\Sophos\Sophos.txt -ErrorAction Stop
    Remove-Item $File.FullName
    Write-Output 'Not Protected'
}
Catch [System.UnauthorizedAccessException]
{
    Write-Output 'Protected'
}
```

_Service Snippet_
```powershell
If (-not (Get-Service -DisplayName 'Sophos Anti-Virus' -ComputerName SERVER1 -ErrorAction Stop | Select-Object -ExpandProperty CanStop))
{
    [System.String]$Status = 'Protected'
}
Else
{
    [System.String]$Status = 'Not Protected'
}
```

As I've mentioned before, always test your security controls; validate and don't assume. This doesn't mean exhaust your resources from other initiatives, try to add levels of automation where you can that will alert you when you need to follow up. Be informed, be secure!

## Usage
This advanced function can be added to your PowerShell Profile, or dot sourced to run at the command line. This particular script is really intended to run frequently across all the devices you want to protect. 

```powershell
PS C:\> . .\Test-SophosEndpointDefense.ps1
PS C:\> Test-SophosEndpointDefense -ComputerName SERVER1 -CanWrite

System  Status        TestCanWrite TestCanStop
------  ------        ------------ -----------
SERVER1 Protected     True         True   
```

You can easily customize the results to only show the machines that did not report back with a status of protected as well. This could be sent via an email or just exported to a log file.

```powershell
PS C:\> . .\Test-SophosEndpointDefense.ps1
PS C:\> $Live = [DateTime]::Today.AddDays(-7)
PS C:\> $List = Get-ADComputer -Properties LastLogonDate,OperatingSystem -filter {LastLogonDate -gt $Live -and OperatingSystem -like "*Windows*"}
PS C:\> $List | ForEach-Object { Test-SophosEndpointDefense -ComputerName $_ -CanStop | Where-Object {$_.Status -ne 'Protected'}}

System       Status          TestCanWrite TestCanStop
------       ------          ------------ -----------
SERVER1      Service Missing False        True       
SERVER2      Not Protected   False        True       
SERVER3      Access Denied   False        True       
SERVER4      Not Supported   False        True       
```


## Problems running scripts
By default, PowerShell restricts script execution to help protect against script based attacks.  It does this via the _execution policy_.  To validate your system's current policy setting use the `Get-ExecutionPolicy` cmdlet:

~~~powershell
Get-ExecutionPolicy
~~~

If you receive a result of _Restricted_ you'll need to either set a new policy (one of _AllSigned_, _RemoteSigned_ or _Unrestricted_ (*not recommended*)) or bypass the policy for this script.  _AllSigned_ will run any signed script whereas _RemoteSigned_ only requires a script to be signed it if comes from a remote system (downloaded from the Internet or via a file share).  _Unrestricted_ is not recommended as all scripts would be permitted to run, including those from malicious actors.

__Note:__ This script is not signed.

To change your execution policy (adjust the level to suit):

~~~powershell
Set-ExecutionPolicy RemoteSigned
~~~

Alternatively, start a `PowerShell` session (from the run prompt) in execution policy bypass mode, then run script as above:

~~~powershell
powershell –ExecutionPolicy Bypass
~~~

## Resources
* Sophos - https://www.sophos.com
* Sophos Endpoint Defense - https://community.sophos.com/kb/en-us/123654
* System Requirements - https://community.sophos.com/kb/en-us/121636
