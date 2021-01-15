---
title: Splitting files by line or bytes with python
published: true
layout: post
tags:
 - defsec
---

**GitHub Repository**: [https://github.com/gh0x0st/TheButcher](https://github.com/gh0x0st/TheButcher)

TheButcher is a utility that is used to split files into specified byte sized chunks or line-by-line derivatives. This can be used when working on bypassing anti-virus file signatures by helping you find the chunks that make up the signature. 

Depending on the anti-virus solution, a binary may be identified through its hash, which is trivial to change, or by a series of other characters that exist in the file itself that are used to build the signature. Sometimes multiple signatures exist for the same file making it more difficult to evade. 

## Use Case 

If you're working on a red team engagement you may eventually have to overcome challenges such as the client's anti-virus. Let's say you have the ability to drop nc.exe onto a machine, the last thing you want is for the anti-virus to block your file or set off alarms. Using the file splitting method, it can help you narrow down where in the file the signatures exist giving you an opportunity to change them to evade the av. This strategy is a matter of trial of error but to keep it simple, we'll split it by 25000 bytes since the file is 60000 bytes. 

```bash
root@kali:~/Desktop# wc -c nc.exe
59392 nc.exe
root@kali:~/Desktop# python thebutcher.py --target nc.exe --split 25000

 _______ _          ____        _       _
|__   __| |        |  _ \      | |     | |
   | |  | |__   ___| |_) |_   _| |_ ___| |__   ___ _ __
   | |  | '_ \ / _ \  _ <| | | | __/ __| '_ \ / _ \ '__|
   | |  | | | |  __/ |_) | |_| | || (__| | | |  __/ |
   |_|  |_| |_|\___|____/ \__,_|\__\___|_| |_|\___|_|

        >> File Splitting Utility
        >> https://www.github.com/gh0x0st
    
[*] Splitting /root/Desktop/nc.exe by 25000 bytes
[*] Derived 3 file(s) from /root/Desktop/nc.exe in /root/Desktop
```

When we scan the original file it's pretty much going to be an instant-bust; this is our control. After scanning each of the chunks, we see that there are detections in the first 25000 bytes of the file only. This tells us there are valid signatures somewhere in the first 25000 bytes of the original nc.exe file and the rest of the file is arbitrary. You would keep repeating these steps, or even in smaller chunks to narrow down the location of the signatures.

After you find the location of the signature(s) and depending on the anti-virus you're up against, it could be very simple, or very complicated to modify the contents enough to bypass the signatures. You could be looking at changing up a few strings, or you may need to go the assembly route and change up instructions. With each change you make, you could very well bypass the anti-virus, but you risk  corrupting or breaking needed functionality. Those techniques I'll leave for the next commit.

### Original File
![Alt text](https://github.com/gh0x0st/TheButcher/blob/master/Screenshots/split_0.PNG?raw=true "Original Detections")

### Split File 1
![Alt text](https://github.com/gh0x0st/TheButcher/blob/master/Screenshots/split_1.PNG?raw=true "Split 1")

### Split File 2
![Alt text](https://github.com/gh0x0st/TheButcher/blob/master/Screenshots/split_2.PNG?raw=true "Split 2")

### Split File 3
![Alt text](https://github.com/gh0x0st/TheButcher/blob/master/Screenshots/split_3.PNG?raw=true "Split 3")

## Requirements:
This Python tool was coded and built on the lastest version of Kali Linux and Python 2.x but was tested and works on the Python 3.x interpreter.

```bash
root@kali:~# uname -a && python --version && python3 --version && cat /etc/*-release
Linux kali 5.2.0-kali3-amd64 #1 SMP Debian 5.2.17-1kali1 (2019-09-27) x86_64 GNU/Linux
Python 2.7.17
Python 3.7.5
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
ID=kali
VERSION="2019.4"
VERSION_ID="2019.4"
VERSION_CODENAME="kali-rolling"
ID_LIKE=debian
ANSI_COLOR="1;31"
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
```

## Usage
```bash
usage: thebutcher.py [-h] [-t TARGET_FILE] [-s [SPLIT]] [-o OUT_DIR] [-q]

A utility to split files into specified byte sized chunks or line-by-line
derivatives.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET_FILE, --target TARGET_FILE
                        Target file to be split
  -s [SPLIT], --split [SPLIT]
                        Amount of bytes to split by. Defaults to line-by-line.
  -o OUT_DIR, --output OUT_DIR
                        Output directory for file chunks
  -q, --quiet           Does not print the banner

```
## Examples:

**Split by line:**
```bash        
python thebutcher.py -t nc.exe --split
```
 
 **Split by x bytes:**
 
```bash
python thebutcher.py -t nc.exe --split 100 -o /root/nc_split
```
