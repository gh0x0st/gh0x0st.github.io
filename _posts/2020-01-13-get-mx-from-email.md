---
title: Grabbing MX records from an email address using bash
published: true
layout: post
tags:
 - offsec
---

**GitHub Repository**: [https://github.com/gh0x0st/MXEnum](https://github.com/gh0x0st/MXEnum)

A simple script to enumerate MX records from an email address

Example Usage:
* ./MXEnum.sh -e 'gh0x0st@protonmail.com'
* ./MXEnum.sh -f ~/Desktop/bad_emails.txt
* ./MXEnum.sh -f ~/Desktop/bad_emails.txt -o ~/Desktop/results.txt

```shell
root@kali:~# ./MXEnum.sh -e 'gh0x0st@protonmail.com'
  ____ _      ___        ___      _
 / ___| |__  / _ \__  __/ _ \ ___| |_
| |  _| '_ \| | | \ \/ / | | / __| __|
| |_| | | | | |_| |>  <| |_| \__ \ |_
 \____|_| |_|\___//_/\_\\___/|___/\__|

    >> MX Enumeration
    >> https://www.github.com/gh0x0st

[+] Email  - gh0x0st@protonmail.com
[-] Domain - protonmail.com
[-] MX Record - mail.protonmail.ch.
[-] MX Record - mailsec.protonmail.ch.

Done
```

OPTIONS:
  
   * -e   Designate an email to enumerate against
   * -f   Designate a file of emails to enumerate against
   * -o   Designate the file to save the output to
   * -h   Display this help page

   Running this script with no options will show only the help menu.
