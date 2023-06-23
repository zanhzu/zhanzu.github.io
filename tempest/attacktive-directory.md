---
description: https://tryhackme.com/room/attacktivedirectory
---

# Attacktive Directory

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -sV 10.10.65.114                          
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-22 02:08 EDT
Nmap scan report for 10.10.65.114
Host is up (0.58s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-22 06:09:55Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.02 seconds
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ enum4linux -U -o 10.10.65.114
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Jun 22 02:11:10 2023

 =========================================( Target Information )=========================================
                                                                                                                     
Target ........... 10.10.65.114                                                                                      
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.65.114 )============================
                                                                                                                     
                                                                                                                     
[E] Can't find workgroup/domain                                                                                      
                                                                                                                     
                                                                                                                     

 ===================================( Session Check on 10.10.65.114 )===================================
                                                                                                                     
                                                                                                                     
[+] Server 10.10.65.114 allows sessions using username '', password ''                                               
                                                                                                                     
                                                                                                                     
 ================================( Getting domain SID for 10.10.65.114 )================================
                                                                                                                     
Domain Name: THM-AD                                                                                                  
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)                                                                       
                                                                                                                     
                                                                                                                     
 ===================================( OS information on 10.10.65.114 )===================================
                                                                                                                     
                                                                                                                     
[E] Can't get OS info with smbclient                                                                                 
                                                                                                                     
                                                                                                                     
[+] Got OS info for 10.10.65.114 from srvinfo:                                                                       
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                               


 =======================================( Users on 10.10.65.114 )=======================================
                                                                                                                     
                                                                                                                     
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                 
                                                                                                                     
                                                                                                                     

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                  
                                                                                                                     
enum4linux complete on Thu Jun 22 02:11:48 2023
```
