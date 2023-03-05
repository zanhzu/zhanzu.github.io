---
description: https://tryhackme.com/room/tempestincident
---

# Tempest Walkthrough

## Challenge Scenario&#x20;

You are one of the Incident Responders that will focus on handling and analyzing the **captured artefacts** of a compromised machine.\
Captured Artifacts include:\
1\.  capture.pcapng\
2\. sysmon\_logs.evtx\
3\. windows.evtx

<figure><img src=".gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

## Tools & Artifacts

SHA-256 Hashes of artifacts via CRC-SHA Checksum Identifier (From 7-Zip Module)\


<figure><img src=".gitbook/assets/image (33).png" alt=""><figcaption><p>SHA-256 of capture.pcapng</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption><p>SHA-256 of windows.evtx</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption><p>SHA-256 of sysmon_logs.evtx</p></figcaption></figure>

## Initial Access

We can infer from the sysmon logs that there were multiple DNS queries from chrome.exe. These queries led to the download of a malicious document, **\<free\_magicules.doc>**

<figure><img src=".gitbook/assets/image (43).png" alt=""><figcaption><p>Key details include TargetFilename, User</p></figcaption></figure>

Further inspection shows that WINWORD.EXE was used to open the malicious document.

<figure><img src=".gitbook/assets/image (26).png" alt=""><figcaption><p>With ProcessID 496</p></figcaption></figure>

We can also see a suspicious entry from the queries resolved to a certain phishteam.xyz&#x20;

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption><p>phishteam.xyz // 167.71.199.191</p></figcaption></figure>

Afterwards, the maldoc executed the payload contained within. We can see several nested expressions in the payload demonstrating a variety of TTPs used by the threat actor; one in particular is the obfuscation of strings using Base64 encoding.

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption><p>The threat actor leveraged msdt.exe to perform RCE, akin to the CVE 2022-30190 vulnerability</p></figcaption></figure>

## Initial Access \<Stage 2 Execution>

The payload then recovered several command lines that will also attempt to retrieve further command line/scripted instructions from the threat actor. After some time, the payload wrote a file **\<update.zip>** on the system

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption><p>Scripted Diagnostic Native Host leveraged to download a zip file that contained a .lnk file</p></figcaption></figure>

The payload also rewrote some registry entries and instructed the victim machine to run some modified rules after the user logs in to the machine.

<figure><img src=".gitbook/assets/image (34).png" alt=""><figcaption><p>Key note: Trigger=UserLogon</p></figcaption></figure>

Following the next instance that winlogon.exe was run, we can see a PowerShell process that ran the command line as seen below and downloaded a binary \<first.exe>

<figure><img src=".gitbook/assets/image (15).png" alt=""><figcaption><p>first.exe 's first interaction with the victim machine</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (2) (1).png" alt=""><figcaption><p>7-Zip // CRC</p></figcaption></figure>

After the malicious binary was run, we can see several outbound packets sent to a C2 server \<resolvecyber\[.]xyz> using port 80.

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption><p>Brim (brimdata.io) was used to chronologically follow the traffic flow.</p></figcaption></figure>

## Initial Access \<Malicious Document Traffic>

One of the malicious document's first commands was to get an **\<index.html>** obfuscated command line that will also retrieve a **<.zip>** file containing the **<.lnk>** file used to deliver the **\<first.exe>** malicious binary.&#x20;

<figure><img src=".gitbook/assets/image (16).png" alt=""><figcaption><p>Also seen that index.html was downloaded twice, a possible slip-up from the threat actor.</p></figcaption></figure>

We can infer from Brim that after the malicious binary was run, an outbound connection was established to a command server **\<resolvecyber\[.]xyz/9ab62b5>**, of which the parameter **\<q>** was passed to the server via http.

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption><p>C2 binary contacting resolvecyber.xyz</p></figcaption></figure>

Focusing on the malicious domain and adding the user\_agent search parameter, we can see that Nim was used to compile & read the binary. Note the string values passed after the \<q> parameter. These are base64 encoded information that relays the victim machine's information to the C2 server.

<figure><img src=".gitbook/assets/image (41).png" alt=""><figcaption><p>We will manually decode the base64 encoded infromation one by one using base64decode.org</p></figcaption></figure>

Using CAPA, we can also determine that the binary was compiled with Nim, and verified that the data was encoded using Base64.&#x20;

<figure><img src=".gitbook/assets/image (40) (1).png" alt=""><figcaption><p>Using CAPA to determine the compiler of the binary &#x26; data encryption</p></figcaption></figure>

## Discovery \<Internal Reconnaisance>

After querying the C2 server \<resolvecyber\[.]xyz>, we decode some of the fields passed and find specific information relayed by the binary (refer to the screenshots below).

<figure><img src=".gitbook/assets/image (46).png" alt=""><figcaption><p>Attacker snooping around the file directories of the victim machine.</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (44).png" alt=""><figcaption><p>Attacker found an interesting .ps1 script at the victim's Desktop which contained a cleartext password.</p></figcaption></figure>

It takes a lot of time to decode all these instructions one by one, so we can just export the URI query results to a <.json> or <.csv> file,  and decode the entire list to get a faster explanation of the attack story.

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption><p>Base64 encoded information sent to C2 server (Brim sorts canonically from bottom to top, so these entries must be read in reverse)</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (40).png" alt=""><figcaption><p>Decoded information sent to C2 server; note that we view this from bottom to top</p></figcaption></figure>

Following the sequence of commands, we see that the attacker indexed the victim machine's network status and probed **listening ports**. Afterwards, they downloaded a certain \<ch.exe>, which we can infer is a payload for tunneling a reverse socks proxy in one of the listed ports.&#x20;

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption><p>That's a lot of open ports!</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption><p>Identified by our trusty friend, Virustotal, as related to &#x3C;chisel.exe></p></figcaption></figure>

## Privilege Escalation \<Exploiting Privileges>

\<ch.exe> was successfully dropped in the victim machine as communicated through the C2 server.

<figure><img src=".gitbook/assets/image (29).png" alt=""><figcaption><p>I need to learn from this guy in preparation for OSCP lol</p></figcaption></figure>

The actor then tried to add a user to the machine, but failed a few times because they missed out the "/add" command to their command line.

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption><p>We can also see here that they suceeded in changing the password of the Administrator to "ch4ng3dpassword!"</p></figcaption></figure>

Mirroring this timeline to the sysmon logs, after \<ch.exe> was ran, the actor leveraged a WinRM associated process to authenticate.

<figure><img src=".gitbook/assets/image (31).png" alt=""><figcaption><p>Theres a ton of files dumped by the payload before &#x26; after this log</p></figcaption></figure>

To which afterwards, they enumerated the privileges of the current logged-in user

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption><p>As seen in sysmon logs</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption><p>As returned to the C2 server</p></figcaption></figure>

The actor then proceeded to download another binary \<spf.exe> which as seen from Virustotal is a variant of the "PrintSpoofer" malware.

<figure><img src=".gitbook/assets/image (38).png" alt=""><figcaption><p>Note the actor used a different directory from the domain</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption><p>PrintSpoofer64.exe abuses the SeImpersonate Privilege to exploit the target machine<br>(<a href="https://github.com/itm4n/PrintSpoofer">https://github.com/itm4n/PrintSpoofer</a>)</p></figcaption></figure>

Eventually, the actor downloaded one last binary \<final.exe> to establish another C2 connection using the same URI from the previous C2 server

<figure><img src=".gitbook/assets/image (32).png" alt=""><figcaption><p>The Base64 encoded data was passed through port 8080 this time</p></figcaption></figure>

## Fully Owned Machine

Combining the two binaries, \<spf.exe> and \<final.exe>, the attacker managed to reach NT Authority/System privileges after payload execution.

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption><p>Setting up for machine ownage</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption><p>whoami? I am owned</p></figcaption></figure>

Finally, the threat actor added 2 users, "shion" and "shuna" to the local administrator's group and regular users group, respectively.

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

And as the finishing blow, the actor leveraged the Service Control Manager Configuration Tool to establish persistent administrative access by auto-running \<final.exe> everytime the machine is booted.

<figure><img src=".gitbook/assets/image (28).png" alt=""><figcaption><p>Game over.</p></figcaption></figure>

**Thank you to ar33zy for creating this room.**&#x20;

#### _It was a great exercise, especially for beginners in infosec such as me, as the room tackled every step of Lockheed Martin's Cyber kill-chain; definitely a must-try room for everyone._



