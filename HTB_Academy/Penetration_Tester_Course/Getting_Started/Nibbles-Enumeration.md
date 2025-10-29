# Nibbles — Enumeration (HTB)
**Summary / Notes**

---

## Table of Contents
1. [Machine Overview](#machine-overview)  
2. [Testing Approach](#testing-approach)  
3. [Initial Enumeration](#initial-enumeration)  
4. [Nmap Commands & Findings](#nmap-commands--findings)  
5. [Web Enumeration & Next Steps](#web-enumeration--next-steps)  
6. [Privilege Escalation Notes](#privilege-escalation-notes)  
7. [Operational Notes / Best Practices](#operational-notes--best-practices)  
8. [Resources / Walkthroughs](#resources--walkthroughs)

---

## Machine Overview
- **Name:** Nibbles  
- **Creator:** mrb3n  
- **OS:** Linux (Ubuntu)  
- **Difficulty:** Easy (20 pts)  
- **Release Date:** 13 Jan 2018  
- **IP (example in notes):** `10.129.42.190` / HTB VIP: `10.10.10.75` (context dependent)  
- **Attack Surface / Paths:** Web (User path), Privilege escalation via world-writable file and `sudoers` misconfiguration  
- **Media:**  
  - Ippsec video: https://www.youtube.com/watch?v=s_0GcRGv6Ds  
  - Writeup: https://0xdf.gitlab.io/2018/06/30/htb-nibbles.html

---

## Testing Approach
- **Grey-box** in this walkthrough (IP and OS known).  
- HTB active-release machines may be approached black-box (only IP given).  
- Understand three assessment types:
  - **Black-box:** Minimal target knowledge; heavy reconnaissance.  
  - **Grey-box:** Some information provided; focus on misconfigurations/exploitation.  
  - **White-box:** Full access/source; comprehensive analysis.  

---

## Initial Enumeration
1. Confirm host is up.  
2. Port/service discovery (initial top-1000 and later full TCP scan).  
3. Service banner grabbing (nc, nmap -sV).  
4. Nmap script scans (`-sC`, `http-enum`) against known ports to find common web directories and service details.  
5. Save **all** outputs (`-oA`) and keep timestamped notes.

---

## Nmap Commands & Findings

### Commands used
```bash
# Quick service scan (top 1000 ports)
nmap -sV --open -oA nibbles_initial_scan <ip>

# Show which ports nmap checks (no target)
nmap -v -oG -

# Full TCP port scan (all 65k ports)
nmap -p- --open -oA nibbles_full_tcp_scan <ip>

# Default scripts on known ports
nmap -sC -p 22,80 -oA nibbles_script_scan <ip>

# HTTP enumeration script
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum <ip>
```

### Example summarized output
- Host up (latency ~0.11s)  
- **Open ports found:**  
  - `22/tcp` — `ssh` — `OpenSSH 7.2p2` (Ubuntu)  
  - `80/tcp` — `http` — `Apache httpd` (Ubuntu)  
- `http-title`: Site doesn't have a title (text/html)  
- No additional useful results from default scripts or `http-enum` in this scan.

### Banner grabbing examples
```bash
nc -nv 10.129.42.190 22
# -> SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8

nc -nv 10.129.42.190 80
# -> port open (no banner)
```

---

## Web Enumeration & Next Steps
- With Apache on port 80: enumerate web directories, look for files/pages (use browser, curl, gobuster/ffuf).  
- Check for common web app vulnerabilities or misconfigurations (file upload, LFI/RFI, path traversal, weak creds).  
- If nothing obvious: perform more thorough content discovery (wordlists, virtual hosts, parameter fuzzing).  
- Keep an eye on file permissions and file-related misconfigurations for potential privilege escalation.

---

## Privilege Escalation Notes
- Goal in Nibbles: escalate via a **world-writable file** and a **sudoers misconfiguration**.  
- Once user-level access obtained (via web or creds), inspect:
  - `sudo -l` (to check allowed sudo commands)  
  - File permissions (`ls -la`, `stat`) for world-writable files and scripts run by privileged users  
  - Cron jobs and SUID binaries  
  - Environment/path hijacking possibilities for binaries run with elevated rights

---

## Operational Notes / Best Practices
- Always save scan outputs (`-oA`) and timestamped notes—essential for reporting and reproduction.  
- Restrict intrusive scans where appropriate; understand tool behavior (`-sC` uses NSE scripts which can be intrusive).  
- When scanning all ports (`-p-`) expect long runtimes—plan and document start/stop times.  
- On HTB: Pwnbox (web-based Parrot) can be used — note location/latency and spawn limits.  
- For learning: compare your steps with official HTB walkthroughs and community writeups to fill gaps.

---

## Resources / Walkthroughs
- Ippsec video walkthrough: https://www.youtube.com/watch?v=s_0GcRGv6Ds  
- Blog writeup: https://0xdf.gitlab.io/2018/06/30/htb-nibbles.html

---

### Quick checklist for this box
- [ ] Run `nmap -sV --open -oA` (done)  
- [ ] Run full TCP scan (`-p-`) and save outputs  
- [ ] Web content discovery (`gobuster`/`ffuf`)  
- [ ] Inspect web application for file handling / upload flaws  
- [ ] If shell obtained: run `sudo -l`, check permissions, cron, SUID, writable files  
- [ ] Document every step with timestamps and outputs

---

*End of summary.*
