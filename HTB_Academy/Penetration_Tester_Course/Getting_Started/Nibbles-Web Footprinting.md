
# Nibbles - Web Footprinting Summary

## Overview

The **Nibbles** machine on Hack The Box reveals a vulnerable **Nibbleblog** web application through careful web enumeration and analysis. This stage of the investigation focuses on identifying the CMS, gathering metadata, and discovering accessible directories and files that expose critical configuration details.

---

## Initial Enumeration

### Step 1: Identify Web Technologies

- **Command Used:** `whatweb 10.129.42.190`
- **Result:** Apache 2.4.18 on Ubuntu, "Hello world!" displayed.
- **Hidden Comment:** `<!-- /nibbleblog/ directory. Nothing interesting here! -->`

### Step 2: Check Nibbleblog Directory

- **Command Used:** `whatweb http://10.129.42.190/nibbleblog`
- **Findings:**  
  - Detected technologies: HTML5, jQuery, PHP  
  - CMS: **Nibbleblog**
  - Page title: *Nibbles - Yum yum*

---

## Directory Enumeration

### Using Gobuster

```bash
gobuster dir -u http://10.129.42.190/nibbleblog/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
**Results:**
- `/admin.php` – Admin login page
- `/README` – Reveals **Nibbleblog v4.0.3 (Coffee)** — known vulnerable version
- Other directories: `/content`, `/languages`, `/plugins`, `/themes`

---

## Vulnerability Research

- A Google search reveals a **File Upload Vulnerability** in Nibbleblog 4.0.3 allowing authenticated RCE.  
- Exploit path: `/admin.php` (requires valid credentials).

---

## Exploring Files and Directories

### Step 1: Themes Directory
Directory listing is enabled; accessible themes: `echo`, `medium`, `note-2`, `simpler`, `techie`.

### Step 2: Content Directory
Contains subfolders like `public`, `private`, `tmp`.

### Step 3: `users.xml`

```bash
curl -s http://10.129.42.190/nibbleblog/content/private/users.xml | xmllint --format -
```
**Findings:**
- Username: `admin`
- IP blacklisting mechanism enabled

### Step 4: `config.xml`

```bash
curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -
```
**Findings:**
- Blog name: `Nibbles`
- Notification email: `admin@nibbles.com`
- Password hint possibly “nibbles”

---

## Authentication Attempts

- Login portal located at `/admin.php`
- Default credentials failed (`admin:admin`, `admin:password`)
- Too many failed attempts result in IP blacklist
- Discovered potential password: **nibbles** (same as box name and email prefix)

---

## Key Takeaways

1. **Iterative enumeration** led from a simple “Hello world!” to full CMS identification.  
2. **Hidden comments and readable configs** can expose crucial details.  
3. **Directory listing** enabled exposure of private data like `users.xml` and `config.xml`.  
4. **Credential reuse and naming conventions** (like using the hostname as a password) can lead to footholds.  
5. **Thorough, methodical note-taking** and repeated enumeration phases are essential in pentesting.

---

## Summary Flow

| Step | Action | Tool | Finding |
|------|---------|------|----------|
| 1 | Scan site | whatweb | Apache, Ubuntu |
| 2 | Check source | Browser / curl | /nibbleblog directory |
| 3 | Identify CMS | whatweb | Nibbleblog v4.0.3 |
| 4 | Directory enum | Gobuster | admin.php, README |
| 5 | Extract config files | curl/xmllint | admin username, possible password |
| 6 | Test credentials | Manual | Password may be “nibbles” |

---

## Conclusion

Through consistent and careful enumeration, the penetration tester identified Nibbleblog CMS version 4.0.3, confirmed admin credentials, and prepared the groundwork for exploitation via the known authenticated file upload vulnerability. The case emphasizes the value of detailed reconnaissance before exploitation.

---
<details>
  cwel is awesome to find password possibilities in a page
</details>
</details>
