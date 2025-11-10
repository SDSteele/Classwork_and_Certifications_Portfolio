# Metasploit Payloads Summary

## Overview
A **payload** in Metasploit is a module that executes on the target machine after an exploit successfully runs. It typically provides a **shell** or **Meterpreter session**, giving the attacker control of the target system.

Payloads are combined with exploits to create a complete attack. They can be **staged** or **single** (unstaged).

---

## Types of Payloads

### 1. Singles
- **Definition:** Contain both the exploit and the full shellcode in one package.
- **Advantages:** Stable and self-contained.
- **Disadvantages:** Large size may be incompatible with some exploits.
- **Example:** `windows/shell_bind_tcp`

### 2. Stagers
- **Definition:** Small payloads that set up a communication channel between attacker and victim.
- **Purpose:** Establish the initial connection (e.g., reverse TCP or bind TCP).
- **Reliability:** NX (No eXecute) CPUs and Data Execution Prevention (DEP) can affect stability.
- **Example:** `reverse_tcp`

### 3. Stages
- **Definition:** Downloaded by stagers after connection is established.
- **Purpose:** Provide advanced features such as Meterpreter, VNC injection, etc.
- **Function:** Large code that performs post-exploitation tasks.
- **Example:** `windows/meterpreter`

---

## Staged Payloads
A **staged payload** separates the attack into multiple parts (Stage 0, Stage 1, etc.) to remain compact and evade antivirus systems.

- **Stage 0:** Initializes a reverse or bind connection.
- **Stage 1:** Downloads and executes the larger payload (e.g., Meterpreter).

### Common Connection Types
- `reverse_tcp` – Victim connects back to attacker.
- `reverse_https` – Uses encrypted HTTPS tunnel.
- `bind_tcp` – Attacker connects to victim’s open port.

Reverse connections are preferred for bypassing firewalls and IPS systems.

---

## Meterpreter Payload

### Key Features
- Uses **DLL injection** to stay memory-resident and stealthy.
- Leaves **no files** on disk (harder to detect).
- Supports **plugins and scripts** for advanced post-exploitation tasks.

### Example Capabilities
- Capture keystrokes
- Collect password hashes
- Record microphone/audio
- Screenshot
- Process token impersonation

### Benefits
- Flexible, modular, and persistent.
- Ideal for penetration testing with advanced control.

---

## Searching and Selecting Payloads

### Listing All Payloads
```bash
msf6 > show payloads
```

### Filtering with `grep`
You can narrow results to specific keywords:
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads
```

To find Meterpreter reverse TCP payloads:
```bash
grep meterpreter grep reverse_tcp show payloads
```

### Selecting a Payload
```bash
set payload windows/x64/meterpreter/reverse_tcp
show options
```

---

## Summary Table

| Payload Type | Description | Example |
|---------------|-------------|----------|
| **Single** | Self-contained payload, includes exploit and shellcode | `windows/shell_bind_tcp` |
| **Stager** | Establishes network connection | `reverse_tcp`, `bind_tcp` |
| **Stage** | Full payload loaded after connection | `windows/meterpreter` |

---

## Key Takeaways
- Payloads define **what happens after exploitation**.
- **Singles** are simple but large.  
- **Stagers + Stages** are modular, stealthy, and flexible.  
- **Meterpreter** is the most powerful and feature-rich payload.  
- Use `grep` in `msfconsole` to find and select payloads efficiently.

