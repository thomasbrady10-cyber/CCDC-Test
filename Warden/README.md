# WARDEN & CITADEL — MWCCDC Host Defense & Hardening Suites

Automated competition-day Linux and Windows host hardening, zero-reboot protocol enforcement, persistent firewall control, continuous background monitoring, and automated forensic incident response bundle generation designed for CCDC cybersecurity competitions.

---

## 1. Repository Structure & Overview

The repository is structured into two dedicated suites: **Warden** for Linux targets and **Citadel** for Windows hosts.

```text
CCDC-Test/
├── .gitattributes          # Enforces LF line endings for .sh, .py, and .service files
├── Warden/                 # Linux Host Hardening & Quarantine Suite
│   ├── README.md           # Linux Quick-Start Documentation
│   ├── setup.py            # Master Linux Hardening & Deployment Script
│   ├── gatekeeper_fw.sh    # Standalone nftables Perimeter Bootstrap Script
│   ├── gatekeeper.py       # Interactive Admin Defense CLI (/usr/bin/gatekeeper)
│   ├── warden_daemon.py    # Background Intrusion Monitor & Forensic Quarantine Daemon
│   └── warden.service      # Systemd Unit File (/etc/systemd/system/warden.service)
└── Citadel/                # Windows Zero-Reboot Defense Suite
    ├── README.md           # Windows Quick-Start Documentation
    ├── setup.ps1           # Master Windows Hardening & Bootstrap Script
    ├── moat.ps1            # Windows Defender Firewall Policy Script
    └── drawbridge.ps1      # Interactive Windows Defense CLI (C:\Citadel\drawbridge.ps1)
```

---

## 2. Warden Linux Defense Suite (`Warden/`)

### Component Breakdown

| Script / Component | Target Path | Function & Role |
| :--- | :--- | :--- |
| **`setup.py`** | `/opt/CCDC-Test/Warden/setup.py` | Master bootstrapper. Rotates `sysadmin` and `root` credentials, masks `ufw`/`firewalld`, builds `/opt/warden/warden.db`, deploys binaries to `/usr/bin/`, and points Splunk Universal Forwarder. |
| **`gatekeeper_fw.sh`** | `/opt/CCDC-Test/Warden/gatekeeper_fw.sh` | Configures `nftables` with default-drop inbound/outbound rules, ICMP ping support, and reboot persistence on Debian/Ubuntu (`/etc/nftables.conf`) and Rocky/RHEL (`/etc/sysconfig/nftables.conf`). |
| **`warden_daemon.py`** | `/usr/bin/warden_daemon.py` | Background service that freezes (`SIGSTOP`) reverse shells, builds Incident Report (IR) evidence packets in `/opt/warden/quarantine/`, locks rogue accounts, reverts `/etc/crontab` edits, and verifies shell binary SHA-256 hashes. |
| **`gatekeeper.py`** | `/usr/bin/gatekeeper` | Interactive CLI for real-time IP bans/whitelists, opening/closing inject ports, and flagging rogue accounts or services. Symlinked to `/usr/local/bin/gatekeeper`. |
| **`warden.service`** | `/etc/systemd/system/warden.service` | Self-healing systemd unit file that keeps `warden_daemon.py` running continuously (`Restart=always`). |

---

### Quick Start (Competition Day Deployment)

Run as `root` (or with `sudo`) on each Linux machine (`Rocky Ecom .10`, `Ubuntu Email .15`, `Debian Splunk .20`):

```bash
git clone https://github.com/thomasbrady10-cyber/CCDC-Test.git /opt/CCDC-Test
cd /opt/CCDC-Test/Warden
sudo python3 setup.py
```

#### Deployment Prompts
1. **OS Profile Confirmation:** Press **Enter** to accept the auto-detected OS profile (`rocky`, `ubuntu`, or `debian`).
2. **Password Rotation:** Input new, unique passwords for `sysadmin` and `root`.
3. **Splunk Forwarder Target:** *(Prompted on Rocky Ecom & Ubuntu Email; automatically skipped on Debian Splunk Indexer)*
   * Press **Enter** to accept default Indexer IP (`172.20.240.20`) and port (`9997`), or supply custom endpoints.
   * Provide Splunk Forwarder credentials (or press **Enter** for default `admin`).

#### Targeted Flag Executions
To re-run specific components without performing a full setup:
```bash
sudo python3 setup.py --passwords   # Rotate root & sysadmin passwords only (-p)
sudo python3 setup.py --firewall    # Re-apply gatekeeper_fw.sh only (-f)
sudo python3 setup.py --splunk      # Reconfigure Splunk forwarder target/monitors (-s)
sudo python3 setup.py --verify      # Run post-deploy service health checks (-v)
```

#### Verification
```bash
sudo systemctl status warden.service nftables.service
sudo nft list ruleset
tail -f /opt/warden/warden.log
```

---

### Live Defense CLI (`sudo gatekeeper`)

Launch the interactive management tool from any terminal on the machine:

```bash
sudo gatekeeper
```

1. **Ban Malicious IP / CIDR:** Immediately appends target IP to `@blacklist` set and drops inbound traffic.
2. **Whitelist Trusted IP / CIDR:** Adds trusted Blue Team jump hosts to `@whitelist`.
3. **Open Port (TCP/UDP):** Opens temporary ports for inject requirements.
4. **Close Port:** Removes port exceptions and reloads ruleset.
5. **Lock Rogue User:** Flags user for locking (`usermod -L -s /sbin/nologin`) and session termination.
6. **Quarantine Rogue Service:** Stops, disables, masks, and moves target service unit to `/opt/warden/quarantine/`.
7. **View Policy & Firewall Status:** Displays all allowed ports, blacklisted/whitelisted IPs, and blocked users/services.

---

### Forensic Quarantine & Incident Response (IR) Workflow

When `warden_daemon.py` detects an unauthorized socket (e.g., `bash`, `sh`, `nc`, `python3`, `perl`, `php` holding an established TCP connection to an external address):

1. **Process Freezing (`SIGSTOP`):** The process is immediately frozen in memory rather than killed, halting outbound beacons while preserving `/proc/<pid>` memory artifacts.
2. **Automated Bundle Generation:** Warden generates an evidence directory at `/opt/warden/quarantine/IR_<timestamp>_pid<PID>_<proc>/`:
   * `incident_report.txt`: Incident narrative, attacker IP/port, full process tree, working directory, command line, and SHA-256 hash.
   * `environ.txt`: Captured environment variables.
   * `open_files.txt`: Open file descriptors and network sockets.
   * `quarantined_binary_<name>`: Copy of suspicious executable binary.
3. **Defender Action Protocol:**
   * Ban attacker IP via `sudo gatekeeper` (Option 1).
   * Submit `incident_report.txt` and SHA-256 hash in CCDC Incident Report.
   * Permanently kill frozen process (`sudo kill -9 <PID>`) or resume if verified (`sudo kill -CONT <PID>`).

---

### Linux Topology & Scored Port Profiles

* **Rocky Linux 9 E-Commerce (`172.20.240.10`):** Scored TCP ports `22, 80, 443` + ICMP. (`mysql`/`mariadb` service accounts whitelisted).
* **Ubuntu 22.04 Email/Webmail (`172.20.240.15`):** Scored TCP ports `22, 25, 80, 110, 143, 443, 465, 587, 993, 995` + ICMP.
* **Debian 12 Splunk Indexer (`172.20.240.20`):** Scored TCP ports `22, 8000, 8089, 9997` + UDP `123` (`chrony`) + ICMP.

---

## 3. Citadel Windows Defense Suite (`Citadel/`)

### Component Breakdown

| Script / Component | Target Path | Function & Role |
| :--- | :--- | :--- |
| **`setup.ps1`** | `C:\Citadel\setup.ps1` | Zero-reboot master hardening script. Detects Windows role (`ad`, `mssql`, `wkst`), rotates `Administrator`/`sysadmin` passwords, captures CSV baselines, hardens protocols, and calls `moat.ps1`. |
| **`moat.ps1`** | `C:\Citadel\moat.ps1` | Enforces Windows Defender Firewall policies with default-drop inbound rules tailored to specific server roles. |
| **`drawbridge.ps1`** | `C:\Citadel\drawbridge.ps1` | Interactive CLI tool for live Windows incident response (IP bans, account locks, port management, active connection audits). |

---

### Quick Start (Windows Deployment — Zero Reboots)

Open an elevated **PowerShell as Administrator** prompt on each Windows machine (`2022 AD .100`, `2019 MSSQL .120`, `Win11 Wkst`):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup.ps1
```

#### Deployment Workflow
1. **Confirm Host Role:** Press **Enter** to accept detected role (`ad`, `mssql`, or `wkst`).
2. **Splunk Target Configuration:** Enter Splunk Indexer IP (default `172.20.240.20`) and port (default `9997`).
3. **Credential Rotation:** Input new secure password for local and Active Directory `Administrator` and `sysadmin` accounts.

---

### Zero-Reboot Hardening Measures

* **Protocol Hardening:** Disables SMBv1 (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`), enforces SMB Signing, disables LLMNR multicast (`EnableMulticast = 0`), and disables NetBIOS over TCP/IP across active adapters.
* **LSASS & Credential Protection:** Disables WDigest plaintext caching in LSASS (`UseLogonCredential = 0`) and enables Defender Attack Surface Reduction (ASR) rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` to block LSASS memory dumping immediately without rebooting. Stages `RunAsPPL = 1` in registry.
* **Audit & Logging Enforcement:** Activates Process Creation (Event ID 4688) with command-line auditing, Logon/Account Management auditing, and PowerShell ScriptBlock Logging (Event ID 4104).
* **Baseline Capture:** Exports clean CSV snapshots of users, Administrators group members, running services, and scheduled tasks to `C:\Citadel\`.

---

### Live Windows Defense CLI (`drawbridge.ps1`)

Execute from PowerShell to perform live triage and defensive control:

```powershell
.\drawbridge.ps1
```

* **Raise Drawbridge (Ban IP/CIDR):** Creates firewall drop rule for attacker IP.
* **Lower Drawbridge (Whitelist IP):** Adds explicit inbound allow rule for Blue Team hosts.
* **Open/Close Gate Ports:** Manages inbound port exceptions for competition injects.
* **Send User to Dungeon:** Disables and locks compromised local accounts.
* **Audit Established Connections:** Displays active TCP connections mapped to process names and PIDs.

---

### Windows Topology & Scored Port Profiles

* **2022 Active Directory Domain Controller (`172.20.240.100`):** AD DS, DNS (53), Kerberos (88), LDAP/LDAPS (389/636), Global Catalog (3268/3269), NTP (123).
* **2019 MSSQL Database Server (`172.20.240.120`):** SQL Server Engine (TCP 1433) + SQL Browser (UDP 1434).
* **Windows 11 Workstation (`172.17.0.x DHCP`):** Internal Blue Team Workstation (no inbound scored services required).

---

## 4. Centralized Logging & Splunk Integration

Both Warden and Citadel automatically integrate with the competition's central Splunk Universal Forwarder to aggregate security logs onto the Debian Splunk Indexer (`172.20.240.20:9997`).

### Monitored Log Sources
* **Linux Targets:** `/etc/passwd`, `/etc/group`, `/etc/sudoers`, `/opt/warden/warden.log`, `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/audit/audit.log` (Rocky Linux).
* **Windows Targets:** `C:\Citadel\citadel.log`, Windows Security Event Log (Event IDs 4624, 4625, 4688, 4720, 4728, 4732), and PowerShell ScriptBlock Log (Event ID 4104).
