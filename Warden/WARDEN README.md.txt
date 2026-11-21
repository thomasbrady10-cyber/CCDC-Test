WARDEN — CCDC Linux Defense & Host Hardening Suite
Automated competition-day Linux hardening, persistent nftables firewall enforcement (default-deny inbound & outbound), active reverse-shell socket detection, and continuous intrusion response (warden.service) with an interactive admin CLI (gatekeeper).
Repository Layout (CCDC-Test/Warden/)
* setup.py — Run this first. Main deployment script. Rotates sysadmin and root passwords, masks ufw/firewalld, enforces gatekeeper_fw.sh, initializes SQLite DB (/opt/warden/warden.db), and installs warden_daemon.py and gatekeeper.
* gatekeeper_fw.sh — Standalone nftables firewall bootstrap script. Enforces default-drop inbound/outbound rulesets with stateful tracking, ICMP ping support, and reboot persistence on both Debian/Ubuntu (/etc/nftables.conf) and Rocky/RHEL 9 (/etc/sysconfig/nftables.conf).
* warden_daemon.py — Continuous background monitoring service installed to /usr/bin/warden_daemon.py. Audits rogue UID 0 users, terminates blacklisted SSH sessions, detects active outbound reverse-shell TCP sockets via ss -tnap, reverts /etc/crontab tampering, and quarantines malicious systemd units.
* gatekeeper.py — Interactive administration CLI installed to /usr/bin/gatekeeper. Used during the competition for live IP/CIDR bans, dynamic TCP/UDP port opening/closing, and locking rogue users or services.
* warden.service — Systemd service unit file installed to /etc/systemd/system/warden.service to keep warden_daemon.py running persistently.
* .gitattributes — Forces Unix LF (\n) line endings for .sh, .py, and .service files so Windows CRLF line endings (\r\n) never break execution on Linux target hosts.
Quick Start (Competition Day Workflow)
1. One-Liner Deploy on Target Host
Run as root (or with sudo) directly on the target Linux machine (Rocky Ecom, Ubuntu Email, or Debian Splunk):
git clone https://github.com/thomasbrady10-cyber/CCDC-Test.git /opt/CCDC-Test && cd /opt/CCDC-Test/Warden && sudo python3 setup.py


2. Interactive Setup Prompts
1. Target Server Selection: Confirm or select the host profile (rocky, ubuntu, debian).
2. Password Rotation: Enter new, unique passwords for sysadmin and root (do not reuse credentials across hosts).
3. Splunk Forwarder Credentials: Enter Splunk forwarder admin user/password (press Enter to default to admin).
4. OS Package Upgrade: Enter N for fastest 10-second deployment (recommended at drop flag), or y to run system package updates.
3. Modular CLI Flags (Optional)
sudo python3 setup.py --passwords   # (-p) Rotate root & sysadmin passwords only
sudo python3 setup.py --firewall    # (-f) Re-enforce gatekeeper_fw.sh only
sudo python3 setup.py --splunk      # (-s) Configure Splunk forwarder only
sudo python3 setup.py --verify      # (-v) Run post-deployment health check


4. Verify Deployment Health
# Check service status
sudo systemctl status warden.service nftables.service


# View active firewall ruleset
sudo nft list ruleset


# Follow live security logs
tail -f /opt/warden/warden.log


Mid-Competition Live Defense (gatekeeper CLI)
Run sudo gatekeeper from any directory on any deployed machine to manage security policies on the fly without touching nftables.conf manually:
sudo gatekeeper


Key CLI Operations:
* Option 1 (Ban IP/CIDR): Immediately adds Red Team IP or subnet (e.g., 10.10.10.5 or 10.10.10.0/24) into the @blacklist nftables set and drops active sessions.
* Option 2 (Whitelist IP/CIDR): Whitelists trusted administrative jump boxes or scoring subnets.
* Option 3 / 4 (Open/Close Port): Dynamic TCP or UDP port management for inject requirements.
* Option 5 / 6 (Lock Account / Quarantine Service): Locks compromised accounts or stops and moves rogue systemd service units to /opt/warden/quarantine/.
Security Architecture Highlights
Reboot Persistence (Rocky/RHEL 9 & Debian/Ubuntu)
* Debian/Ubuntu reads /etc/nftables.conf on boot.
* Rocky/RHEL 9 reads /etc/sysconfig/nftables.conf on boot.
* Both gatekeeper_fw.sh and gatekeeper auto-detect RHEL systems, sync rules to /etc/sysconfig/nftables.conf, and apply SELinux context (restorecon) so firewall rules survive reboots.
Default-Deny Outbound Traffic
* Outbound policy is set to policy drop.
* Only essential outbound traffic is permitted: Loopback (lo), Established/Related return sessions, DNS (UDP/TCP 53), NTP (UDP 123), ICMP pings, HTTP/HTTPS repositories (TCP 80, 443), and Splunk Indexer shipping (TCP 8089, 9997).
Socket-Based Reverse Shell Detection
* warden_daemon.py scans active ESTABLISHED TCP sockets via ss -tnap rather than relying on brittle process regex string matching.
* Any interactive interpreter or shell (bash, sh, python3, nc, perl, ruby, php) holding an unauthorized outbound connection is immediately sent SIGKILL and logged with PID, local port, peer IP, and full /proc/<pid>/cmdline.