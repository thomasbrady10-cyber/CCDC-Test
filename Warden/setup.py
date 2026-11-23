#!/usr/bin/env python3
"""
================================================================================
WARDEN SETUP — CCDC Rapid Linux Host Hardening & Defense Bootstrapper
================================================================================
PURPOSE:
    Automates initial competition-day triage across the 3 MWCCDC Linux hosts
    using only the Python 3 standard library (zero pip/compiler delays):
      - Rocky Linux 9 (E-Commerce — .10): TCP 22, 80, 443 + ICMP
      - Ubuntu 22.04  (Email/Web  — .15): TCP 22, 25, 80, 110, 143, 443, 465,
                                          587, 993, 995 + ICMP
      - Debian 12     (Splunk Srv — .20): TCP 22, 8000, 8089, 9997 +
                                          UDP 123 (Chrony) + ICMP

WHAT THIS SCRIPT DOES:
    [1/5] Rotates 'sysadmin' and 'root' passwords using secure `chpasswd` pipes.
    [2/5] Syncs system time (NTP/Chrony) and verifies `nftables` is installed.
    [3/5] Builds `/opt/warden/warden.db` (SQLite policy store), deploys the
          background monitor (`/usr/bin/warden_daemon.py`) and interactive CLI
          (`/usr/bin/gatekeeper`), and enables `warden.service`.
    [4/5] Stops/masks `ufw` and `firewalld`, then calls `gatekeeper_fw.sh` to
          enforce default-drop inbound and outbound `nftables` rules.
    [5/5] Prompts for Splunk Indexer IP/port (defaulting to 172.20.240.20:9997),
          configures `/opt/splunkforwarder` (skipping Debian Splunk Server),
          and verifies service health.

USAGE:
    sudo python3 setup.py               # Full interactive deployment
    sudo python3 setup.py --passwords   # Rotate root & sysadmin passwords only
    sudo python3 setup.py --firewall    # Re-enforce gatekeeper_fw.sh only
    sudo python3 setup.py --splunk      # Configure Splunk forwarder only
    sudo python3 setup.py --verify      # Verify defense & scored services
================================================================================
"""

import os
import sys
import getpass
import ipaddress
import logging
import shutil
import sqlite3
import subprocess
from pathlib import Path

# ------------------------------------------------------------------------------
# GLOBAL PATHS & DEFAULT NETWORK TARGETS
# ------------------------------------------------------------------------------
# SCRIPT_DIR resolves the exact directory where setup.py is stored so companion
# files (gatekeeper_fw.sh, gatekeeper.py, etc.) are found regardless of pwd.
SCRIPT_DIR = Path(__file__).resolve().parent

# WARDEN_DIR holds persistent runtime state (SQLite policy DB, logs, quarantine).
WARDEN_DIR = Path("/opt/warden")
DB_PATH = WARDEN_DIR / "warden.db"
LOG_PATH = WARDEN_DIR / "warden.log"

# Default Splunk Indexer IP and receiver port (can be overridden at prompt)
DEFAULT_SPLUNK_IP = "172.20.240.20"
DEFAULT_SPLUNK_PORT = "9997"

# ------------------------------------------------------------------------------
# MWCCDC LINUX HOST PROFILES
# ------------------------------------------------------------------------------
# Maps each competition Linux distro to:
#   - label:              Human-readable role description shown at startup
#   - pkg_mgr:            Native OS package manager (dnf vs. apt-get)
#   - tcp_ports:          Scored inbound TCP ports opened in nftables
#   - udp_ports:          Scored inbound UDP ports opened in nftables (e.g., 123)
#   - is_splunk_indexer:  True on Debian (.20) so we do NOT run forwarder setup
#                         on top of the full Splunk Enterprise server
#   - audit_log:          OS authentication log path monitored by Splunk
#   - services:           Core systemd units checked during final verification
HOST_PROFILES = {
    "rocky": {
        "label": "Rocky Linux 9 (E-Commerce — 172.20.240.10)",
        "pkg_mgr": "dnf",
        "tcp_ports": [22, 80, 443],
        "udp_ports": [],
        "is_splunk_indexer": False,
        "audit_log": "/var/log/audit/audit.log",
        "services": ["sshd", "httpd", "nginx", "mariadb", "nftables", "warden"],
    },
    "ubuntu": {
        "label": "Ubuntu 22.04 (Email/Webmail — 172.20.240.15)",
        "pkg_mgr": "apt-get",
        "tcp_ports": [22, 25, 80, 110, 143, 443, 465, 587, 993, 995],
        "udp_ports": [],
        "is_splunk_indexer": False,
        "audit_log": "/var/log/auth.log",
        "services": ["ssh", "postfix", "dovecot", "apache2", "nginx", "nftables", "warden"],
    },
    "debian": {
        "label": "Debian 12 (Splunk Indexer — 172.20.240.20)",
        "pkg_mgr": "apt-get",
        "tcp_ports": [22, 8000, 8089, 9997],
        "udp_ports": [123],  # CRITICAL: Scored splunk-chrony NTP service!
        "is_splunk_indexer": True,
        "audit_log": "/var/log/auth.log",
        "services": ["ssh", "Splunkd", "chrony", "nftables", "warden"],
    },
}

# Baseline system/service usernames that warden_daemon.py must never lock out.
DEFAULT_ALLOWED_USERS = [
    "root", "sysadmin", "splunk", "splunkfwd", "mysql", "mariadb",
    "apache", "www-data", "nginx", "postfix", "dovecot", "dovenull",
    "chrony", "_chrony", "nobody",
]


# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def require_root():
    """Abort immediately if not executed with root privileges (UID 0)."""
    if os.geteuid() != 0:
        print("ERROR: setup.py must be run as root (sudo python3 setup.py).")
        sys.exit(1)


def setup_logging():
    """Create /opt/warden with strict 0700 permissions and initialize logging."""
    WARDEN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WARDEN_DIR, 0o700)
    logging.basicConfig(
        level=logging.INFO,
        filename=str(LOG_PATH),
        filemode="a",
        format="%(asctime)s - %(levelname)s - [SETUP] %(message)s",
    )


def run_cmd(cmd, check=True, input_text=None):
    """
    Safe wrapper around subprocess.run() using list arguments (shell=False)
    to prevent shell injection and log stderr cleanly on errors.
    """
    res = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and res.returncode != 0:
        logging.error(f"Command failed ({' '.join(cmd)}): {res.stderr.strip()}")
        raise subprocess.CalledProcessError(res.returncode, cmd, res.stdout, res.stderr)
    return res


def detect_host_profile():
    """
    Inspect /etc/os-release to auto-detect whether we are running on Rocky,
    Ubuntu, or Debian so the operator can confirm with a single Enter press.
    """
    os_release = Path("/etc/os-release")
    if os_release.exists():
        content = os_release.read_text().lower()
        if "rocky" in content or "rhel" in content or "centos" in content:
            return "rocky"
        if "ubuntu" in content:
            return "ubuntu"
        if "debian" in content:
            return "debian"
    return "rocky"


def prompt_host_profile():
    """Prompt the operator to confirm or override the detected OS profile."""
    detected = detect_host_profile()
    print(f"Detected OS Profile: [{detected}] -> {HOST_PROFILES[detected]['label']}")
    while True:
        choice = input(f"Confirm profile ({'/'.join(HOST_PROFILES.keys())}) [{detected}]: ").strip().lower()
        if not choice:
            return detected
        if choice in HOST_PROFILES:
            return choice
        print(f"Invalid profile '{choice}'. Choose from: {', '.join(HOST_PROFILES.keys())}")


# ------------------------------------------------------------------------------
# STEP 1: CREDENTIAL ROTATION
# ------------------------------------------------------------------------------
def rotate_passwords():
    """
    Rotate 'sysadmin' (default Changeme1!) and 'root' passwords immediately.
    Passes credentials via `chpasswd` stdin so plaintext passwords never
    appear in `ps aux` process arguments.
    """
    print("[1/5] Rotating 'sysadmin' and 'root' passwords...")
    for account in ["sysadmin", "root"]:
        # Skip if the account does not exist on this host
        if run_cmd(["id", account], check=False).returncode != 0:
            logging.warning(f"Account '{account}' not present on host; skipping.")
            continue

        while True:
            pw1 = getpass.getpass(f"Enter NEW unique '{account}' password: ")
            pw2 = getpass.getpass(f"Confirm '{account}' password: ")
            if not pw1 or pw1 != pw2:
                print("Mismatch or empty. Try again.")
                continue
            run_cmd(["chpasswd"], check=True, input_text=f"{account}:{pw1}\n")
            logging.info(f"Password rotated for local account '{account}'.")
            break


# ------------------------------------------------------------------------------
# STEP 2: TIME SYNC & NFTABLES PACKAGE CHECK
# ------------------------------------------------------------------------------
def prep_system(server):
    """
    Ensure NTP clock synchronization is active (critical for Splunk log
    correlation and Debian's scored splunk-chrony check) and verify `nft`
    is installed.
    """
    print("[2/5] Syncing time & ensuring nftables is installed...")
    pkg_mgr = HOST_PROFILES[server]["pkg_mgr"]
    run_cmd(["timedatectl", "set-ntp", "true"], check=False)

    # Explicitly enable chrony on Debian Splunk Server (.20) since UDP 123 is scored
    if server == "debian":
        run_cmd(["systemctl", "enable", "--now", "chrony"], check=False)

    # Install nftables only if not already present on the system
    if not shutil.which("nft"):
        if pkg_mgr == "apt-get":
            run_cmd(["apt-get", "update", "-qq"], check=True)
            run_cmd(["apt-get", "install", "-y", "-qq", "nftables"], check=True)
        else:
            run_cmd(["dnf", "install", "-y", "-q", "nftables"], check=True)
        logging.info("Installed nftables package.")


# ------------------------------------------------------------------------------
# STEP 3: DATABASE INITIALIZATION & DAEMON / CLI DEPLOYMENT
# ------------------------------------------------------------------------------
def init_db_and_deploy(server):
    """
    1. Create `/opt/warden/warden.db` (SQLite) and seed it with this host's
       scored TCP/UDP ports, baseline allowed users, and allowed services.
    2. Copy `warden_daemon.py` and `gatekeeper.py` into `/usr/bin/` (which is
       included in Rocky/RHEL's default sudo secure_path and allowed by SELinux).
    3. Create a `/usr/local/bin/gatekeeper` symlink for muscle-memory convenience.
    4. Install and start `warden.service` under systemd.
    """
    print("[3/5] Initializing /opt/warden/warden.db & deploying daemon/CLI...")
    profile = HOST_PROFILES[server]

    # --- Initialize SQLite Policy Store ---
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS accepted_ports (
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
            PRIMARY KEY (port, protocol)
        );
        CREATE TABLE IF NOT EXISTS blocked_ports (
            port INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS allowed_users (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS blocked_users (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS allowed_services (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS blocked_services (
            name TEXT PRIMARY KEY
        );
    """)

    # Seed scored ports, allowed accounts, and scored services for this host
    for p in profile["tcp_ports"]:
        cur.execute("INSERT OR IGNORE INTO accepted_ports (port, protocol) VALUES (?, 'tcp')", (p,))
    for p in profile["udp_ports"]:
        cur.execute("INSERT OR IGNORE INTO accepted_ports (port, protocol) VALUES (?, 'udp')", (p,))
    for u in DEFAULT_ALLOWED_USERS:
        cur.execute("INSERT OR IGNORE INTO allowed_users (name) VALUES (?)", (u,))
    for s in profile["services"]:
        cur.execute("INSERT OR IGNORE INTO allowed_services (name) VALUES (?)", (s,))

    conn.commit()
    conn.close()
    os.chmod(DB_PATH, 0o600)

    # --- Deploy Daemon, CLI, and Systemd Service ---
    for src_name, dst_path, mode in [
        ("warden_daemon.py", "/usr/bin/warden_daemon.py", 0o700),
        ("gatekeeper.py", "/usr/bin/gatekeeper", 0o700),
        ("warden.service", "/etc/systemd/system/warden.service", 0o644),
    ]:
        src = SCRIPT_DIR / src_name
        if not src.exists():
            print(f"ERROR: Missing {src}")
            sys.exit(1)
        shutil.copy(str(src), dst_path)
        os.chmod(dst_path, mode)

    # Symlink /usr/local/bin/gatekeeper -> /usr/bin/gatekeeper
    if not os.path.exists("/usr/local/bin/gatekeeper"):
        os.symlink("/usr/bin/gatekeeper", "/usr/local/bin/gatekeeper")

    # Quarantine folder where malicious Red Team systemd unit files are moved
    quarantine_dir = WARDEN_DIR / "quarantine"
    quarantine_dir.mkdir(exist_ok=True)
    os.chmod(quarantine_dir, 0o600)

    # Restore SELinux file contexts on Rocky Linux so systemd can execute the daemon
    if shutil.which("restorecon"):
        run_cmd(
            ["restorecon", "-Rv", "/opt/warden", "/usr/bin/warden_daemon.py",
             "/usr/bin/gatekeeper", "/etc/systemd/system/warden.service"],
            check=False,
        )

    run_cmd(["systemctl", "daemon-reload"], check=True)
    run_cmd(["systemctl", "enable", "--now", "warden.service"], check=True)
    logging.info("Deployed warden.db, gatekeeper CLI, and started warden.service.")


# ------------------------------------------------------------------------------
# STEP 4: FIREWALL ENFORCEMENT (GATEKEEPER_FW.SH)
# ------------------------------------------------------------------------------
def enforce_firewall(server):
    """
    1. Stop, disable, and mask `ufw` and `firewalld` so they cannot flush or
       override our nftables ruleset.
    2. Strip Windows CRLF (\r\n) line endings from `gatekeeper_fw.sh` automatically
       so edits made on a Windows workstation never cause `$\\r: command not found`.
    3. Execute `gatekeeper_fw.sh` with this host's scored TCP and UDP ports.
    """
    print("[4/5] Masking ufw/firewalld & enforcing gatekeeper_fw.sh...")
    for fw in ["ufw", "firewalld"]:
        run_cmd(["systemctl", "stop", fw], check=False)
        run_cmd(["systemctl", "disable", fw], check=False)
        run_cmd(["systemctl", "mask", fw], check=False)

    fw_script = SCRIPT_DIR / "gatekeeper_fw.sh"
    if not fw_script.exists():
        print(f"ERROR: {fw_script} not found!")
        sys.exit(1)

    # Normalize CRLF -> LF if edited on Windows
    raw_bytes = fw_script.read_bytes()
    if b"\r\n" in raw_bytes:
        fw_script.write_bytes(raw_bytes.replace(b"\r\n", b"\n"))

    os.chmod(fw_script, 0o700)
    profile = HOST_PROFILES[server]

    # Pass host role and scored ports into gatekeeper_fw.sh via environment vars
    env = os.environ.copy()
    env["TARGET_SERVER"] = server
    env["ALLOWED_TCP_PORTS"] = ",".join(str(p) for p in profile["tcp_ports"])
    env["ALLOWED_UDP_PORTS"] = ",".join(str(p) for p in profile["udp_ports"])

    subprocess.run(["/bin/bash", str(fw_script)], env=env, check=True)
    logging.info("Firewall enforced via gatekeeper_fw.sh.")


# ------------------------------------------------------------------------------
# STEP 5: SPLUNK UNIVERSAL FORWARDER (INTERACTIVE TARGET) & HEALTH CHECK
# ------------------------------------------------------------------------------
def configure_splunk_forwarder(server):
    """
    Prompt for the Splunk Indexer IP and receiver port (defaulting to
    172.20.240.20:9997 on Enter) and configure `/opt/splunkforwarder` on
    Rocky Ecom and Ubuntu Email. Skips Debian (.20) since it IS the Splunk Server.
    """
    profile = HOST_PROFILES[server]
    if profile["is_splunk_indexer"]:
        print("[5/5] Host is Debian Splunk Indexer — skipping forwarder setup.")
        return

    splunk_bin = Path("/opt/splunkforwarder/bin/splunk")
    if not splunk_bin.is_file():
        print("[5/5] Splunk Universal Forwarder not installed at /opt/splunkforwarder; skipping.")
        return

    print("[5/5] Configuring Splunk Universal Forwarder...")

    # Prompt for Splunk Server IP with IPv4/IPv6 validation
    while True:
        entered_ip = input(f"Enter Splunk Indexer IP [{DEFAULT_SPLUNK_IP}]: ").strip()
        splunk_ip = entered_ip if entered_ip else DEFAULT_SPLUNK_IP
        try:
            ipaddress.ip_address(splunk_ip)
            break
        except ValueError:
            print("Invalid IP address. Try again.")

    # Prompt for Splunk Receiver Port with 1-65535 validation
    while True:
        entered_port = input(f"Enter Splunk Forwarder Port [{DEFAULT_SPLUNK_PORT}]: ").strip()
        splunk_port = entered_port if entered_port else DEFAULT_SPLUNK_PORT
        if splunk_port.isdigit() and 1 <= int(splunk_port) <= 65535:
            break
        print("Invalid port (must be 1-65535).")

    splunk_user = input("Enter Splunk Forwarder Admin User [admin]: ").strip() or "admin"
    splunk_pass = getpass.getpass("Enter Splunk Forwarder Password: ")

    # Seed forwarder admin credentials via user-seed.conf
    seed_dir = Path("/opt/splunkforwarder/etc/system/local")
    seed_dir.mkdir(parents=True, exist_ok=True)
    seed_file = seed_dir / "user-seed.conf"
    seed_file.write_text(f"[user_info]\nUSERNAME = {splunk_user}\nPASSWORD = {splunk_pass}\n")
    os.chmod(seed_file, 0o600)

    run_cmd([str(splunk_bin), "restart", "--accept-license", "--answer-yes", "--no-prompt"], check=False)

    # Point forwarder to Splunk Indexer and add critical security log monitors
    auth = f"{splunk_user}:{splunk_pass}"
    target = f"{splunk_ip}:{splunk_port}"
    run_cmd([str(splunk_bin), "add", "forward-server", target, "-auth", auth], check=False)

    for path in ["/etc/passwd", "/etc/group", "/etc/sudoers", str(LOG_PATH), profile["audit_log"]]:
        if os.path.exists(path):
            run_cmd([str(splunk_bin), "add", "monitor", path, "-auth", auth], check=False)

    run_cmd([str(splunk_bin), "enable", "boot-start"], check=False)
    run_cmd([str(splunk_bin), "restart"], check=False)
    logging.info(f"Configured Splunk forwarder -> {target}")


def verify_services(server):
    """Display systemd status for core defense units and host-specific scored services."""
    print("\n--- Final Health & Scoring Service Check ---")
    for svc in HOST_PROFILES[server]["services"]:
        res = run_cmd(["systemctl", "is-active", svc], check=False)
        state = res.stdout.strip() or "inactive"
        tag = "[ OK ]" if state == "active" else "[INFO]"
        print(f"  {tag} {svc:<14} -> {state}")


def main():
    require_root()
    setup_logging()

    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    server = prompt_host_profile()

    if arg == "--passwords":
        rotate_passwords()
    elif arg == "--firewall":
        enforce_firewall(server)
    elif arg == "--splunk":
        configure_splunk_forwarder(server)
    elif arg == "--verify":
        verify_services(server)
    elif arg == "":
        rotate_passwords()
        prep_system(server)
        init_db_and_deploy(server)
        enforce_firewall(server)
        configure_splunk_forwarder(server)
        verify_services(server)
        print("\n[+] WARDEN deployment complete! Run `sudo gatekeeper` anytime for live defense.")
    else:
        print(f"Unknown argument: {arg}")
        print("Usage: sudo python3 setup.py [--passwords | --firewall | --splunk | --verify]")
        sys.exit(1)


if __name__ == "__main__":
    main()
