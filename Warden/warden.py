#!/usr/bin/env python3
"""
================================================================================
WARDEN — MWCCDC Rapid Linux Hardening & Deployment Suite (warden.py)
================================================================================
Deploys in <15 seconds using Python 3 stdlib + SQLite (zero pip/gcc/MariaDB lag).
Covers:
  - Rocky Ecom    (172.20.240.10): TCP 80, 443 + ICMP
  - Ubuntu Email  (172.20.240.15): TCP 22, 25, 80, 110, 143, 443, 587, 993, 995 + ICMP
  - Debian Splunk (172.20.240.20): TCP 22, 8000, 8089, 9997 | UDP 123 (Chrony) + ICMP

Usage:
  sudo python3 warden.py              # Full rapid deployment
  sudo python3 warden.py --passwords  # Rotate root & sysadmin passwords only
  sudo python3 warden.py --firewall   # Re-apply gatekeeper_fw.sh only
  sudo python3 warden.py --splunk     # Configure Splunk forwarder only
  sudo python3 warden.py --verify     # Verify active scored & defense services
================================================================================
"""

import os
import sys
import shutil
import sqlite3
import getpass
import logging
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
WARDEN_DIR = Path("/opt/warden")
DB_PATH = WARDEN_DIR / "warden.db"
LOG_PATH = WARDEN_DIR / "warden.log"

SPLUNK_INDEXER_IP = "172.20.240.20"
SPLUNK_FORWARD_PORT = "9997"

HOST_PROFILES = {
    "rocky": {
        "role": "Rocky Ecom (172.20.240.10)",
        "pkg_mgr": "dnf",
        "tcp_ports": [80, 443],
        "udp_ports": [],
        "is_splunk_indexer": False,
        "audit_log": "/var/log/audit/audit.log",
    },
    "ubuntu": {
        "role": "Ubuntu Email (172.20.240.15)",
        "pkg_mgr": "apt-get",
        "tcp_ports": [22, 25, 80, 110, 143, 443, 587, 993, 995],
        "udp_ports": [],
        "is_splunk_indexer": False,
        "audit_log": "/var/log/auth.log",
    },
    "debian": {
        "role": "Debian Splunk Server (172.20.240.20)",
        "pkg_mgr": "apt-get",
        "tcp_ports": [22, 8000, 8089, 9997],
        "udp_ports": [123],
        "is_splunk_indexer": True,
        "audit_log": "/var/log/auth.log",
    },
}

server = ""
sysadmin_pass = ""
root_pass = ""
splunk_user = "admin"
splunk_pass = ""
run_sys_upgrade = False


def run_cmd(cmd, input_text=None, check=True):
    return subprocess.run(cmd, input=input_text, capture_output=True, text=True, check=check)


def detect_distro():
    if os.path.exists("/etc/os-release"):
        data = Path("/etc/os-release").read_text().lower()
        for distro in HOST_PROFILES:
            if f"id={distro}" in data or f'id="{distro}"' in data:
                return distro
    return ""


def init_env():
    WARDEN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WARDEN_DIR, 0o700)
    logging.basicConfig(
        level=logging.INFO,
        filename=str(LOG_PATH),
        filemode="a",
        format="%(asctime)s - %(levelname)s - [WARDEN] %(message)s",
    )


def prologue():
    global server, sysadmin_pass, root_pass, splunk_user, splunk_pass, run_sys_upgrade

    if os.geteuid() != 0:
        print("ERROR: Run as root (sudo python3 warden.py).")
        sys.exit(1)

    init_env()
    detected = detect_distro()
    prompt = (
        f"Select Server {list(HOST_PROFILES.keys())} [{detected}]: "
        if detected
        else f"Select Server {list(HOST_PROFILES.keys())}: "
    )

    while server not in HOST_PROFILES:
        choice = input(prompt).strip().lower()
        server = choice if choice else detected

    profile = HOST_PROFILES[server]
    print(f"\n>>> Deploying WARDEN on {profile['role']} <<<")

    while True:
        sysadmin_pass = getpass.getpass("Enter NEW 'sysadmin' password: ")
        if sysadmin_pass and sysadmin_pass == getpass.getpass("Confirm 'sysadmin' password: "):
            break
        print("Mismatch or empty. Try again.")

    while True:
        root_pass = getpass.getpass("Enter NEW 'root' password: ")
        if root_pass and root_pass == getpass.getpass("Confirm 'root' password: "):
            break
        print("Mismatch or empty. Try again.")

    if not profile["is_splunk_indexer"]:
        splunk_user = input("Splunk Forwarder Admin User [admin]: ").strip() or "admin"
        splunk_pass = getpass.getpass("Splunk Forwarder Password: ")

    ans = input("Run OS package upgrade? (y/N - skip for fastest deploy): ").strip().lower()
    run_sys_upgrade = (ans == "y")


def rotate_passwords():
    print("[1/5] Rotating 'root' and 'sysadmin' passwords...")
    payload = f"root:{root_pass}\n"
    if run_cmd(["id", "sysadmin"], check=False).returncode == 0:
        payload += f"sysadmin:{sysadmin_pass}\n"
    run_cmd(["chpasswd"], input_text=payload, check=True)
    logging.info("Rotated root and sysadmin passwords.")


def ensure_base_tools():
    print("[2/5] Syncing time & ensuring nftables is present...")
    run_cmd(["timedatectl", "set-ntp", "true"], check=False)
    if server == "debian":
        run_cmd(["systemctl", "enable", "--now", "chrony"], check=False)

    mgr = HOST_PROFILES[server]["pkg_mgr"]
    if not shutil.which("nft") or run_sys_upgrade:
        if mgr == "apt-get":
            run_cmd(["apt-get", "update"], check=True)
            if run_sys_upgrade:
                run_cmd(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "upgrade", "-y"], check=True)
            run_cmd(["apt-get", "install", "-y", "nftables"], check=True)
        else:
            if run_sys_upgrade:
                run_cmd(["dnf", "upgrade", "-y"], check=True)
            run_cmd(["dnf", "install", "-y", "nftables"], check=True)


def init_db_and_deploy():
    print("[3/5] Initializing /opt/warden/warden.db & deploying daemon/CLI...")
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS accepted_ports (
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            PRIMARY KEY (port, protocol)
        );
        CREATE TABLE IF NOT EXISTS blocked_ports (
            port INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS allowed_services (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS blocked_services (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS allowed_users (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS blocked_users (
            name TEXT PRIMARY KEY
        );
    """)

    profile = HOST_PROFILES[server]
    for p in profile["tcp_ports"]:
        cur.execute("INSERT OR IGNORE INTO accepted_ports (port, protocol) VALUES (?, 'tcp')", (p,))
    for p in profile["udp_ports"]:
        cur.execute("INSERT OR IGNORE INTO accepted_ports (port, protocol) VALUES (?, 'udp')", (p,))

    core_users = [
        "root", "sysadmin", "nobody", "splunk", "splunkfwd", "mysql", "mariadb",
        "www-data", "apache", "nginx", "postfix", "dovecot", "vmail",
    ]
    for u in core_users:
        cur.execute("INSERT OR IGNORE INTO allowed_users (name) VALUES (?)", (u,))

    core_services = [
        "warden.service", "nftables.service", "sshd.service", "ssh.service",
        "chrony.service", "Splunkd.service", "SplunkForwarder.service",
        "httpd.service", "apache2.service", "nginx.service", "postfix.service", "dovecot.service",
    ]
    for s in core_services:
        cur.execute("INSERT OR IGNORE INTO allowed_services (name) VALUES (?)", (s,))

    cur.execute("INSERT OR IGNORE INTO whitelist (ip) VALUES ('192.0.2.1')")
    cur.execute("INSERT OR IGNORE INTO blacklist (ip) VALUES ('198.51.100.1')")
    conn.commit()
    conn.close()
    os.chmod(DB_PATH, 0o600)

    # Deploy background daemon & interactive CLI directly into /usr/bin
    daemon_src = SCRIPT_DIR / "warden_daemon.py"
    if daemon_src.exists():
        shutil.copy(str(daemon_src), "/usr/bin/warden_daemon.py")
        os.chmod("/usr/bin/warden_daemon.py", 0o700)
    else:
        print(f"ERROR: {daemon_src} not found!")

    cli_src = SCRIPT_DIR / "gatekeeper.py"
    if cli_src.exists():
        shutil.copy(str(cli_src), "/usr/bin/gatekeeper")
        os.chmod("/usr/bin/gatekeeper", 0o700)
        if not os.path.exists("/usr/local/bin/gatekeeper"):
            os.symlink("/usr/bin/gatekeeper", "/usr/local/bin/gatekeeper")
    else:
        print(f"ERROR: {cli_src} not found!")

    svc_src = SCRIPT_DIR / "warden.service"
    if svc_src.exists():
        shutil.copy(str(svc_src), "/etc/systemd/system/warden.service")
        os.chmod("/etc/systemd/system/warden.service", 0o644)
    else:
        print(f"ERROR: {svc_src} not found!")

    (WARDEN_DIR / "quarantine").mkdir(exist_ok=True)
    os.chmod(WARDEN_DIR / "quarantine", 0o600)

    run_cmd(
        ["restorecon", "-Rv", "/opt/warden", "/usr/bin/warden_daemon.py", "/usr/bin/gatekeeper", "/etc/systemd/system"],
        check=False,
    )
    run_cmd(["systemctl", "daemon-reload"], check=True)
    run_cmd(["systemctl", "enable", "--now", "warden.service"], check=True)
    logging.info("Warden SQLite DB, CLI (gatekeeper), and daemon deployed.")


def enforce_firewall():
    print("[4/5] Masking ufw/firewalld & enforcing gatekeeper_fw.sh...")
    for fw in ["ufw", "firewalld"]:
        run_cmd(["systemctl", "stop", fw], check=False)
        run_cmd(["systemctl", "disable", fw], check=False)
        run_cmd(["systemctl", "mask", fw], check=False)

    fw_script = SCRIPT_DIR / "gatekeeper_fw.sh"
    if not fw_script.exists():
        print(f"ERROR: {fw_script} not found!")
        sys.exit(1)

    os.chmod(fw_script, 0o700)
    profile = HOST_PROFILES[server]
    env = os.environ.copy()
    env["TARGET_SERVER"] = server
    env["ALLOWED_TCP_PORTS"] = ",".join(str(p) for p in profile["tcp_ports"])
    env["ALLOWED_UDP_PORTS"] = ",".join(str(p) for p in profile["udp_ports"])

    subprocess.run([str(fw_script)], env=env, check=True)
    logging.info("Firewall enforced via gatekeeper_fw.sh.")


def configure_splunk():
    print("[5/5] Configuring Splunk Universal Forwarder...")
    if HOST_PROFILES[server]["is_splunk_indexer"]:
        print("      Host is Debian Splunk Indexer — skipping forwarder setup.")
        return

    splunk_bin = Path("/opt/splunkforwarder/bin/splunk")
    if not splunk_bin.is_file():
        print("      WARNING: /opt/splunkforwarder/bin/splunk not found.")
        return

    seed_dir = Path("/opt/splunkforwarder/etc/system/local")
    seed_dir.mkdir(parents=True, exist_ok=True)
    seed_file = seed_dir / "user-seed.conf"
    seed_file.write_text(f"[user_info]\nUSERNAME = {splunk_user}\nPASSWORD = {splunk_pass}\n")
    os.chmod(seed_file, 0o600)

    run_cmd([str(splunk_bin), "restart", "--accept-license", "--answer-yes", "--no-prompt"], check=False)
    auth = f"{splunk_user}:{splunk_pass}"
    target = f"{SPLUNK_INDEXER_IP}:{SPLUNK_FORWARD_PORT}"
    run_cmd([str(splunk_bin), "add", "forward-server", target, "-auth", auth], check=False)

    monitors = [
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
        str(LOG_PATH),
        HOST_PROFILES[server]["audit_log"],
    ]
    for path in monitors:
        if os.path.exists(path):
            run_cmd([str(splunk_bin), "add", "monitor", path, "-auth", auth], check=False)

    run_cmd([str(splunk_bin), "enable", "boot-start"], check=False)
    run_cmd([str(splunk_bin), "restart"], check=False)
    logging.info(f"Splunk forwarder configured -> {target}")


def verify_health():
    print("\n=== WARDEN POST-DEPLOY STATUS ===")
    services = ["nftables.service", "warden.service"]
    if server == "debian":
        services.append("chrony.service")

    for svc in services:
        status = run_cmd(["systemctl", "is-active", svc], check=False).stdout.strip()
        print(f"[{'OK' if status == 'active' else 'FAIL'}] {svc}: {status}")
    print("Admin CLI ready: run 'sudo gatekeeper' anytime to ban IPs or manage ports.\n")


def main():
    prologue()
    if len(sys.argv) > 1:
        flag = sys.argv[1]
        actions = {
            "-p": rotate_passwords,
            "--passwords": rotate_passwords,
            "-f": enforce_firewall,
            "--firewall": enforce_firewall,
            "-s": configure_splunk,
            "--splunk": configure_splunk,
            "-v": verify_health,
            "--verify": verify_health,
        }
        if flag in actions:
            actions[flag]()
        else:
            print(f"Unknown flag: {flag}")
    else:
        rotate_passwords()
        ensure_base_tools()
        init_db_and_deploy()
        enforce_firewall()
        configure_splunk()
        verify_health()


if __name__ == "__main__":
    main()
