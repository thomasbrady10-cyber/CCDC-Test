#!/usr/bin/env python3
"""
================================================================================
WARDEN DAEMON — Continuous Host Persistence & Intrusion Monitor
================================================================================
"""

import os
import re
import time
import signal
import shutil
import sqlite3
import logging
import subprocess
from pathlib import Path

DB_PATH = "/opt/warden/warden.db"
LOG_PATH = "/opt/warden/warden.log"
QUARANTINE_DIR = Path("/opt/warden/quarantine")

logging.basicConfig(
    level=logging.INFO,
    filename=LOG_PATH,
    filemode="a",
    format="%(asctime)s - %(levelname)s - [DAEMON] %(message)s",
)

SUSPICIOUS_SHELL_BINARIES = {
    "bash", "sh", "dash", "zsh", "ash", "ksh",
    "nc", "ncat", "netcat", "socat",
    "python", "python3", "perl", "ruby", "php",
}

# Add your Splunk Indexer IP here so Splunk scripts aren't flagged
TRUSTED_OUTBOUND_IPS = {"127.0.0.1", "::1"}

baseline_users = set()
baseline_crontab = ""
seen_logins = set()


def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()


def get_passwd():
    users = {}
    with open("/etc/passwd") as f:
        for line in f:
            p = line.strip().split(":")
            if len(p) >= 7:
                users[p[0]] = (int(p[2]), int(p[3]), p[6])
    return users


def init_baselines():
    global baseline_users, baseline_crontab
    baseline_users = set(get_passwd().keys())
    cron = Path("/etc/crontab")
    if cron.is_file():
        baseline_crontab = cron.read_text()
    logging.info(f"Baselines captured ({len(baseline_users)} users).")


def sweep():
    global seen_logins
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    allowed_users = {r[0] for r in cur.execute("SELECT name FROM allowed_users")}
    blocked_users = {r[0] for r in cur.execute("SELECT name FROM blocked_users")}
    blocked_services = {r[0] for r in cur.execute("SELECT name FROM blocked_services")}
    whitelist_ips = {r[0] for r in cur.execute("SELECT ip FROM whitelist")}
    blacklist_ips = {r[0] for r in cur.execute("SELECT ip FROM blacklist")}
    conn.close()

    # 1. User Audit (protects baseline & nobody/65534; locks new/rogue accounts)
    for user, (uid, gid, shell) in get_passwd().items():
        if user == "root" or user in allowed_users or user in baseline_users:
            continue
        if user in blocked_users or uid == 0 or gid == 0 or (1000 <= uid < 65534):
            logging.error(f"ROGUE USER: {user} (UID={uid}, GID={gid}, Shell={shell})")
            run_cmd(["usermod", "-L", "-s", "/usr/sbin/nologin", user])

    # 2. SSH / Login Session Audit (kills blacklisted IPs; logs unlisted IPs for IR)
    for line in run_cmd(["who"]).splitlines():
        parts = line.split()
        if len(parts) >= 5:
            user, tty, t_str = parts[0], parts[1], parts[3]
            ip = parts[4].strip("()")
            key = f"{user}@{tty}@{ip}@{t_str}"
            if key in seen_logins:
                continue
            seen_logins.add(key)
            if ip in blacklist_ips:
                run_cmd(["pkill", "-KILL", "-t", tty])
                logging.error(f"TERMINATED blacklisted SSH session: {user} from {ip} ({tty})")
            elif ip not in whitelist_ips:
                logging.warning(f"SSH login observed: user={user} ip={ip} tty={tty}")

    # 3. Outbound Socket Reverse Shell & C2 Sweep
    my_pid = os.getpid()
    ss_out = run_cmd(["ss", "-tnap", "state", "established"])
    for line in ss_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue

        local_addr, peer_addr = parts[2], parts[3]
        proc_info = " ".join(parts[4:])

        peer_ip = peer_addr.rsplit(":", 1)[0].strip("[]")
        local_port = local_addr.rsplit(":", 1)[-1]

        if peer_ip in TRUSTED_OUTBOUND_IPS or peer_ip in whitelist_ips:
            continue

        match = re.search(r'\(\("([^"]+)",pid=(\d+),', proc_info)
        if not match:
            continue

        comm, pid_str = match.group(1), match.group(2)
        pid = int(pid_str)

        # Kill any shell/interpreter holding an active external socket (excluding inbound SSH on port 22)
        if pid != my_pid and comm in SUSPICIOUS_SHELL_BINARIES and local_port != "22":
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore").strip()
            except Exception:
                cmdline = comm

            try:
                os.kill(pid, signal.SIGKILL)
                logging.error(
                    f"KILLED reverse shell socket PID={pid} BIN={comm} "
                    f"LOCAL={local_addr} PEER={peer_addr} CMD='{cmdline}'"
                )
            except (ProcessLookupError, PermissionError) as err:
                logging.error(f"Failed to kill PID={pid} ({comm}) -> {peer_addr}: {err}")

    # 4. Crontab Integrity
    cron = Path("/etc/crontab")
    if cron.is_file():
        current = cron.read_text()
        if current != baseline_crontab:
            logging.error(f"CRONTAB TAMPERED! Captured contents:\n{current.strip()}")
            cron.write_text(baseline_crontab)

    # 5. Blacklisted Systemd Units
    if blocked_services:
        for line in run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"]).splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit in blocked_services or unit.replace(".service", "") in blocked_services:
                run_cmd(["systemctl", "stop", unit])
                run_cmd(["systemctl", "disable", unit])
                unit_path = Path(f"/etc/systemd/system/{unit}")
                if unit_path.exists():
                    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(unit_path), str(QUARANTINE_DIR / unit))
                run_cmd(["systemctl", "daemon-reload"])
                logging.error(f"QUARANTINED service: {unit}")


if __name__ == "__main__":
    init_baselines()
    while True:
        try:
            sweep()
        except Exception as exc:
            logging.error(f"Sweep error: {exc}")
        time.sleep(15)
