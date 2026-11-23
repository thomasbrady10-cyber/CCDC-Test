#!/usr/bin/env python3
"""
================================================================================
WARDEN DAEMON — Continuous Host Persistence & Intrusion Monitor
================================================================================
PURPOSE:
    Runs continuously in the background as a systemd service (`warden.service`),
    sweeping the host every 15 seconds for Red Team persistence and active C2.

SIX DEFENSIVE SWEEPS PER CYCLE:
    1. User Audit:       Locks any newly created UID 0, GID 0, or login user not
                         present in the initial baseline or allowed_users table.
    2. SSH Login Audit:  Logs all new SSH logins for Incident Reports and kills
                         any active TTY session originating from @blacklist.
    3. Socket C2 Sweep:  Inspects live ESTABLISHED TCP sockets via `ss -tnap`
                         and kills any shell or scripting interpreter holding an
                         unauthorized external socket (catches reverse shells
                         regardless of full path or obfuscated arguments).
    4. Crontab Guard:    Detects unauthorized modifications to /etc/crontab, logs
                         the injected payload for IR, and restores the baseline.
    5. Unit Quarantine:  Stops, disables, and moves any flagged systemd service
                         file into /opt/warden/quarantine/.
    6. Shell Integrity:  Detects symlink, hard-link (inode), or SHA-256 hash
                         tampering on /bin/bash, /bin/sh, /sbin/nologin,
                         /bin/false, and all shells in /etc/shells.
================================================================================
"""

import os
import re
import time
import signal
import shutil
import hashlib
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

# Binaries that should never hold direct external TCP connections on a server
SUSPICIOUS_SHELL_BINARIES = {
    "bash", "sh", "dash", "zsh", "ash", "ksh",
    "nc", "ncat", "netcat", "socat",
    "python", "python3", "perl", "ruby", "php",
}

# Loopback and trusted internal IPs excluded from outbound socket kills
# (Add your Splunk Indexer IP here if Splunk runs custom alert scripts)
TRUSTED_OUTBOUND_IPS = {"127.0.0.1", "::1"}

# Interactive shells that grant command execution
INTERACTIVE_SHELLS = {
    "/bin/bash", "/usr/bin/bash",
    "/bin/sh", "/usr/bin/sh",
    "/bin/dash", "/usr/bin/dash",
    "/bin/zsh", "/usr/bin/zsh",
}

# Restricted shells meant to block interactive logins for service accounts
RESTRICTED_SHELLS = {
    "/sbin/nologin", "/usr/sbin/nologin",
    "/bin/false", "/usr/bin/false",
}

# In-memory baselines captured when the daemon starts
baseline_users = set()
baseline_crontab = ""
baseline_shell_hashes = {}
seen_logins = set()
alerted_shell_anomalies = set()


def run_cmd(cmd):
    """Execute a system command safely and return stripped stdout."""
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()


def get_passwd():
    """Parse /etc/passwd into {username: (uid, gid, login_shell)}."""
    users = {}
    with open("/etc/passwd") as f:
        for line in f:
            p = line.strip().split(":")
            if len(p) >= 7:
                users[p[0]] = (int(p[2]), int(p[3]), p[6])
    return users


def get_monitored_shells():
    """Collect all interactive, restricted, and /etc/shells paths present on disk."""
    shells = set(INTERACTIVE_SHELLS | RESTRICTED_SHELLS)
    etc_shells = Path("/etc/shells")
    if etc_shells.is_file():
        for line in etc_shells.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                shells.add(line)
    return sorted(shells)


def hash_file(path_str):
    """Return SHA-256 hex digest of a file, or None if missing/unreadable."""
    try:
        h = hashlib.sha256()
        with open(path_str, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def init_baselines():
    """Snapshot known-good /etc/passwd, /etc/crontab, and shell binary hashes at boot."""
    global baseline_users, baseline_crontab, baseline_shell_hashes
    baseline_users = set(get_passwd().keys())

    cron = Path("/etc/crontab")
    if cron.is_file():
        baseline_crontab = cron.read_text()

    for sp in get_monitored_shells():
        digest = hash_file(sp)
        if digest:
            baseline_shell_hashes[sp] = digest

    logging.info(
        f"Baselines captured ({len(baseline_users)} users, {len(baseline_shell_hashes)} shell binaries)."
    )


def sweep():
    """Execute one full 6-part defensive audit cycle."""
    global seen_logins

    # Reload dynamic policies from SQLite on every sweep so `gatekeeper` CLI
    # changes take effect within 15 seconds without restarting the daemon.
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    allowed_users = {r[0] for r in cur.execute("SELECT name FROM allowed_users")}
    blocked_users = {r[0] for r in cur.execute("SELECT name FROM blocked_users")}
    blocked_services = {r[0] for r in cur.execute("SELECT name FROM blocked_services")}
    whitelist_ips = {r[0] for r in cur.execute("SELECT ip FROM whitelist")}
    blacklist_ips = {r[0] for r in cur.execute("SELECT ip FROM blacklist")}
    conn.close()

    # --------------------------------------------------------------------------
    # 1. LOCAL USER ACCOUNT AUDIT
    # --------------------------------------------------------------------------
    for user, (uid, gid, shell) in get_passwd().items():
        if user == "root" or user in allowed_users or user in baseline_users:
            continue
        # Flag backdoor UID 0/GID 0 accounts, newly added human UIDs (>=1000), or CLI-blocked users
        if user in blocked_users or uid == 0 or gid == 0 or (1000 <= uid < 65534):
            logging.error(f"ROGUE USER DETECTED: {user} (UID={uid}, GID={gid}, Shell={shell})")
            run_cmd(["usermod", "-L", "-s", "/usr/sbin/nologin", user])

    # --------------------------------------------------------------------------
    # 2. ACTIVE SSH / TTY LOGIN AUDIT
    # --------------------------------------------------------------------------
    for line in run_cmd(["who"]).splitlines():
        parts = line.split()
        if len(parts) >= 5:
            user, tty, t_str = parts[0], parts[1], parts[3]
            ip = parts[4].strip("()")
            key = f"{user}@{tty}@{ip}@{t_str}"
            if key in seen_logins:
                continue
            seen_logins.add(key)

            # Immediately kill TTY sessions from banned IPs
            if ip in blacklist_ips:
                run_cmd(["pkill", "-KILL", "-t", tty])
                logging.error(f"TERMINATED blacklisted SSH session: user={user} ip={ip} tty={tty}")
            elif ip not in whitelist_ips:
                logging.warning(f"SSH login observed: user={user} ip={ip} tty={tty}")

    # --------------------------------------------------------------------------
    # 3. OUTBOUND SOCKET REVERSE SHELL & C2 SWEEP
    # --------------------------------------------------------------------------
    # Inspect active ESTABLISHED TCP sockets rather than regex-matching `ps` so
    # shells invoked via PATH (`bash -i`), Python, Perl, or nc are caught reliably.
    my_pid = os.getpid()
    ss_out = run_cmd(["ss", "-tnap", "state", "established"])
    for line in ss_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue

        local_addr, peer_addr = parts[2], parts[3]
        proc_info = " ".join(parts[4:])

        # Extract remote peer IP and local port (handles IPv4 and [IPv6]:port)
        peer_ip = peer_addr.rsplit(":", 1)[0].strip("[]")
        local_port = local_addr.rsplit(":", 1)[-1]

        if peer_ip in TRUSTED_OUTBOUND_IPS or peer_ip in whitelist_ips:
            continue

        # Parse process binary name and PID from ss output: users:(("bash",pid=1234,fd=0))
        match = re.search(r'\(\("([^"]+)",pid=(\d+),', proc_info)
        if not match:
            continue

        comm, pid_str = match.group(1), match.group(2)
        pid = int(pid_str)

        # Terminate any shell/interpreter holding an external socket (excluding inbound SSH on 22)
        if pid != my_pid and comm in SUSPICIOUS_SHELL_BINARIES and local_port != "22":
            try:
                cmdline = (
                    Path(f"/proc/{pid}/cmdline")
                    .read_bytes()
                    .replace(b"\x00", b" ")
                    .decode(errors="ignore")
                    .strip()
                )
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

    # --------------------------------------------------------------------------
    # 4. /ETC/CRONTAB INTEGRITY GUARD
    # --------------------------------------------------------------------------
    cron = Path("/etc/crontab")
    if cron.is_file():
        current = cron.read_text()
        if current != baseline_crontab:
            logging.error(f"CRONTAB TAMPERED! Captured contents:\n{current.strip()}")
            cron.write_text(baseline_crontab)

    # --------------------------------------------------------------------------
    # 5. QUARANTINE BLACKLISTED SYSTEMD UNITS
    # --------------------------------------------------------------------------
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
                logging.error(f"QUARANTINED malicious service unit: {unit}")

    # --------------------------------------------------------------------------
    # 6. SHELL BINARY, SYMLINK, HARD-LINK & SHA-256 HASH INTEGRITY CHECK
    # --------------------------------------------------------------------------
    # Catches Red Team persistence where /sbin/nologin or /bin/false is symlinked,
    # hard-linked (same inode), or overwritten with /bin/bash or /bin/sh.
    interactive_hashes = {}
    interactive_inodes = {}

    for sp in INTERACTIVE_SHELLS:
        p = Path(sp)
        if p.exists():
            digest = hash_file(sp)
            if digest:
                interactive_hashes[digest] = sp
            st = p.stat()
            interactive_inodes[(st.st_dev, st.st_ino)] = sp

    for sp in get_monitored_shells():
        p = Path(sp)
        if not p.exists():
            continue

        # A. Detect symlink tampering (e.g., /sbin/nologin -> /bin/bash)
        if p.is_symlink():
            resolved = str(p.resolve())
            if sp in RESTRICTED_SHELLS and resolved in INTERACTIVE_SHELLS:
                key = f"symlink:{sp}->{resolved}"
                if key not in alerted_shell_anomalies:
                    alerted_shell_anomalies.add(key)
                    logging.error(
                        f"CRITICAL SHELL TAMPER (SYMLINK): {sp} points to interactive shell {resolved}!"
                    )

        # B. Detect hard links (shared inode) or binary copies replacing nologin/false
        st = p.stat()
        digest = hash_file(sp)
        if sp in RESTRICTED_SHELLS:
            inode_key = (st.st_dev, st.st_ino)
            if inode_key in interactive_inodes:
                key = f"hardlink:{sp}=={interactive_inodes[inode_key]}"
                if key not in alerted_shell_anomalies:
                    alerted_shell_anomalies.add(key)
                    logging.error(
                        f"CRITICAL SHELL TAMPER (HARD LINK): {sp} shares inode {st.st_ino} with {interactive_inodes[inode_key]}!"
                    )
            elif digest and digest in interactive_hashes:
                key = f"hashmatch:{sp}=={interactive_hashes[digest]}"
                if key not in alerted_shell_anomalies:
                    alerted_shell_anomalies.add(key)
                    logging.error(
                        f"CRITICAL SHELL TAMPER (HASH MATCH): {sp} has identical SHA-256 ({digest[:16]}...) to {interactive_hashes[digest]}!"
                    )

        # C. Detect post-deploy binary modification against initial startup baseline
        if sp in baseline_shell_hashes and digest and digest != baseline_shell_hashes[sp]:
            key = f"modified:{sp}:{digest}"
            if key not in alerted_shell_anomalies:
                alerted_shell_anomalies.add(key)
                logging.error(
                    f"CRITICAL SHELL MODIFIED: {sp} SHA-256 changed from "
                    f"{baseline_shell_hashes[sp][:16]}... to {digest[:16]}...!"
                )


if __name__ == "__main__":
    init_baselines()
    while True:
        try:
            sweep()
        except Exception as exc:
            logging.error(f"Sweep error: {exc}")
        time.sleep(15)
