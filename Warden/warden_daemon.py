#!/usr/bin/env python3
"""
================================================================================
WARDEN DAEMON — Continuous Linux Host Intrusion & Forensic Quarantine Monitor
================================================================================
PURPOSE:
    Runs continuously in the background via systemd (`warden.service`), scanning
    every 5 seconds to detect, freeze, and package Red Team activity for CCDC
    Incident Reports (IRs) WITHOUT destroying forensic evidence:
      1. Reverse-Shell & C2 Process Quarantine (`SIGSTOP` + IR Bundle):
         Instead of `SIGKILL` (which wipes `/proc/<pid>`), freezes suspicious
         processes holding external sockets using `SIGSTOP` so they cannot
         execute commands or beacon out, then generates a ready-to-submit
         forensic folder in `/opt/warden/quarantine/IR_<timestamp>_pid<PID>/`
         complete with a plain-English explanation, parent process chain,
         command line, environment variables, and open file descriptors.
      2. Unauthorized User & SSH Session Enforcement: Locks rogue accounts and
         suspends/terminates unauthorized sessions.
      3. Malicious Systemd Unit Quarantine: Stops, disables, masks, and moves
         any unit in `blocked_services` into `/opt/warden/quarantine/`.
      4. Crontab Tamper Reversion: Saves the tampered `/etc/crontab` into
         quarantine as IR evidence before restoring the clean baseline.
      5. Shell Binary Integrity Guard: Monitors SHA-256 hashes of `/bin/bash`,
         `/bin/sh`, `/sbin/nologin`, and `/bin/false`.
================================================================================
"""

import os
import re
import pwd
import time
import shutil
import signal
import hashlib
import logging
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path

DB_PATH = "/opt/warden/warden.db"
LOG_PATH = "/opt/warden/warden.log"
QUARANTINE_DIR = Path("/opt/warden/quarantine")

# Internal trusted infrastructure peers that legitimate processes may talk to:
# Loopback + Debian Splunk (.20) + 2022 AD (.100) + 2019 MSSQL (.120)
TRUSTED_OUTBOUND_IPS = {
    "127.0.0.1",
    "::1",
    "172.20.240.20",
    "172.20.240.100",
    "172.20.240.120",
}

# Shells & scripting interpreters that should NEVER hold direct external sockets
SUSPICIOUS_SOCKET_PROCS = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh",
    "nc", "ncat", "netcat", "socat",
    "python", "python2", "python3", "perl", "ruby", "php", "lua",
}

# System binaries that should NEVER be moved/deleted from /bin or /usr/bin
# (we copy them for hashing instead of moving them)
PROTECTED_SYSTEM_PATHS = {
    "/bin/bash", "/usr/bin/bash",
    "/bin/sh", "/usr/bin/sh",
    "/bin/dash", "/usr/bin/dash",
    "/usr/bin/python3", "/usr/bin/python",
    "/usr/bin/perl", "/usr/bin/php", "/usr/bin/ruby",
}

# Critical shell/nologin binaries watched for SHA-256 hash drift
WATCHED_BINARIES = [
    "/bin/bash",
    "/bin/sh",
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
]

# Track PIDs already frozen via SIGSTOP so we don't re-generate duplicate IR folders
# every 5 seconds while the frozen process sits in quarantine
FROZEN_PIDS = set()

logging.basicConfig(
    level=logging.INFO,
    filename=LOG_PATH,
    filemode="a",
    format="%(asctime)s - %(levelname)s - [DAEMON] %(message)s",
)


def sha256_file(path: str) -> str:
    """Compute SHA-256 digest of a file on disk (returns empty string if unreadable)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def get_policy():
    """Fetch current allowed/blocked users and blocked services from warden.db."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    allowed_users = {r[0] for r in cur.execute("SELECT name FROM allowed_users")}
    blocked_users = {r[0] for r in cur.execute("SELECT name FROM blocked_users")}
    blocked_svcs = {r[0] for r in cur.execute("SELECT name FROM blocked_services")}
    conn.close()
    return allowed_users, blocked_users, blocked_svcs


def explain_threat(proc_name: str, peer: str, cmdline: str, exe_path: str) -> str:
    """
    Generate a plain-English explanation of WHY Warden quarantined this process
    so Blue Team can paste it straight into an Incident Response (IR) form.
    """
    p = proc_name.lower()
    reasons = []

    if p in {"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh"}:
        reasons.append(
            f"Interactive command shell ('{proc_name}') was caught holding an active "
            f"network socket to external IP {peer}. Standard shells never open raw "
            f"TCP connections on their own; this is a classic reverse-shell or bind-shell indicator."
        )
    elif p in {"nc", "ncat", "netcat", "socat"}:
        reasons.append(
            f"Raw network relay utility ('{proc_name}') established a socket to {peer}, "
            f"commonly used for manual reverse shells, port relays, or file exfiltration."
        )
    elif p in {"python", "python2", "python3", "perl", "ruby", "php", "lua"}:
        reasons.append(
            f"Scripting interpreter ('{proc_name}') opened an unauthorized outbound/external "
            f"socket to {peer}. Attackers frequently use one-liner scripts or web-shell "
            f"child processes to establish C2 callbacks."
        )
    else:
        reasons.append(
            f"Process '{proc_name}' held an unauthorized external network connection to {peer}."
        )

    if any(tmp_dir in exe_path or tmp_dir in cmdline for tmp_dir in ("/tmp/", "/dev/shm/", "/var/tmp/")):
        reasons.append(
            "Execution originated from a world-writable temporary directory (/tmp, /dev/shm, or /var/tmp), "
            "strongly indicating a dropped Red Team payload."
        )

    if "deleted" in exe_path:
        reasons.append(
            "The underlying binary on disk was deleted while running (fileless/self-deleting malware technique)."
        )

    return " ".join(reasons)


def build_parent_chain(pid: int) -> str:
    """Walk /proc/<pid>/status upward to reconstruct the full process ancestry tree."""
    chain = []
    curr = pid
    visited = set()
    while curr > 1 and curr not in visited:
        visited.add(curr)
        try:
            status_text = Path(f"/proc/{curr}/status").read_text(errors="ignore")
            name_m = re.search(r"^Name:\s*(.+)$", status_text, re.M)
            ppid_m = re.search(r"^PPid:\s*(\d+)$", status_text, re.M)
            uid_m = re.search(r"^Uid:\s*(\d+)", status_text, re.M)
            name = name_m.group(1).strip() if name_m else "?"
            uid = uid_m.group(1) if uid_m else "?"
            cmd = (
                Path(f"/proc/{curr}/cmdline")
                .read_bytes()
                .replace(b"\x00", b" ")
                .decode(errors="ignore")
                .strip()
            )
            chain.append(f"PID {curr} (UID {uid}) [{name}]: {cmd}")
            curr = int(ppid_m.group(1)) if ppid_m else 0
        except OSError:
            break
    return "\n  -> ".join(chain) if chain else "Unavailable"


def quarantine_process(pid: int, proc_name: str, local_addr: str, peer: str):
    """
    1. Freeze the process immediately via `SIGSTOP` so it cannot run commands
       or transmit data while preserving `/proc/<pid>` intact in memory.
    2. Collect full forensic artifacts and write an IR summary into
       `/opt/warden/quarantine/IR_<timestamp>_pid<pid>_<proc>/`.
    3. Copy the suspicious binary (if not a core system interpreter) and compute
       its SHA-256 hash for your Incident Report.
    """
    # Freeze process execution immediately (reversible with `kill -CONT <pid>` if needed)
    try:
        os.kill(pid, signal.SIGSTOP)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        logging.error(f"Failed to SIGSTOP PID {pid}: {exc}")
        return

    FROZEN_PIDS.add(pid)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ir_dir = QUARANTINE_DIR / f"IR_{ts}_pid{pid}_{proc_name}"
    ir_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(ir_dir, 0o700)

    # Read /proc/<pid> metadata while the process is safely frozen
    try:
        cmdline = (
            Path(f"/proc/{pid}/cmdline")
            .read_bytes()
            .replace(b"\x00", b" ")
            .decode(errors="ignore")
            .strip()
        )
    except OSError:
        cmdline = "<unreadable>"

    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe_path = "<unknown>"

    try:
        cwd_path = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        cwd_path = "<unknown>"

    parent_chain = build_parent_chain(pid)
    explanation = explain_threat(proc_name, peer, cmdline, exe_path)

    # Copy executable binary to quarantine for hashing/submission (never move /bin/bash!)
    bin_sha256 = "N/A"
    copied_note = "System interpreter left in place (not moved)."
    clean_exe = exe_path.replace(" (deleted)", "")
    if clean_exe and clean_exe not in PROTECTED_SYSTEM_PATHS:
        dest_bin = ir_dir / f"quarantined_binary_{Path(clean_exe).name}"
        try:
            # Reading from /proc/<pid>/exe works even if the file was unlinked on disk!
            shutil.copyfile(f"/proc/{pid}/exe", str(dest_bin))
            os.chmod(dest_bin, 0o600)
            bin_sha256 = sha256_file(str(dest_bin))
            copied_note = f"Copied executable to {dest_bin}"
        except OSError as exc:
            copied_note = f"Could not copy binary: {exc}"
    elif os.path.exists(clean_exe):
        bin_sha256 = sha256_file(clean_exe)

    # Dump environment variables (/proc/<pid>/environ)
    try:
        env_raw = Path(f"/proc/{pid}/environ").read_bytes().replace(b"\x00", b"\n").decode(errors="ignore")
        (ir_dir / "environ.txt").write_text(env_raw)
    except OSError:
        pass

    # Dump open file descriptors & sockets (/proc/<pid>/fd)
    fd_lines = []
    fd_dir = Path(f"/proc/{pid}/fd")
    if fd_dir.exists():
        for fd in sorted(fd_dir.iterdir(), key=lambda x: x.name):
            try:
                fd_lines.append(f"fd {fd.name} -> {os.readlink(fd)}")
            except OSError:
                pass
    (ir_dir / "open_files.txt").write_text("\n".join(fd_lines) + "\n")

    # Write human-readable Incident Report summary file
    report_text = f"""================================================================================
WARDEN AUTOMATED INCIDENT REPORT (IR) EVIDENCE PACKET
================================================================================
Timestamp         : {datetime.now().isoformat()}
Action Taken      : PROCESS FROZEN IN QUARANTINE (SIGSTOP) — NOT KILLED
Process Name      : {proc_name}
PID               : {pid}
Local Socket      : {local_addr}
Remote Attacker   : {peer}
Executable Path   : {exe_path}
Binary SHA-256    : {bin_sha256}
Binary Handling   : {copied_note}
Working Directory : {cwd_path}
Full Command Line : {cmdline}

PLAIN-ENGLISH EXPLANATION (WHY THIS WAS FLAGGED):
  {explanation}

PROCESS ANCESTRY TREE (PARENT -> CHILD):
  -> {parent_chain}

OPERATOR NEXT STEPS FOR INCIDENT RESPONSE:
  1. Ban attacker IP via: sudo gatekeeper  (Option 1 -> {peer.rsplit(':', 1)[0]})
  2. Review open_files.txt and environ.txt in this folder ({ir_dir})
  3. After submitting your Incident Report, terminate the frozen PID with:
       sudo kill -9 {pid}
     (Or if this was a false positive, resume it with: sudo kill -CONT {pid})
================================================================================
"""
    report_file = ir_dir / "incident_report.txt"
    report_file.write_text(report_text)
    os.chmod(report_file, 0o600)

    logging.critical(
        f"QUARANTINED PROCESS (SIGSTOP) | proc={proc_name} pid={pid} peer={peer} "
        f"ir_folder={ir_dir} reason='{explanation}'"
    )


def quarantine_reverse_shells():
    """
    Inspect all ESTABLISHED TCP connections via `ss -tnap`. If a shell or
    scripting interpreter holds a socket to an untrusted remote IP, freeze it
    with `SIGSTOP` and capture an Incident Report packet.
    """
    # Prune PIDs from FROZEN_PIDS if an operator manually killed them
    for tracked_pid in list(FROZEN_PIDS):
        if not os.path.exists(f"/proc/{tracked_pid}"):
            FROZEN_PIDS.discard(tracked_pid)

    res = subprocess.run(["ss", "-tnap"], capture_output=True, text=True, check=False)
    for line in res.stdout.splitlines():
        if "ESTAB" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        local_addr = parts[3]
        peer = parts[4]
        peer_ip = peer.rsplit(":", 1)[0].strip("[]")
        if peer_ip in TRUSTED_OUTBOUND_IPS:
            continue

        proc_matches = re.findall(r'\("([^"]+)",pid=(\d+),', line)
        for proc_name, pid_str in proc_matches:
            pid = int(pid_str)
            if pid in FROZEN_PIDS:
                continue
            if proc_name.lower() in SUSPICIOUS_SOCKET_PROCS:
                quarantine_process(pid, proc_name, local_addr, peer)


def enforce_users(allowed_users, blocked_users):
    """
    Lock rogue UID >= 1000 or explicitly blocked users (`usermod -L -s /sbin/nologin`)
    and freeze their active processes (`SIGSTOP`) for IR inspection.
    """
    for entry in pwd.getpwall():
        user = entry.pw_name
        if user in ("root", "sysadmin"):
            continue
        is_rogue = (user in blocked_users) or (entry.pw_uid >= 1000 and user not in allowed_users)
        if is_rogue:
            # Only act if the user isn't already locked to /sbin/nologin
            if entry.pw_shell != "/sbin/nologin":
                logging.warning(f"LOCKING ROGUE USER: {user} (UID={entry.pw_uid})")
                subprocess.run(["usermod", "-L", "-s", "/sbin/nologin", user], check=False)
                subprocess.run(["pkill", "-STOP", "-u", user], check=False)


def enforce_services(blocked_svcs):
    """Stop, disable, mask, and move any blacklisted unit file into quarantine."""
    for svc in blocked_svcs:
        unit = svc if svc.endswith(".service") else f"{svc}.service"
        unit_path = Path(f"/etc/systemd/system/{unit}")
        if unit_path.exists():
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            logging.critical(f"QUARANTINING ROGUE SERVICE: {unit}")
            subprocess.run(["systemctl", "stop", unit], check=False)
            subprocess.run(["systemctl", "disable", unit], check=False)
            subprocess.run(["systemctl", "mask", unit], check=False)
            shutil.move(str(unit_path), str(QUARANTINE_DIR / f"{ts}_{unit}"))
            subprocess.run(["systemctl", "daemon-reload"], check=False)


def main():
    logging.info("Warden forensic quarantine daemon started.")
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    baseline_hashes = {p: sha256_file(p) for p in WATCHED_BINARIES if os.path.exists(p)}
    crontab_path = Path("/etc/crontab")
    baseline_crontab = crontab_path.read_text() if crontab_path.exists() else ""

    while True:
        try:
            allowed_users, blocked_users, blocked_svcs = get_policy()
            quarantine_reverse_shells()
            enforce_users(allowed_users, blocked_users)
            enforce_services(blocked_svcs)

            # Save tampered /etc/crontab to quarantine for IR evidence before reverting
            if crontab_path.exists():
                current_cron = crontab_path.read_text()
                if current_cron != baseline_crontab:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    evidence_path = QUARANTINE_DIR / f"IR_{ts}_tampered_crontab.txt"
                    evidence_path.write_text(current_cron)
                    logging.critical(
                        f"TAMPER DETECTED in /etc/crontab — saved evidence to {evidence_path} and reverted!"
                    )
                    crontab_path.write_text(baseline_crontab)

            # Alert if any watched shell/nologin binary hash changes on disk
            for bin_path, orig_hash in baseline_hashes.items():
                curr_hash = sha256_file(bin_path)
                if curr_hash and curr_hash != orig_hash:
                    logging.critical(f"BINARY INTEGRITY ALERT: {bin_path} SHA-256 changed!")
                    baseline_hashes[bin_path] = curr_hash

        except Exception as exc:
            logging.error(f"Daemon loop error: {exc}")

        time.sleep(5)


if __name__ == "__main__":
    main()
