#!/usr/bin/env python3
"""
================================================================================
GATEKEEPER — Live Firewall & Policy Admin CLI (/usr/local/bin/gatekeeper)
================================================================================
Run `sudo gatekeeper` during the competition to:
  - Immediately ban Red Team IPs or CIDR subnets into @blacklist
  - Open/close TCP or UDP ports for injects
  - Lock rogue users or quarantine rogue systemd services
================================================================================
"""

import os
import sys
import sqlite3
import ipaddress
import logging
import subprocess

if os.geteuid() != 0:
    print("ERROR: Run as root (sudo gatekeeper).")
    sys.exit(1)

DB_PATH = "/opt/warden/warden.db"
LOG_PATH = "/opt/warden/warden.log"
NFT_CONF = "/etc/sysconfig/nftables.conf"

logging.basicConfig(
    level=logging.INFO,
    filename=LOG_PATH,
    filemode="a",
    format="%(asctime)s - %(levelname)s - [GATEKEEPER] %(message)s",
)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()


def is_valid_net(val):
    try:
        ipaddress.ip_network(val, strict=False)
        return True
    except ValueError:
        return False


def reload_nftables():
    tcp_ports = [str(r[0]) for r in cur.execute("SELECT port FROM accepted_ports WHERE protocol='tcp' ORDER BY port")]
    udp_ports = [str(r[0]) for r in cur.execute("SELECT port FROM accepted_ports WHERE protocol='udp' ORDER BY port")]
    bl_ips = [r[0] for r in cur.execute("SELECT ip FROM blacklist ORDER BY ip")] or ["198.51.100.1"]
    wl_ips = [r[0] for r in cur.execute("SELECT ip FROM whitelist ORDER BY ip")] or ["192.0.2.1"]

    lines = [
        "#!/usr/sbin/nft -f",
        "flush ruleset",
        "table inet filter {",
        "    set blacklist {",
        "        type ipv4_addr",
        "        flags interval",
        f"        elements = {{ {', '.join(bl_ips)} }}",
        "    }",
        "    set whitelist {",
        "        type ipv4_addr",
        "        flags interval",
        f"        elements = {{ {', '.join(wl_ips)} }}",
        "    }",
        "    chain input {",
        "        type filter hook input priority 0;",
        "        policy drop;",
        "        ip saddr @blacklist drop",
        '        iif "lo" accept',
        "        ct state established,related accept",
        "        ct state invalid drop",
        "        ip saddr @whitelist accept",
        "        ip protocol icmp accept",
        "        ip6 nexthdr icmpv6 accept",
    ]
    if tcp_ports:
        lines.append(f"        tcp dport {{ {', '.join(tcp_ports)} }} accept")
    if udp_ports:
        lines.append(f"        udp dport {{ {', '.join(udp_ports)} }} accept")

    lines.extend([
        "    }",
        "    chain forward { type filter hook forward priority 0; policy drop; }",
        "    chain output { type filter hook output priority 0; policy accept; }",
        "}",
        "",
    ])

    tmp = "/etc/sysconfig/nftables.conf.tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines))
    os.chmod(tmp, 0o600)

    check = subprocess.run(["nft", "-c", "-f", tmp], capture_output=True, text=True)
    if check.returncode != 0:
        print(f"[ERROR] Syntax validation failed:\n{check.stderr}")
        os.remove(tmp)
        return

    os.replace(tmp, NFT_CONF)
    subprocess.run(["nft", "-f", NFT_CONF], check=True)
    print("[+] Firewall reloaded.")


def ban_ip():
    ip = input("Malicious IP or CIDR to ban (e.g. 10.10.10.5 or 10.10.10.0/24): ").strip()
    if not is_valid_net(ip):
        print("Invalid IP/CIDR.")
        return
    cur.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
    cur.execute("INSERT OR IGNORE INTO blacklist (ip) VALUES (?)", (ip,))
    conn.commit()
    logging.warning(f"BANNED {ip} in @blacklist")
    reload_nftables()


def allow_ip():
    ip = input("Trusted IP or CIDR to whitelist: ").strip()
    if not is_valid_net(ip):
        print("Invalid IP/CIDR.")
        return
    cur.execute("DELETE FROM blacklist WHERE ip=?", (ip,))
    cur.execute("INSERT OR IGNORE INTO whitelist (ip) VALUES (?)", (ip,))
    conn.commit()
    logging.info(f"WHITELISTED {ip}")
    reload_nftables()


def open_port():
    try:
        port = int(input("Port (1-65535): ").strip())
        assert 1 <= port <= 65535
    except (ValueError, AssertionError):
        print("Invalid port.")
        return
    proto = input("Protocol (tcp/udp) [tcp]: ").strip().lower() or "tcp"
    if proto not in ("tcp", "udp"):
        print("Must be tcp or udp.")
        return
    cur.execute("DELETE FROM blocked_ports WHERE port=?", (port,))
    cur.execute("INSERT OR REPLACE INTO accepted_ports (port, protocol) VALUES (?, ?)", (port, proto))
    conn.commit()
    logging.info(f"Opened {proto.upper()} {port}")
    reload_nftables()


def close_port():
    try:
        port = int(input("Port to close: ").strip())
    except ValueError:
        print("Invalid port.")
        return
    cur.execute("DELETE FROM accepted_ports WHERE port=?", (port,))
    cur.execute("INSERT OR IGNORE INTO blocked_ports (port) VALUES (?)", (port,))
    conn.commit()
    logging.info(f"Closed port {port}")
    reload_nftables()


def block_user():
    user = input("Username to lock: ").strip()
    if not user or user in ("root", "sysadmin"):
        print("Protected account.")
        return
    cur.execute("DELETE FROM allowed_users WHERE name=?", (user,))
    cur.execute("INSERT OR IGNORE INTO blocked_users (name) VALUES (?)", (user,))
    conn.commit()
    logging.warning(f"Flagged user {user} for lock")


def block_service():
    svc = input("Service unit to quarantine (e.g. evil.service): ").strip()
    if not svc:
        return
    cur.execute("DELETE FROM allowed_services WHERE name=?", (svc,))
    cur.execute("INSERT OR IGNORE INTO blocked_services (name) VALUES (?)", (svc,))
    conn.commit()
    logging.warning(f"Flagged service {svc} for quarantine")


def show_status():
    print("\n--- WARDEN ACTIVE POLICY ---")
    print("Accepted Ports :", cur.execute("SELECT port, protocol FROM accepted_ports").fetchall())
    print("Blacklist IPs  :", [r[0] for r in cur.execute("SELECT ip FROM blacklist")])
    print("Whitelist IPs  :", [r[0] for r in cur.execute("SELECT ip FROM whitelist")])
    print("Blocked Users  :", [r[0] for r in cur.execute("SELECT name FROM blocked_users")])
    print("Blocked Svcs   :", [r[0] for r in cur.execute("SELECT name FROM blocked_services")])
    input("\nPress Enter...")


def main():
    menu = [
        ("1. Ban IP/CIDR (Immediate Drop)", ban_ip),
        ("2. Whitelist IP/CIDR", allow_ip),
        ("3. Open Port (TCP/UDP)", open_port),
        ("4. Close Port", close_port),
        ("5. Lock/Block User", block_user),
        ("6. Quarantine Service", block_service),
        ("7. View Current Policy", show_status),
        ("0. Exit", lambda: sys.exit(0)),
    ]
    while True:
        print("\n=== GATEKEEPER CLI ===")
        for label, _ in menu:
            print(label)
        choice = input("Select: ").strip()
        for label, fn in menu:
            if label.startswith(f"{choice}."):
                fn()
                break


if __name__ == "__main__":
    main()
