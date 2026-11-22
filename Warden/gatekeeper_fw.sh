#!/usr/bin/env bash
# ==============================================================================
# GATEKEEPER_FW.SH — CCDC Perimeter & Egress nftables Bootstrap Script
# ==============================================================================
# PURPOSE:
#   Builds a clean, stateful nftables ruleset from scratch with:
#     1. Default-DROP inbound policy (only scored ports, ICMP, and @whitelist pass).
#     2. Immediate @blacklist drop set for banning Red Team IPs/CIDRs.
#     3. Default-DROP outbound policy (blocks unauthorized reverse shells and
#        C2 beacons while allowing DNS, NTP, ICMP, Splunk, and OS updates).
#     4. Dual-path persistence (/etc/nftables.conf AND /etc/sysconfig/nftables.conf)
#        so firewall rules survive reboots on both Debian/Ubuntu and Rocky/RHEL.
# ==============================================================================

# Exit immediately on any command failure (-e), unset variable (-u), or pipe error
set -euo pipefail

# Read comma-separated port lists passed from setup.py (default empty if standalone)
TCP_PORTS="${ALLOWED_TCP_PORTS:-}"
UDP_PORTS="${ALLOWED_UDP_PORTS:-}"

# ------------------------------------------------------------------------------
# 1. WRITE BASE NFTABLES CONFIGURATION (/etc/nftables.conf)
# ------------------------------------------------------------------------------
cat <<'EOF' > /etc/nftables.conf
#!/usr/sbin/nft -f
# Clear any pre-existing iptables/nftables rules so we start from a known state
flush ruleset

table inet filter {
    # Dynamic set for malicious Red Team IPs/subnets (managed via `gatekeeper`)
    set blacklist {
        type ipv4_addr
        flags interval
        elements = { 198.51.100.1 }
    }

    # Dynamic set for trusted Blue Team jump hosts / scoring engines
    set whitelist {
        type ipv4_addr
        flags interval
        elements = { 192.0.2.1 }
    }

    # --------------------------------------------------------------------------
    # INBOUND TRAFFIC FILTER (Default Drop)
    # --------------------------------------------------------------------------
    chain input {
        type filter hook input priority 0;
        policy drop;

        # Drop blacklisted attackers before evaluating any accept rules
        ip saddr @blacklist drop

        # Allow local loopback communication (localhost services, IPC)
        iif "lo" accept

        # Allow return packets for outbound connections we initiated
        ct state established,related accept

        # Drop malformed/invalid packets early
        ct state invalid drop

        # Allow unrestricted access from whitelisted Blue Team admin IPs
        ip saddr @whitelist accept

        # Keep ICMP/ICMPv6 open for CCDC scoring engine ping checks
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
EOF

# Dynamically inject this host's scored TCP ports (e.g., 22, 80, 443)
if [[ -n "$TCP_PORTS" ]]; then
    echo "        tcp dport { ${TCP_PORTS} } accept" >> /etc/nftables.conf
fi

# Dynamically inject this host's scored UDP ports (e.g., 123, 514)
if [[ -n "$UDP_PORTS" ]]; then
    echo "        udp dport { ${UDP_PORTS} } accept" >> /etc/nftables.conf
fi

# ------------------------------------------------------------------------------
# 2. APPEND FORWARD & DEFAULT-DENY OUTBOUND CHAINS
# ------------------------------------------------------------------------------
cat <<'EOF' >> /etc/nftables.conf
    }

    # Block packet forwarding (this host is an endpoint, not a router)
    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    # --------------------------------------------------------------------------
    # OUTBOUND TRAFFIC FILTER (Default Drop — Anti-C2 / Anti-Reverse-Shell)
    # --------------------------------------------------------------------------
    chain output {
        type filter hook output priority 0;
        policy drop;

        # Allow loopback & replies to legitimate inbound client sessions
        oif "lo" accept
        ct state established,related accept
        ct state invalid drop

        # Allow essential infrastructure: DNS (53), NTP (123), and ICMP
        udp dport 53 accept
        tcp dport 53 accept
        udp dport 123 accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow Splunk Universal Forwarder -> Indexer (9997) & Mgmt (8089)
        tcp dport { 8089, 9997 } accept

        # Allow OS repository updates & package downloads (HTTP/HTTPS)
        tcp dport { 80, 443 } accept
    }
}
EOF

# ------------------------------------------------------------------------------
# 3. VALIDATE, APPLY, AND PERSIST ACROSS REBOOTS (DEBIAN/UBUNTU + ROCKY/RHEL)
# ------------------------------------------------------------------------------
chmod 600 /etc/nftables.conf

# Dry-run syntax check (-c) before loading into the kernel
nft -c -f /etc/nftables.conf
nft -f /etc/nftables.conf

# Rocky Linux / RHEL 9 boots nftables.service from /etc/sysconfig/nftables.conf
# rather than /etc/nftables.conf — mirror the file and restore SELinux context.
if [[ -d /etc/sysconfig ]]; then
    cp /etc/nftables.conf /etc/sysconfig/nftables.conf
    chmod 600 /etc/sysconfig/nftables.conf
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -v /etc/nftables.conf /etc/sysconfig/nftables.conf >/dev/null 2>&1 || true
    fi
fi

# Enable nftables at boot and ensure the service is currently active
systemctl enable --now nftables
echo "[+] Gatekeeper firewall active | TCP={${TCP_PORTS:-none}} UDP={${UDP_PORTS:-none}}"
