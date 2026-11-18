in/env bash
set -euo pipefail

TCP_PORTS="${ALLOWED_TCP_PORTS:-}"
UDP_PORTS="${ALLOWED_UDP_PORTS:-}"

cat <<'EOF' > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    set blacklist {
        type ipv4_addr
        flags interval
        elements = { 198.51.100.1 }
    }

    set whitelist {
        type ipv4_addr
        flags interval
        elements = { 192.0.2.1 }
    }

    chain input {
        type filter hook input priority 0;
        policy drop;

        ip saddr @blacklist drop
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip saddr @whitelist accept

        # Competition Rule 12: Keep ICMP open for scored ping checks
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
EOF

if [[ -n "$TCP_PORTS" ]]; then
    echo "        tcp dport { ${TCP_PORTS} } accept" >> /etc/nftables.conf
fi

if [[ -n "$UDP_PORTS" ]]; then
    echo "        udp dport { ${UDP_PORTS} } accept" >> /etc/nftables.conf
fi

cat <<'EOF' >> /etc/nftables.conf
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
EOF

chmod 600 /etc/nftables.conf
nft -c -f /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable --now nftables
echo "[+] Gatekeeper firewall active | TCP={${TCP_PORTS:-none}} UDP={${UDP_PORTS:-none}}"
