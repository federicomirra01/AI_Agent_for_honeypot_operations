#!/bin/bash
echo "=== Configuring Attacker Container Routing ==="

# Add route to honeypot network via VM4 firewall
echo "Adding route to honeypot network via VM4 firewall..."
ip route add 172.20.0.0/24 via 192.168.100.254

tail -f /dev/null
