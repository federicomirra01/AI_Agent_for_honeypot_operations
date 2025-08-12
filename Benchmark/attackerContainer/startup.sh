#!/bin/bash

# Script to configure attacker container routing and test firewall connectivity
# Run this script on the attacker container

echo "=== Configuring Attacker Container Routing ==="

# Add route to honeypot network via VM4 firewall
echo "Adding route to honeypot network via VM4 firewall..."
ip route add 172.20.0.0/24 via 192.168.100.254

tail -f /dev/null
