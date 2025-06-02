#!/bin/bash

# Script to configure attacker container routing and test firewall connectivity
# Run this script on the attacker container

echo "=== Configuring Attacker Container Routing ==="

# First, let's see current network configuration
echo "Current network configuration:"
ip addr show
echo ""
echo "Current routing table:"
ip route
echo ""

# Add route to honeypot network via VM4 firewall
echo "Adding route to honeypot network via VM4 firewall..."
ip route add 172.20.0.0/24 via 192.168.100.254

# Verify the route was added
echo "Updated routing table:"
ip route
echo ""

# Test connectivity to VM4 firewall
echo "Testing connectivity to VM4 firewall (192.168.100.254)..."
ping -c 3 192.168.100.254

# Test firewall API accessibility
echo ""
echo "Testing Firewall API accessibility..."
curl -s http://192.168.100.254:5000/health || echo "Firewall API not accessible (expected - traffic blocked)"

echo ""
echo "=== Attacker routing configuration complete ==="
echo "Note: Traffic to honeypot network is still blocked by firewall rules"
echo "Use the firewall API to allow specific traffic"
tail -f /dev/null
