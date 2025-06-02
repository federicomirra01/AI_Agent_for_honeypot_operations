#!/bin/bash

# Setup Routing Between Networks
# Configures routing rules for traffic between attacker and honeypot networks

echo "Setting up routing..."

# Get interface names
ATTACKER_IFACE=$(ip route | grep "192.168.100.0/24" | head -1 | awk '{print $3}' 2>/dev/null || echo "eth0")
HONEYPOT_IFACE=$(ip route | grep "172.20.0.0/24" | head -1 | awk '{print $3}' 2>/dev/null || echo "eth1")

echo "Attacker interface: $ATTACKER_IFACE"
echo "Honeypot interface: $HONEYPOT_IFACE"

# Add routing rules
# Route traffic from attacker network to honeypot network via this container
ip route add 172.20.0.0/24 dev $HONEYPOT_IFACE 2>/dev/null || echo "Honeypot route already exists"
ip route add 192.168.100.0/24 dev $ATTACKER_IFACE 2>/dev/null || echo "Attacker route already exists"

# Add explicit routes
ip route add 192.168.100.0/24 dev eth0
ip route add 172.20.0.0/24 dev eth1

# Configure this container as the gateway for cross-network communication
# This will be handled by Docker networking, but we can add custom routes if needed

# Show current routing table
echo "Current routing table:"
ip route

# Show network interfaces
echo "Network interfaces:"
ip addr show

echo "Routing setup complete"
