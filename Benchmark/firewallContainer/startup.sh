#!/bin/bash

# Firewall/Router Startup Script
# This script initializes the firewall container

echo "=== VM4 Firewall/Router Starting ==="

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding


Start rsyslog for logging
service rsyslog start

# Wait for network interfaces to be ready
sleep 5

# Get network interface information
ATTACKER_INTERFACE=$(ip route | grep "192.168.100.0/24" | head -1 | awk '{print $3}')
HONEYPOT_INTERFACE=$(ip route | grep "172.20.0.0/24" | head -1 | awk '{print $3}')

echo "Attacker network interface: $ATTACKER_INTERFACE"
echo "Honeypot network interface: $HONEYPOT_INTERFACE"

# Initialize firewall rules
/firewall/scripts/init_firewall.sh

# Set up routing
/firewall/scripts/setup_routing.sh

# Start firewall management API
echo "Starting Firewall Management API..."
cd /firewall
python3 scripts/firewall_api.py &

# Start traffic monitoring
#echo "Starting Traffic Monitor..."
#python3 scripts/traffic_monitor.py &

echo "=== VM4 Firewall/Router Ready ==="

# Keep container running and show logs
touch /var/log/syslog /firewall/logs/firewall.log
tail -f /var/log/syslog /firewall/logs/firewall.log
