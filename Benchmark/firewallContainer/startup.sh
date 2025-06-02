#!/bin/bash

# Firewall/Router Startup Script with Packet Monitor
# This script initializes the firewall container with packet monitoring

echo "=== VM4 Firewall/Router Starting ==="

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Start rsyslog for logging
rsyslogd &
echo "rsyslog started"

# Wait for network interfaces to be ready
sleep 5

# Get network interface information
ATTACKER_INTERFACE=$(ip route | grep "192.168.100.0/24" | head -1 | awk '{print $3}')
HONEYPOT_INTERFACE=$(ip route | grep "172.20.0.0/24" | head -1 | awk '{print $3}')

echo "Attacker network interface: $ATTACKER_INTERFACE"
echo "Honeypot network interface: $HONEYPOT_INTERFACE"

# Initialize firewall rules
echo "Initializing firewall rules..."
/firewall/scripts/init_firewall.sh

# Set up routing
echo "Setting up routing..."
/firewall/scripts/setup_routing.sh

# Start firewall management API
echo "Starting Firewall Management API..."
cd /firewall
python3 scripts/firewall_api.py &
FIREWALL_API_PID=$!

# Wait a moment for API to start
sleep 3

# Start packet monitor API service
echo "Starting Packet Monitor API Service..."
python3 scripts/packet_monitor.py &
PACKET_MONITOR_PID=$!

# Function to cleanup processes on exit
cleanup() {
    echo "Cleaning up processes..."
    kill $FIREWALL_API_PID 2>/dev/null
    kill $PACKET_MONITOR_PID 2>/dev/null
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

echo "=== VM4 Firewall/Router Ready ==="
echo "Firewall API: http://localhost:5000"
echo "Packet Monitor API: http://localhost:6000"
echo "Agent Network: http://192.168.200.2:6000"
echo "Packet logs: /firewall/logs/packets.json"
echo "Monitor logs: /firewall/logs/packet_monitor.log"

# Keep container running and show logs
touch /var/log/syslog /firewall/logs/firewall.log /firewall/logs/packet_monitor.log
tail -f /var/log/syslog /firewall/logs/firewall.log /firewall/logs/packet_monitor.log