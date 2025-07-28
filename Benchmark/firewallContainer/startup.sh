#!/bin/bash

echo "=== VM4 Firewall/Router Starting ==="

# Clean up log files from previous runs
echo "Cleaning up previous logs..."
> /firewall/logs/firewall.log
> /var/log/syslog

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# DNS configuration
echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
# Fix rsyslog startup - create necessary directories and config
mkdir -p /var/spool/rsyslog
chown syslog:adm /var/spool/rsyslog

# Start rsyslog in foreground mode to avoid daemon timeout issues
echo "Starting rsyslog..."
rsyslogd -n &
RSYSLOG_PID=$!
sleep 2

# Check if rsyslog started successfully
if ps -p $RSYSLOG_PID > /dev/null 2>&1; then
    echo "✅ rsyslog started successfully"
else
    echo "⚠️  rsyslog failed to start, continuing without it"
fi

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

# Ensure only one instance of each service runs
echo "Stopping any existing services..."
pkill -f "firewall_api.py" 2>/dev/null || true
pkill -f "suricata_API.py" 2>/dev/null || true
sleep 1

# Verify no processes are running
if pgrep -f "firewall_api.py" > /dev/null; then
    echo "⚠️  Warning: firewall_api.py still running, force killing..."
    pkill -9 -f "firewall_api.py" || true
    sleep 1
fi

# Start firewall management API
echo "Starting Firewall Management API..."
cd /firewall
python3 scripts/firewall_api.py > /firewall/logs/firewall.log 2>&1 &
FIREWALL_API_PID=$!

# Wait for API to start and verify
sleep 3
if ps -p $FIREWALL_API_PID > /dev/null 2>&1; then
    echo "✅ Firewall API started successfully (PID: $FIREWALL_API_PID)"

    # Test API connectivity
    if curl -s --connect-timeout 5 http://192.168.200.2:5000/health > /dev/null 2>&1; then
        echo "✅ Firewall API responding to health checks"
    else
        echo "⚠️  Firewall API not responding yet"
    fi
else
    echo "❌ Firewall API failed to start"
    echo "Last 10 lines of firewall log:"
    tail -10 /firewall/logs/firewall.log
fi

# Start suricata API service
echo "Starting Suricata API Service..."
python3 scripts/suricata_API.py > /firewall/logs/suricata_API.log 2>&1 &

SURICATA_PID=$!
sleep 1
# Verify suricata started
if ps -p $SURICATA_PID > /dev/null 2>&1; then
    echo "✅ Suricata started successfully (PID: $SURICATA_PID)"

    # Test API connectivity
    if curl -s --connect-timeout 5 http://192.168.200.2:7000/health > /dev/null 2>&1; then
        echo "✅ Suricata API responding to health checks"
    else
        echo "⚠️  Suricata  API not responding yet"
    fi
else
    echo "❌ Suricata API failed to start"
    echo "Last 10 lines of Suricata API log:"
    tail -10 /firewall/logs/suricata_api.log
fi

# Function to cleanup processes on exit
cleanup() {
    echo "Cleaning up processes..."
    kill $FIREWALL_API_PID 2>/dev/null || true
    kill $RSYSLOG_PID 2>/dev/null || true
    kill $SURICATA_PID 2>/dev/null || true

    # Force kill if still running
    sleep 1
    pkill -9 -f "firewall_api.py" 2>/dev/null || true
    pkill -9 -f "suricata_API.py" 2>/dev/null || true
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

echo ""
echo "=== VM4 Firewall/Router Ready ==="
echo "Firewall API: http://192.168.200.2:5000"
echo "Suricata API: http://192.168.200.2:7000"
echo ""
echo "Log Files:"
echo "  Firewall logs: /firewall/logs/firewall.log"
echo "  Suricata logs: /suricata/logs/suricata_api.log"

# Show currently running services
echo ""
echo "Currently running services:"
ps aux | grep -E "(firewall_api|rsyslog|suricata_API)" | grep -v grep | while read line; do
    echo "  $line"
done

# Health check loop
echo ""
echo "Performing periodic health checks..."
while true; do
    sleep 30

    # Check if processes are still running
    if ! ps -p $FIREWALL_API_PID > /dev/null 2>&1; then
        echo "❌ Firewall API died (PID: $FIREWALL_API_PID)"
        break
    fi
    
    if ! ps -p $SURICATA_PID > /dev/null 2>&1; then
        echo "❌ Suricata API died (PID: $SURICATA_PID)"
        break
    fi

    # Test API endpoints every 5 minutes
    if [ $(($(date +%s) % 300)) -eq 0 ]; then
        echo "🔍 Health check at $(date)"
        curl -s http://192.168.200.2:5000/health || echo "  ⚠️  Firewall API not responding"
        curl -s http://192.168.200.2:7000/health || echo "  ⚠️  Suricata API not responding"
    fi
done

echo "❌ One or more services failed, exiting..."
cleanup
