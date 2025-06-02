#!/bin/bash

# VM4 Firewall/Router Deployment Script

set -e

echo "=== VM4 Firewall/Router Deployment ==="

# Create necessary directories
echo "Creating project directories..."
mkdir -p firewall_scripts firewall_logs firewall_rules

# Create firewall scripts directory structure
mkdir -p firewall_scripts

# Copy the scripts we created into the firewall_scripts directory
cat > firewall_scripts/init_firewall.sh << 'EOF'
#!/bin/bash

# Initialize Firewall Rules
echo "Initializing firewall rules..."

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH access to this container
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP access to management API
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT

# Enable NAT for outbound internet access from honeypot
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -o eth0 -j MASQUERADE

# Initially DENY all forwarding from attacker to honeypot
iptables -A FORWARD -s 192.168.100.0/24 -d 172.20.0.0/24 -j DROP

# Log dropped packets
iptables -A FORWARD -j LOG --log-prefix "FIREWALL-DROP: " --log-level 4

# Save rules
mkdir -p /firewall/rules
iptables-save > /firewall/rules/current_rules.txt

echo "Basic firewall rules initialized"
EOF

cat > firewall_scripts/setup_routing.sh << 'EOF'
#!/bin/bash

echo "Setting up routing..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Show current routing table
echo "Current routing table:"
ip route

# Show network interfaces
echo "Network interfaces:"
ip addr show

echo "Routing setup complete"
EOF

# Make scripts executable
chmod +x firewall_scripts/*.sh

# Check if networks exist
if ! docker network inspect attacker_net >/dev/null 2>&1; then
    echo "❌ Attacker network doesn't exist. Please create it first."
    exit 1
fi

if ! docker network inspect thesis_net >/dev/null 2>&1; then
    echo "❌ Thesis network doesn't exist. Please create it first."
    exit 1
fi

# Build and deploy firewall container
echo "Building firewall container..."
docker build -f Dockerfile.firewall -t thesis-firewall .

echo "Starting firewall container..."
docker-compose -f docker-compose.firewall.yml up -d

# Wait for container to be ready
echo "Waiting for firewall container to be ready..."
sleep 10

# Check container status
if docker ps | grep -q vm4_firewall_router; then
    echo "✅ Firewall container is running successfully"

    # Show container network info
    echo ""
    echo "Container Network Information:"
    docker exec vm4_firewall_router ip addr show

    echo ""
    echo "Testing Firewall API..."
    sleep 5
    if curl -s http://localhost:5000/health >/dev/null; then
        echo "✅ Firewall API is responding"
    else
        echo "⚠️  Firewall API not responding yet (may need more time)"
    fi

    echo ""
    echo "=== Firewall Management ==="
    echo "API URL: http://localhost:5000"
    echo ""
    echo "To test API:"
    echo "  curl http://localhost:5000/health"
    echo "  curl http://localhost:5000/rules"
    echo ""
    echo "To add allow rule:"
    echo "  curl -X POST http://localhost:5000/rules/allow -H 'Content-Type: application/json' -d '{\"source_ip\":\"192.168.100.10\", \"dest_ip\":\"172.20.0.2\", \"port\":80}'"

else
    echo "❌ Failed to start firewall container"
    docker logs vm4_firewall_router
    exit 1
fi
