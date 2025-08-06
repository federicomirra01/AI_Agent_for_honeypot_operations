#!/bin/bash

# Initialize Firewall Rules
# Sets up basic iptables configuration

echo "Initializing firewall rules..."

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTP access to management API
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -p tcp --dport 6000 -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Enable NAT for outbound internet access from honeypot containers
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -o eth0 -j MASQUERADE

# Allow all outbound traffic from honeypot containers to internet
#iptables -A FORWARD -s 172.20.0.0/24 -o eth0 -j ACCEPT

# Allow return traffic from internet to honeypot containers (established/related only)
#iptables -A FORWARD -i eth0 -d 172.20.0.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow containers to communicate with each other within the honeypot network
iptables -A FORWARD -s 172.20.0.0/24 -d 172.20.0.0/24 -j ACCEPT

# Block traffic between attacker network and honeypot network (will be modified by AI agent)
# These rules block direct communication between the two networks
iptables -A FORWARD -s 192.168.100.0/24 -d 172.20.0.0/24 -j DROP
iptables -A FORWARD -s 172.20.0.0/24 -d 192.168.100.0/24 -j DROP

# Log dropped packets for analysis
iptables -A FORWARD -j LOG --log-prefix "FIREWALL-DROP: " --log-level 4

# Save rules
mkdir -p /firewall/rules
iptables-save > /firewall/rules/current_rules.txt

echo "Basic firewall rules initialized"
echo "DNS and outbound traffic from containers (172.20.0.0/24) is ALLOWED"
echo "Traffic between attacker network (192.168.100.0/24) and honeypot (172.20.0.0/24) is BLOCKED"
echo "Use the API or AI agent to modify rules dynamically"
