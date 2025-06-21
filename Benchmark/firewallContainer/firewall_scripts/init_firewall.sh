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

# Enable NAT for outbound internet access from honeypot
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -o eth0 -j MASQUERADE


# Allow honeypot containers to reach the internet
iptables -A FORWARD -s 172.20.0.0/24 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -d 172.20.0.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Basic forwarding rules (will be modified by AI agent)
# Initially drop all forwarding from attacker to honeypot
#iptables -A FORWARD -s 192.168.100.0/24 -d 172.20.0.0/24 -j DROP
iptables -A INPUT -s 192.168.100.0/24 -d 172.20.0.0/24 -j ACCEPT
iptables -A OUTPUT -s 192.168.100.0/24 -d 172.20.0.0/24 -j ACCEPT

#iptables -A FORWARD -s 172.20.0.0/24 -d 192.168.100.0/24 -j DROP
iptables -A INPUT -s 172.20.0.0/24 -d 192.168.100.0/24 -j ACCEPT
iptables -A OUTPUT -s 172.20.0.0/24 -d 192.168.100.0/24 -j ACCEPT
# Log dropped packets for analysis
iptables -A FORWARD -j LOG --log-prefix "FIREWALL-DROP: " --log-level 4

# Save rules
iptables-save > /firewall/rules/current_rules.txt

echo "Basic firewall rules initialized"
echo "All traffic from attacker network (192.168.100.0/24) to honeypot (172.20.0.0/24) is currently BLOCKED"
echo "Use the API or AI agent to modify rules dynamically"
