#!/bin/sh
echo "Setting up gateway..."
apt update && apt install -y iproute2

ip route del default
ip route add default via 172.20.0.254
exec /usr/local/bin/configure-port.sh


