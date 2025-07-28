#!/bin/sh
echo "Setting up gateway..."
echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && \
echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list && \
echo "deb http://archive.debian.org/debian buster-updates main" >> /etc/apt/sources.list && \
echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archived-repos && \
apt update && \
apt install -y iproute2

ip route del default
ip route add default via 172.20.0.254
exec /usr/local/bin/configure-port.sh


