#!/bin/sh

echo "Updating repository sources..."
cat > /etc/apt/sources.list << EOF
deb http://archive.debian.org/debian buster main
deb http://archive.debian.org/debian-security buster/updates main
EOF

echo "Installing network tools..."
apt-get update && apt-get install -y iproute2 sudo

mkdir -p /home/php
touch /home/php/flag.txt
chmod +r /home/php/flag.txt
echo "flag{user_access_php}" > /home/php/user.txt
chmod +s /usr/bin/find
echo "flag{privileged_access_php}" > /root/root.txt

echo "Setting up gateway..."
ip route del default
ip route add default via 172.20.0.254

service apache2 start && tail -f /var/log/apache2/access.log


