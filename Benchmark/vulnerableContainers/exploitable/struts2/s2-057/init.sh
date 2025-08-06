#!/bin/sh
echo "Setting up gateway..."
sleep 3
ip route del default
ip route add default via 172.20.0.254
exec catalina.sh run  # or original entrypoint
