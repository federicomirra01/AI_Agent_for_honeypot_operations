#!/bin/sh
# Set up the gateway for the containers
#ip route del default
#ip route add default via 172.20.0.254

ip route add 192.168.100.0/24 via 172.20.0.254

