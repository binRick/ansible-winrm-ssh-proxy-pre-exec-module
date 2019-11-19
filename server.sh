#!/bin/bash
set -e
sudo csf -r
sudo iptables -t nat -A OUTPUT -d 74.125.136.101 -p tcp --dport 443 -j DNAT --to-destination 127.0.0.100:10443
sudo iptables -t nat -A POSTROUTING -d 74.125.136.101 -p tcp --dport 443 -j MASQUERADE
sudo sysctl -w net.ipv4.conf.all.route_localnet=1
ssh -oServerAliveInterval=60 -L127.0.0.100:10443:74.125.136.101:443 vpn299 sleep 9999
