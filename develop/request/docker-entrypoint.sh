#!/usr/bin/env sh
set -e
LOCAL_DNS_IP=$(ping -c 1 "dnsmasq" | grep "64 bytes from " | awk '{print $4}' | cut -d":" -f1)
echo "$(echo -n "nameserver ${LOCAL_DNS_IP}
"; cat /etc/resolv.conf)" > /etc/resolv.conf

while :; do :; done & kill -STOP $! && wait $!