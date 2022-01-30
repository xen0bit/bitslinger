#!/bin/bash

echo "Routing packets to nfqueue...";
sudo iptables -t raw -A PREROUTING -p tcp --tcp-flags PSH,ACK PSH,ACK --source-port 9999 -j NFQUEUE --queue-num 0

while true
do
    read -p "Ready to stop routing packets to nfqueue? [y/n]: "
    if [ "$REPLY" = "y" ]; then
    echo "Removing routes."
    sudo iptables -F -t raw
    exit 0
    fi
done