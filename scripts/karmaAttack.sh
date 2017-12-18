#!/bin/bash
iface=$1
sudo airmon-ng start $iface
sleep 2
echo $iface"mon"
sudo airbase-ng -c 6 -P -C 20 -v $iface"mon"
#sudo airmon-ng stop $iface"mon"

