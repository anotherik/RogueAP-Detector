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

  printf "starting AP...\n"
  airbase-ng -a $bssid -e $essid -c $channel $iface
done

printf "done2"
