#!/bin/bash

printf "Choose your distro:\n(1) Debian based\n(2) Red Hat based\n(3) Other\n"
read choice

case "$choice" in
	"1") apt-get install python-pip
	;;
	"2") dnf install python-pip
	;;
	"3") continue
	;;
esac

