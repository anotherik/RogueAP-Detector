#!/bin/bash
printf "  [Run as root] This will install all the required dependencies...\n"
printf "  Choose your distro:\n\t(1) Debian based\n\t(2) Red Hat based\n\t(3) Arch\n"
read choice

case "$choice" in
	"1") apt-get install python2.7 
	     apt-get install python-pip
	;;
	"2") yum install epel-release
	     yum install python2.7	
	     yum install python-pip
	;;
	"3") pacman -S python2.7
	     pacman -S python-pip
	;;
	*) 
	   printf "Wrong Option!\n"
	   exit 1
esac

pip install -r requirements.txt
printf "Finished."
