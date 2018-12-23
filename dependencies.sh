#!/bin/bash
# anotherik

printf "  [Run as root] This will install all the required dependencies...\n"
printf "  Choose your distro:\n\t(1) Debian based\n\t(2) Red Hat based\n\t(3) Arch\n\t(4) Open suse\n"
read choice

case "$choice" in
	"1") apt-get install python2.7 
	     apt-get install python-pip
	     apt-get install wireless-tools
	     apt-get install iw
	;;
	"2") yum install epel-release
	     yum install python2.7	
	     yum install python-pip
	     yum install wireless-tools
	     yum install iw
	;;
	"3") pacman -S python2.7
	     pacman -S python-pip
	     pacman -S wireless_tools
	     pacman -S iw
	;;
	"4") zypper install python2
	     zypper install python-pip
	     zypper install wireless-tools
	     zypper install iw
	;;
	*) 
	   printf "Bye\n"
	   exit 1
esac

pip install -r requirements.txt
printf "Finished"
