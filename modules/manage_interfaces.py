#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Rogue Access Point Detector
# version: 2.0
# author: anotherik (Ricardo Gonçalves)

import os, random, string, sys, time
from itertools import imap
from random import randint

# optional: change the mac address of the interface performing the scan 
def change_mac(iface):
	print("Changing the interface mac address...")
	os.system("sudo ifconfig %s down" % iface)
	time.sleep(0.5)
	mac_sufix = "00:10:FF:" 
	mac_prefix = ':'.join(['%02x'%x for x in imap(lambda x:randint(0,255), range(3))])
	new_mac = mac_sufix+mac_prefix.upper()
	print("New MAC address: %s" % new_mac)
	try:
		os.system("sudo ifconfig %s hw ether %s" %(iface,new_mac))
		os.system("sudo ifconfig %s up" % iface)
	except Exception as e:
		print("Exception: %s" % e)
		sys.exit(0)
	
# enable monitor mode to the given interface
def enable_monitor(iface):
	print("Changing "+str(iface)+" to monitor mode.")
	os.system("ifconfig %s down" % iface)
	os.system("iwconfig %s mode monitor" % iface)
	os.system("ifconfig %s up" % iface)

# disable monitor mode to the given interface
def disable_monitor(iface):
	print("Changing "+str(iface)+" to managed mode.")
	os.system("ifconfig %s down" % iface)
	os.system("iwconfig %s mode managed" % iface)
	os.system("ifconfig %s up" % iface)
