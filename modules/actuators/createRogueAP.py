#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Rogue Access Point Detector
# version: 2.0
# author: anotherik (Ricardo Gonçalves)

##################################
#  Hive Mode - Create Rogue APs  #
##################################

# Supress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess, signal, struct, sys
import modules.manage_interfaces as manage_interfaces

def getRogueApParams():
	# rogueAP_configs (essid, bssid, ch, enc)
	with open('profiles/rogueAP.txt') as fp:
	    for line in fp:
	        print line.strip()
	        params = line.split()
	fp.close()
	return params        

def signal_handler(signal, frame):
	manage_interfaces.disable_monitor(interface)
	print("Goodbye! ")
	sys.exit(0)	

def startRogueAP(i):

	global interface
	interface = i
	params = getRogueApParams()
	ap_name = params[0] # read essid from config file

	broadcast = ":".join(["ff"]*6)
	bssid = params[1] # read bssid from config file
	channel = struct.pack('<Q', int(params[2]))[:1]
	enc = params[3] # Open, WEP, WPA

	print "HERE: "+params[0]+params[1]+params[2]+params[3]

	while True:

		essid = ap_name

		radioTapHeader = RadioTap()
		dot11Header = Dot11(addr1 = broadcast, addr2 = bssid, addr3 = bssid)

		dot11Elt1 = Dot11Elt( ID=0, info = essid)
		dot11Elt2 = Dot11Elt( ID=1, info = "\x82\x84\x8b\x96\x12\x24\x48\x6c")
		dot11Elt3 = Dot11Elt( ID=3, info = channel)
		dot11Elt4 = Dot11Elt( ID=5, info = "\x04\x01\x03\x00\x04")
		dot11Elt5 = Dot11Elt( ID=50, info = "\x8c\x98\xb0\x60")

		if (enc == "Open"):
			dot11BeaconHeaderOpen = Dot11Beacon(cap = 0x00)
			pkt = radioTapHeader / dot11Header / dot11BeaconHeaderOpen / dot11Elt1 / dot11Elt2 / dot11Elt3 / dot11Elt4 / dot11Elt5			
		if (enc == "WEP"):
			dot11BeaconHeaderWEP = Dot11Beacon(cap = 0x1104)
			pkt = radioTapHeader / dot11Header / dot11BeaconHeaderWEP / dot11Elt1 / dot11Elt2 / dot11Elt3 / dot11Elt4 / dot11Elt5
		if (enc == "WPA"):
			dot11BeaconHeaderWPA = Dot11Beacon(cap = 0x310c)
			rsn = Dot11Elt(ID='RSNinfo', info=(
			'\x01\x00'                 # RSN Version 1
			'\x00\x0f\xac\x02'         # Group Cipher Suite : 00-0f-ac TKIP
			'\x02\x00'                 # 2 Pairwise Cipher Suites (next two lines)
			'\x00\x0f\xac\x04'         # AES Cipher
			'\x00\x0f\xac\x02'         # TKIP Cipher
			'\x01\x00'                 # 1 Authentication Key Managment Suite (line below)
			'\x37\x68\x33\x20\x35\x75\x70\x33\x72\x20\x35\x33\x63\x75\x72\x33\x20\x70\x34\x35\x35\x77\x30\x72\x64\x21'  # Pre-Shared Key
			'\x00\x00'))               # RSN Capabilities (no extra capabilities)

			pkt = radioTapHeader / dot11Header / dot11BeaconHeaderWPA / dot11Elt1 / dot11Elt2 / dot11Elt3 / dot11Elt4 / dot11Elt5 / rsn


		ch = int(ord(pkt[Dot11Elt:3].info)) # for debug purposes
		print ("Rogue ap with essid: "+essid+" in channel: "+ str(ch))

		sendp(pkt, iface=interface) #, count=100, inter=0.5
		
		signal.signal(signal.SIGINT, signal_handler)
