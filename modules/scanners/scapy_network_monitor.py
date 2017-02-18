#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Network monitor using scapy
# author: anotherik (Ricardo Gonçalves)

# Supress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import os, signal, sys, string
import manufacturer.parse_manufacturer as manufacturer

manufacturer_table = "manufacturer/manufacturer_table.txt"
table_of_manufacturers = {}

access_points = set()
encryption = "0"
vendor = ""
channel = 1
spaces = 0

class colors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WHITE = '\033[37m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	GRAY = '\033[90m'
	UNDERLINE = '\033[4m'

def aps_lookup(pkt):
	global channel
	os.system("iwconfig %s channel %s" % (interface,channel) )
	global table_of_manufacturers
	table_of_manufacturers = manufacturer.MacParser(manufacturer_table).refresh()

	# we are checking if ssid is already in the access_points list (and we also want same ssid with different bssid)
	if ( (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and (pkt[Dot11].info not in access_points) ):

		access_points.add(pkt[Dot11].info)
		ssid = pkt[Dot11].info
		bssid = pkt[Dot11].addr3
		channel = int(ord(pkt[Dot11Elt:3].info))
		capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
		        {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

		manufacturer_data = manufacturer.search(table_of_manufacturers,str(pkt.addr2))
		vendor = manufacturer_data[0].comment

		if re.search("privacy", capability): encryption = "1"
		else: encryption = "0"

		spaces = 23 - len(ssid)
		spaces = ' '*spaces
		spaces2 = 26 - len(vendor)
		spaces2 = ' '*spaces2
		if encryption=="0":
			print colors.OKGREEN+"%2d  %s%s%s  %s%s%s" % (int(channel), ssid, spaces, bssid, vendor, spaces2, encryption) +colors.ENDC
		else:	
			print "%2d  %s%s%s  %s%s%s" % (int(channel), ssid, spaces, bssid, vendor, spaces2, encryption)

	channel = random.randrange(1,12)

def printHeader():
	print colors.BOLD + "CH  SSID                   BSSID              BRAND                     ENCRYPTION" + colors.ENDC

def scapy_scan(i):
	global interface
	interface = i
	printHeader()
	sniff(iface=interface, prn=aps_lookup)	
