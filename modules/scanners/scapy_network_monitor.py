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
import modules.detectors.evil_twin_detector as detector1
import data.manipulate_db as db_api

manufacturer_table = "manufacturer/manufacturer_table.txt"
table_of_manufacturers = {}

access_points = set()
encryption = "0"
vendor = ""
spaces = 0

global current_ch
current_ch = 1

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
	global table_of_manufacturers, current_ch
	table_of_manufacturers = manufacturer.MacParser(manufacturer_table).refresh()

	if(current_ch >= 13):
		current_ch = 1
	os.system("iw dev %s set channel %d" % (interface, current_ch) )
	#os.system("iwconfig %s channel %s" % (interface, current_ch) )
	time.sleep(0.1)

	# we are checking if ssid is already in the access_points list (and we also want same ssid with different bssid)
	if ( (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and (pkt[Dot11].addr3 not in access_points) ):

		access_points.add(pkt[Dot11].addr3)
		ssid = pkt[Dot11].info
		bssid = pkt[Dot11].addr3
		channel = int(ord(pkt[Dot11Elt:3].info))
		capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
		        {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

		manufacturer_data = manufacturer.search(table_of_manufacturers,str(pkt.addr2))
		if(manufacturer_data == []):
			vendor = "Not Found"
		else:
			vendor = manufacturer_data[0].comment

		if re.search("privacy", capability): encryption = "1"
		else: encryption = "0"

		spaces = 23 - len(ssid)
		spaces = ' '*spaces
		spaces2 = 26 - len(vendor)
		spaces2 = ' '*spaces2
		if encryption=="0":
			print colors.OKGREEN+"%s%s%s  %2d  %s%s%s" % (ssid, spaces, bssid, int(channel), vendor, spaces2, encryption) +colors.ENDC
		else:	
			print "%s%s%s  %2d  %s%s%s" % (ssid, spaces, bssid, int(channel), vendor, spaces2, encryption)
		db_api.insert_in_db_scapy(conn, ssid, bssid, int(channel), vendor, encryption)

	current_ch+=1
	signal.signal(signal.SIGINT, signal_handler)

# disable monitor mode to the given interface
def disable_monitor():
	print("\nChanging "+str(interface)+" to managed mode.")
	os.system("ifconfig %s down" % interface)
	os.system("iwconfig %s mode managed" % interface)
	os.system("ifconfig %s up" % interface)

def signal_handler(signal, frame):
	db_api.select_from_db(conn)
	disable_monitor()
	print("Goodbye! ")
	sys.exit(0)


def printHeader():
	print colors.WARNING + "SSID                   BSSID              CH  BRAND                     ENCRYPTION" + colors.ENDC

def scapy_scan(i):
	global interface
	interface = i
	printHeader()
	global conn
	conn = db_api.open_db()
	conn.text_factory = str
	db_api.create_table_scapy(conn)
	sniff(iface=interface, prn=aps_lookup)	
