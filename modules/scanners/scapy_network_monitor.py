#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Network monitor using scapy
# author: anotherik (Ricardo Gonçalves)

# Supress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from multiprocessing import Queue, Process
import os, signal, sys, string
import manufacturer.parse_manufacturer as manufacturer
import data.manipulate_db as db_api
import modules.manage_interfaces as manage_interfaces
import modules.colors as colors
import modules.detectors.passive_detectors as passive_detectors

manufacturer_table = "manufacturer/manufacturer_table.txt"
table_of_manufacturers = {}

access_points = set()
encryption = "0"
vendor = ""
spaces = 0

def aps_lookup(pkt):
	global table_of_manufacturers
	table_of_manufacturers = manufacturer.MacParser(manufacturer_table).refresh()

	# we are checking if ssid is already in the access_points list (and we also want same ssid with different bssid)
	if ( (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and (pkt[Dot11].addr3 not in access_points) ):

		access_points.add(pkt[Dot11].addr3)
		ssid = pkt[Dot11].info
		bssid = pkt[Dot11].addr3
		channel = int(ord(pkt[Dot11Elt:3].info))
		capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
		        {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

		extra = pkt.notdecoded
		sig_str = -(256-ord(extra[-4:-3]))

		manufacturer_data = manufacturer.search(table_of_manufacturers,str(pkt.addr2))
		if(manufacturer_data == []):
			vendor = "Not Found"
		else:
			vendor = manufacturer_data[0].manuf

		if(str(vendor) == "None"):
			vendor = "Not Found"	

		if re.search("privacy", capability): encryption = "1"
		else: encryption = "0"

		# call passive detectors
		passive_detectors.authorized_aps_scapy(ssid, bssid, sig_str, encryption, profile)

		spaces = 23 - len(ssid)
		spaces = ' '*spaces
		#spaces2 = 18 - len(vendor)
		#spaces2 = ' '*spaces2
		if encryption=="0":
			print colors.get_color("OKGREEN")+"%s %s %s %2d %s   %s  %s" % (ssid, spaces, bssid, int(channel), vendor, encryption, sig_str) + colors.get_color("ENDC")
		else:	
			print "%s %s %s %2d %s   %s  %s" % (ssid, spaces, bssid, int(channel), vendor, encryption, sig_str)
		db_api.insert_in_db_scapy(conn, ssid, bssid, int(channel), vendor, encryption)

	signal.signal(signal.SIGINT, signal_handler)


def channel_hopper():
	current_ch = 6
	while True:
		try:
			current_ch+=1
			if(current_ch > 13):
				current_ch = 1
			#print("The current_ch: %s" % str(current_ch))	
			os.system("iw dev %s set channel %d" % (interface, current_ch) )
			time.sleep(0.5)
		except KeyboardInterrupt:
			break

def signal_handler(signal, frame):
	db_api.select_from_db(conn)
	manage_interfaces.disable_monitor(interface)
	print("Goodbye! ")
	sys.exit(0)

def printHeader():
	print(colors.get_color("WARNING") + "SSID\t\t\t\tBSSID\t   CH  BRAND\tENC  RSSI" + colors.get_color("ENDC"))

def scapy_scan(*arg):
	global interface, profile
	interface = arg[0]
	if (len(arg)>1):
		profile = arg[1]
	printHeader()
	global conn
	conn = db_api.open_db()
	conn.text_factory = str
	db_api.create_table_scapy(conn)

	# start the channel hopper
	p = Process(target = channel_hopper)
	p.start()

    # start scanning
	sniff(iface=interface, prn=aps_lookup)

	p.terminate()
	p.join()
	sys.exit(0)