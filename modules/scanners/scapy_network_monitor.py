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
import modules.detectors.noknowled_detector as noknowled_detector
import modules.logs.logs_api as logs_api
import multiprocessing

manufacturer_table = "manufacturer/manufacturer_table.txt"
table_of_manufacturers = {}

access_points = set()
encryption = "0"
vendor = ""
spaces = 0
captured_aps = []
channel = 1

def aps_lookup(pkt):
	global table_of_manufacturers
	global channel
	table_of_manufacturers = manufacturer.MacParser(manufacturer_table).refresh()

	parsed_list = []
	ap={}
	
	if(channel > 13):
		channel = 1
	channel_hopper()
	channel+=1

	# we are checking if ssid is already in the access_points list (and we also want same ssid with different bssid)
	if ( (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and (pkt[Dot11].addr3 not in access_points) ):
		
		print pkt[Dot11].cap
		#print pkt[Dot11ProbeResp].cap
		access_points.add(pkt[Dot11].addr3)
		ssid = pkt[Dot11].info
		ap.update({"essid":ssid})

		bssid = pkt[Dot11].addr3
		ap.update({"mac":bssid.upper()})

		channel = int(ord(pkt[Dot11Elt:3].info))
		ap.update({"channel":channel})

		capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
		        {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

		extra = pkt.notdecoded
		sig_str = -(256-ord(extra[-4:-3]))

		ap.update({"signal":sig_str})

		manufacturer_data = manufacturer.search(table_of_manufacturers,str(pkt.addr2))
		if(manufacturer_data == []):
			vendor = "Not Found"
			ap.update({"manufacturer":"Null"})
		else:
			vendor = manufacturer_data[0].manuf
			ap.update({"manufacturer":vendor})

		if(str(vendor) == "None"):
			vendor = "Not Found"	

		if (re.search("privacy", capability)): 
			encryption = "1"
			#print pkt[Dot11Elt].ID
			#if (pkt[Dot11Elt].ID == 48):
			#	key_type = "WPA2"
			#	ap.update({"key type":key_type})
			#	encryption = key_type
			#elif (pkt[Dot11Elt].ID == 221 and pkt[Dot11Elt].info.startswith('\x00P\xf2\x01\x01\x00')):
			#	key_type = "WEP"
			#	ap.update({"key type":key_type})
			#	encryption = key_type

			#encryption = "1"
			#key_type="Yes"
			#ap.update({"key type":key_type})
		else: 
			encryption = "0"
			key_type="Open"
			ap.update({"key type":key_type})

		# call passive detectors

		##print ("The AP:\n %s" % ap)
		if (profile):
			passive_detectors.authorized_aps(ap, profile)
		passive_detectors.free_WiFis_detect(ap, captured_aps)
		passive_detectors.spot_karma(ap)

		captured_aps.append(ap)

		spaces = 23 - len(ssid)
		spaces = ' '*spaces
		#spaces2 = 18 - len(vendor)
		#spaces2 = ' '*spaces2
		if encryption=="0":
			print colors.get_color("OKGREEN")+"%s %s %s %2d %s   %s  %s" % (ssid, spaces, bssid, int(channel), vendor, encryption, sig_str) + colors.get_color("ENDC")
		else:	
			print "%s %s %s %2d %s   %s  %s" % (ssid, spaces, bssid, int(channel), vendor, encryption, sig_str)
		##db_api.insert_in_db_scapy(conn, ssid, bssid, int(channel), vendor, encryption)

		#time.sleep(0.5)

	signal.signal(signal.SIGINT, signal_handler)


def channel_hopper():
	#current_ch = 6
	#while True:
	try:
		#current_ch+=1
		#if(current_ch > 13):
		#	current_ch = 1
		#print("The current_ch: %s" % str(channel))	
		os.system("sudo iw dev %s set channel %d" % (interface, channel) )
		#time.sleep(0.5)
	except Exception, err:
		logs_api.errors_log(str(err))
		pass

def signal_handler(signal, frame):
	##print("\n=== Dumping APs from memory ===")
	##db_api.select_from_db(conn)
	manage_interfaces.disable_monitor(interface)
	print("Goodbye! ")
	sys.exit(0)

def printHeader():
	print(colors.get_color("WARNING") + "SSID\t\t\t\tBSSID\t   CH  BRAND\tENC  RSSI" + colors.get_color("ENDC"))

def scapy_scan(*arg):
	global interface, profile
	profile = False
	interface = arg[0]
	if (len(arg)>1):
		profile = arg[1]
	printHeader()
	##global conn
	##conn = db_api.open_db()
	##conn.text_factory = str
	##db_api.create_table_scapy(conn)

	# start the channel hopper
	##p = Process(target = channel_hopper)
	##p.start()

	#p = multiprocessing.Process(channel_hopper())
	#p.start()
	#p.join()
    # start scanning
	sniff(iface=interface, prn=aps_lookup, store=0)

	##p.terminate()
	##p.join()
	sys.exit(0)