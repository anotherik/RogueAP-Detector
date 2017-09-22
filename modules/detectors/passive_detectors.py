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
import modules.actuators.associate as associateTo
import modules.manage_interfaces as manage_interfaces
import Queue, multiprocessing
from itertools import imap
from random import randint

def authorized_aps(ssid, bssid, rssi, encryption, profile):

	with open(profile+'.txt','r') as f:
		next(f)
		for line in f:
			auth_ssid, auth_enc, auth_rssi = line.split()[0], line.split()[1], line.split()[2]
			auth_rssi = int(auth_rssi)
			if (ssid == auth_ssid):	
				auth_bssids = []
				c = 3
				while c<len(line.split()):
				 	auth_bssids.append(line.split()[c])
				 	c+=1

				if (bssid in auth_bssids):
					if (auth_enc != 'Open' and encryption == "0"):
						print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, different encryption." % (ssid,bssid) +colors.get_color("ENDC"))
						break 
					if ( abs(int(rssi)) > auth_rssi+15 or abs(int(rssi)) < auth_rssi-15 ):
					 	print(colors.get_color("FAIL")+"[%s | %s] Stange RSSI!!! Associate?" % (ssid,bssid) +colors.get_color("ENDC"))
					 	#call associate
				else:
					print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, unauthorized bssid." % (ssid,bssid) +colors.get_color("ENDC") )	


def authorized_aps_iwlist(scanned_ap, profile):
	
	with open(profile+'.txt','r') as f:
		next(f) #skipping first line
		for line in f:
			auth_ssid, auth_enc, auth_rssi = line.split()[0], line.split()[1], line.split()[2]
			auth_rssi = int(auth_rssi)
			nr_auth_aps = 5
			t = 0
			if (scanned_ap['essid'] == auth_ssid):
				auth_bssids = []
				c = 3
				while c<len(line.split()):
				 	auth_bssids.append(line.split()[c])
				 	c+=1

				print ("scanned ap: %s" % scanned_ap['mac'])
				print ("auth bssids: %s" % auth_bssids) 	
				if (scanned_ap['mac'] in auth_bssids): #(.lower())
					if (auth_enc != 'Open' and scanned_ap['key type'] == "Open"):
						print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, different encryption." % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC"))
						break
					if ( abs(int(scanned_ap['signal'])) > auth_rssi+15 or abs(int(scanned_ap['signal'])) < auth_rssi-15 ):
					 	print(colors.get_color("FAIL")+"[%s | %s] Strange RSSI!!! Associate? (y/n)" % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC"))
					 	associate = str(raw_input())
					 	if(associate=="y"):
					 		pwd = str(raw_input("Enter AP password: "))
					 		iface = str(raw_input("Choose interface to association process: "))
					 		p = multiprocessing.Process(associateTo.associate(scanned_ap['essid'],scanned_ap['mac'],pwd,iface))
					 	else:
					 		break
				else:
					t+=1
					if (t==nr_auth_aps):
						print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, unauthorized bssid." % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC") )	


phishing_karma = {}
def spot_karma(scanned_ap):
	#print("Looking fot karmas...")
	
	#print phishing_karma
	#print (scanned_ap['mac'] in phishing_karma and scanned_ap['essid'] not in phishing_karma)

	if (scanned_ap['mac'] in phishing_karma):
		c = len(phishing_karma.values())
		cp = 0
		for i in range(c):
		 	if (scanned_ap['essid'] in phishing_karma.values()[i]):
		 		break
		 	#print ("scanned_ap %s" % scanned_ap['essid'])
		 	#print ("phishing_karma: %s" % phishing_karma.values()[i])
		 	if (scanned_ap['essid'] not in phishing_karma.values()[i]):
		 		cp+=1
		 		#print "cp added up!"
		 	#print ("%s and %s" %(cp,c))	
		 	if (cp == c):
		 		phishing_karma[scanned_ap['mac']].add(scanned_ap['essid'])
				print(colors.get_color("FAIL")+"[%s | %s] Karma Rogue Access Point!\n[Type] Karma attack." % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC") )
				break
	else:
		#print "HERE"
		phishing_karma[scanned_ap['mac']] = set([scanned_ap['essid']])


def gen_random_ssid():
	N = 6
	SSID = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))
	return SSID


pineAP_ssids = []
def gen_PineAp_ssid(scanned_ap):

	default_name = "Pinnaple_"
	if(scanned_ap['key type'] == "Open"): #based from neighbour Open networks around
		prefix = scanned_ap['bssid'][12:].replace(":","")
		pineAP_ssids.append(default_name+prefix)

	# random prefix
	rand_prefix = ''.join(random.choice('0123456789ABCDEF') for i in range(4))
	pineAP_ssids.append(default_name+rand_prefix)


def send_Probe_Req(interface):
	
	for pineAP_ssid in pineAP_ssids:
		
		print("Probing for %s" % pineAP_ssid)	

		broadcast = ":".join(["ff"]*6)
		rand_bssid = new_mac = ':'.join(['%02x'%x for x in imap(lambda x:randint(0,255), range(6))])

		radioTapHeader = RadioTap()
		dot11Header = Dot11(addr1 = broadcast, addr2 = rand_bssid, addr3 = rand_bssid)
		dot11ProbeReq = Dot11ProbeReq()
		dot11Elt = Dot11Elt(ID=0, info = pineAP_ssid)

		pkt = radioTapHeader / dot11Header / dot11ProbeReq / dot11Elt
		sendp(pkt, iface=interface, verbose=0) #, verbose=0	

def spoting_PineAP(*arg):
	
	scanned_ap = arg[0] 

	default_bssid = "00:13:37"
	if (default_bssid in scanned_ap['mac'] and scanned_ap['key type'] == "Open"):
		print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] PineAp produced RAP." % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC"))

	'''if(arg[1]):
		active_probing = arg[1]
		interface_monitor = arg[2]	
		
		p1 = multiprocessing.Process(gen_PineAp_ssid(scanned_ap))
		p2 = multiprocessing.Process(send_Probe_Req(interface_monitor))

	for pineAP_ssid in pineAP_ssids:
		if(pineAP_ssid == scanned_ap['essid']):
			print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] PineAp produced RAP (hidden RAP)." % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC"))			
	'''

def free_WiFis_detect():
	print ("To be developed soon...")
