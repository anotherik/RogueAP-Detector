#!/usr/bin/python2
# anotherik

# Script to send Prob Requests using Scapy

# Supress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import random, string, sys
from scapy.all import *

def gen_ssid():
	N = 6
	SSID = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))
	return SSID

while True:
	
	ssid = gen_ssid()
	print("Probing %s ..." % ssid)

	broadcast = ":".join(["ff"]*6)
	bssid = "24:0D:C2:81:D5:A2"

	radioTapHeader = RadioTap()
	dot11Header = Dot11(addr1 = broadcast, addr2 = bssid, addr3 = bssid)
	dot11ProbeReq = Dot11ProbeReq()
	dot11Elt = Dot11Elt(ID=0, info = ssid)

	pkt = radioTapHeader / dot11Header / dot11ProbeReq / dot11Elt
    
	sendp(pkt, iface=sys.argv[1])
