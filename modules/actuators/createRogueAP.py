import sys
from scapy.all import *
import subprocess, signal, struct

def getRogueApParams():
	# rogueAP_configs (essid, bssid, ch, enc)
	with open('rogueAP_configs.txt') as fp:
	    params = []
	    for line in fp:
	        print line.strip()
	        params.append(line.strip())
	fp.close()
	return params        

# disable monitor mode to the given interface
def disable_monitor():
	#interface = "wlp0s20u1"
	print("\nChanging "+str(interface)+" to managed mode.")
	os.system("ifconfig %s down" % interface)
	os.system("iwconfig %s mode managed" % interface)
	os.system("ifconfig %s up" % interface)

def signal_handler(signal, frame):
	disable_monitor()
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

	while True:

		essid = ap_name

		radioTapHeader = RadioTap()
		dot11Header = Dot11(addr1 = broadcast, addr2 = bssid, addr3 = bssid)

		dot11Elt1 = Dot11Elt( ID=0, info = essid)
		dot11Elt2 = Dot11Elt( ID=1, info = "\x82\x84\x8b\x96\x24\x30\x48\x6c")
		dot11Elt3 = Dot11Elt( ID=3, info = channel)
		dot11Elt4 = Dot11Elt( ID=5, info = "\x00\x01\x00\x00")

		if (enc == "Open"):
			dot11BeaconHeaderOpen = Dot11Beacon(cap = 0x0)
			pkt = radioTapHeader / dot11Header / dot11BeaconHeaderOpen / dot11Elt1 / dot11Elt2 / dot11Elt3 / dot11Elt4			
		if (enc == "WEP"):
			dot11BeaconHeaderWEP = Dot11Beacon(cap = 0x1104)
			pkt = radioTapHeader / dot11Header / dot11BeaconHeaderWEP / dot11Elt1 / dot11Elt2 / dot11Elt3 / dot11Elt4
		if (enc == "WPA"):
			dot11BeaconHeader = Dot11Beacon(cap = 0x1104)
			rsn = Dot11Elt(ID='RSNinfo', info=(
			'\x01\x00'                 #RSN Version 1
			'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
			'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
			'\x00\x0f\xac\x04'         #AES Cipher
			'\x00\x0f\xac\x02'         #TKIP Cipher
			'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
			'\x00\x0f\xac\x02'         #Pre-Shared Key
			'\x00\x00'))               #RSN Capabilities (no extra capabilities)

			pkt = radioTapHeader / dot11Header / dot11BeaconHeader / dot11Elt1 / dot11Elt2 / dot11Elt3 / dot11Elt4 / rsn


		ch = int(ord(pkt[Dot11Elt:3].info)) # for debug purposes
		print ("Rogue ap with essid: "+essid+" in channel: "+ str(ch))

		sendp(pkt, iface=interface) #, count=100, inter=0.5
		
		signal.signal(signal.SIGINT, signal_handler)
		#time.sleep(5.0)