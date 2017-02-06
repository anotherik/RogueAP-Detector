#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Rogue Access Point Detector
# version: 0.1
# author: anotherik (Ricardo Gonçalves)

import os, string

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

class thread(threading, Thread):
	def __init__(self, function):
		threading.Thread.__init__(self)
		self.function=function
	def run(self):
		print("Thread stared")
		self.function()
		print("Thread ended")

def print_info(info, type=0):
        if (type == 0):
                m = colors.OKBLUE
        elif (type == 1):
                m = colors.OKGREEN
        elif (type == 2):
                m = TEXT_RED
        m += "[*] " + colors.ENDC + colors.BOLD + info + colors.ENDC
        print(m)

def intro():
	print(colors.BOLD + "Rogue Access Point Detector" + colors.ENDC)

def usage():
	print_info("Usage: python rogue-detector.py [option]")
	print("\nOptions:  -i interface    -> the interface to monitor the network")

# optional: change the mac address of the interface performing the scan 
def change_mac(iface):
	print(colors.GRAY+"Changing the interface mac address..."+colors.ENDC)
	os.system("ifconfig %s down" % iface)
	chars = string.digits +string.ascii_lowercase
	new_mac = ''.join(random.choice(chars) for _ in range(6))
	new_mac =  "00:36:29"+":"+new_mac[3:6]+":"+new_mac[6:8]+":"+new_mac[8:]
	print(colors.OKBLUE+"your new MAC address: %s" % new_mac +colors.ENDC)
	os.system("ifconfig %s hw ether %s" %(iface,new_mac))
	os.system("ifconfig %s up" % iface)

# enable monitor mode to the given interface
def enable_monitor(iface):
	os.system("ifconfig %s down" % iface)
	os.system("iwconfig %s mode monitor" % iface)
	os.system("ifconfig %s up" % iface)

# disable monitor mode to the given interface
def enable_monitor(iface):
	os.system("ifconfig %s down" % iface)
	os.system("iwconfig %s mode managed" % iface)
	os.system("ifconfig %s up" % iface)

# parse the input arguments
def parse_args():
	if (len(sys.argv) < 2):
		usage()
		return
	if (sys.argv[1] == "-i"):
		global interface
		interface = sys.argv[2]
		#change_mac(interface)
		intro()
		enable_monitor(interface)
		scan_thread = thread(lambda: iwlist.scan(interface))
		scan_thread.start()
		time.sleep(2)
	else:
		usage()

def main():
	parse_args()

if __name__ == '__main__':
	main()
