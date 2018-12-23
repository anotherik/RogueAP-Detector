#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Rogue Access Point Detector
# version: 2.0
# author: anotherik (Ricardo Gonçalves)

##################################
#        Rogue AP Detector       #
#           Main Module          #
##################################

import os, string, threading, sys, time, Queue, multiprocessing, subprocess
import modules.scanners.iwlist_network_monitor as iwlist_monitor
import modules.scanners.scapy_network_monitor as scapy_monitor
import modules.actuators.createRogueAP as hive_mode
import modules.actuators.deauthing as deauthing
import modules.detectors.passive_detectors as passive_detectors
import modules.manage_interfaces as manage_interfaces
import modules.colors as colors

def print_info(info, type=0):
    if (type == 0):
        m = colors.get_color("OKBLUE")
    elif (type == 1):
        m = colors.get_color("OKGREEN")
    elif (type == 2):
        m = colors.get_color("WARNING")
    m += "[*] " + colors.get_color("ENDC") + colors.get_color("BOLD") + info + colors.get_color("ENDC")
    print(m)

def intro():
	print(colors.get_color("BOLD") +
	 "                               _    ____    ____       _            _     \n"+
	 " _ __ ___   __ _ _   _  ___   / \  |  _ \  |  _ \  ___| |_ ___  ___| |_ \n" +
	 "| '__/ _ \ / _` | | | |/ _ \ / _ \ | |_) | | | | |/ _ \ __/ _ \/ __| __| \n" +
	 "| | | (_) | (_| | |_| |  __// ___ \|  __/  | |_| |  __/ ||  __/ (__| |_ \n"+
	 "|_|  \___/ \__, |\__,_|\___/_/   \_\_|     |____/ \___|\__\___|\___|\__| \n "+
	 "          |___/                                                   v2.0\n"+
     "\t\t\t\tby Ricardo Gonçalves - 0x4notherik\n"+ colors.get_color("ENDC"))

def usage():
	intro()
	print_info("Usage: ./rogue_detector.py [option]")
	print("\nOptions:  -i interface\t\t -> the interface to monitor the network")
	print("\t  -im interface\t\t -> interface for active mode")
	print("\t  -p profile\t\t -> name of the profile to load")
	print("\t  -s scan_type\t\t -> name of scanning type (iwlist, scapy)")
	print("\t  -h hive_mode\t\t -> creates an AP")
	print("\t  -d deauth\t\t -> deauthenticates users from target AP")
	print("\t  -wifi_attacks_detect\t -> detects deauthentication and pmkid attacks")
	print("\t  -a active_mode\t -> activates random probe requests")

	print(colors.get_color("BOLD")+"\nExample:  ./rogue_detector.py -i iface -s iwlist -p example_profile.txt"+colors.get_color("ENDC"))

def parse_args():
	##intro()
	scanners = ["scapy", "iwlist"]
	scanner_type = ""
	profile, scan, hive, deauth, active_probing, wifi_attacks_detect = False, False, False, False, False, False

	if (len(sys.argv) < 4):
		usage()
		return

	# setting up args
	for cmd in sys.argv:

		if (cmd == "-i"):
			global interface
			interface = sys.argv[sys.argv.index(cmd)+1]
			pre_check(interface)

		if (cmd == "-im"):
			global interface_monitor
			interface_monitor = sys.argv[sys.argv.index(cmd)+1]
			pre_check(interface_monitor)

		if (cmd == "-p"):
			profile_name = sys.argv[sys.argv.index(cmd)+1]
			if(os.path.isfile(profile_name)):
				profile = True
			else:
				print (colors.get_color("FAIL")+ "Profile selected does not exists!\n"+ colors.get_color("ENDC"))
				return
			
		if (cmd == "-s"):
			scan = True
			scanner_type = sys.argv[sys.argv.index(cmd)+1]

		if (cmd == "-h"):
			hive = True

		if (cmd == "-d"):
			deauth = True

		if (cmd == "-a"):
			active_probing = True	

		if (cmd == "-wifi_attacks_detect"):
			wifi_attacks_detect = True

	if (scan):		
		if (scanner_type == "scapy"):
			manage_interfaces.enable_monitor(interface)
			try:
				if (profile):
					scapy_monitor.scapy_scan(interface, profile_name)
				else: 
					scapy_monitor.scapy_scan(interface)
			except Exception as e:
				print("Exception: %s" % e)
				return
		
		if (scanner_type == "iwlist"):

			try:
				if (profile and active_probing):
					manage_interfaces.change_mac(interface_monitor)
					manage_interfaces.enable_monitor(interface_monitor)
					iwlist_monitor.scan(interface, profile_name, active_probing, interface_monitor)
				elif (active_probing):
					manage_interfaces.change_mac(interface_monitor)
					manage_interfaces.enable_monitor(interface_monitor)
					iwlist_monitor.scan(interface, active_probing, interface_monitor)
				elif (profile):
					iwlist_monitor.scan(interface, profile_name)
				else:
					iwlist_monitor.scan(interface)
			except Exception as e:
				print("Exception: %s" %e)
				return

		if (scanner_type not in scanners):
			print (colors.get_color("FAIL")+ "Wrong module selected!\n"+ colors.get_color("ENDC"))
			usage()
			return

	if (hive):
		try:
			interface_monitor
		except Exception as e:
			print (colors.get_color("ORANGE") + "'im' interface not defined!" + colors.get_color("ENDC"))
			print (colors.get_color("GRAY") + "Exception: %s" % e + colors.get_color("ENDC"))
			sys.exit(0)

		iface_hive = interface_monitor
		try:	
			manage_interfaces.enable_monitor(iface_hive)
			p = multiprocessing.Process(hive_mode.startRogueAP(iface_hive))
			p.start()
			p.join()
		except Exception as e:
			print("Exception: %s" % e)
			return

	if (deauth):
		iface_deauth = interface_monitor
		try:	
			manage_interfaces.enable_monitor(iface_deauth)
			p = multiprocessing.Process(deauthing.deauthenticate(iface_deauth))
			p.start()
			p.join()
		except Exception as e:
			print("Exception: %s" % e)
			return		

	if (wifi_attacks_detect):
		iface_deauth = interface_monitor
		try:	
			manage_interfaces.enable_monitor(iface_deauth)
			p = multiprocessing.Process(passive_detectors.wifi_attacks_detector(interface_monitor))
			p.start()
			p.join()
		except Exception as e:
			print("Exception: %s" % e)
			return	


def pre_check(iface):
	try:
		if(iface):
			check_interface(iface)
	except:
		sys.exit(0)

def check_interface(iface):
	try:
		outputz = subprocess.check_output("iwlist " + iface + " scan", stderr=subprocess.STDOUT, shell=True)
	except Exception as e:
		print (colors.get_color("ORANGE") + "Please check your interface." + colors.get_color("ENDC"))
		print (colors.get_color("GRAY") + "Exception: %s" % e + colors.get_color("ENDC") )
		sys.exit(1)

def check_root():
	if os.geteuid() != 0:
		print(colors.get_color("FAIL") + "[!] Requires root" + colors.get_color("ENDC"))
		sys.exit(0)

def main():
	check_root()
	parse_args()
	
if __name__ == '__main__':
	main()