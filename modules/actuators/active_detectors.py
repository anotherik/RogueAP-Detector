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
from itertools import imap
from random import randint
import requests, json, subprocess
import modules.logs.logs_api as logs_api


def get_internal_IP(iface):	

	try:
		internal_ip = subprocess.check_output(" ip addr show "+iface+" | grep 'inet ' | awk -F' ' '{print $2}' ", shell=True)
		return internal_ip.strip()	
	except subprocess.CalledProcessError:
		logs_api.errors_log("Error: "+str(subprocess.CalledProcessError))
		pass
	return	

def get_external_IP():

	try:
		external_ip = subprocess.check_output(" dig +short myip.opendns.com @resolver1.opendns.com ", shell=True)
		return external_ip.strip()
	except subprocess.CalledProcessError:
		logs_api.errors_log("Error: "+str(subprocess.CalledProcessError))
		pass
	return	
	
def get_ISP(external_ip):

	url = "http://ip-api.com/json/"
	req_isp = "?fields=isp"
	
	try:
		r = requests.get(url+external_ip+req_isp)
		isp = json.loads(r.text)["isp"]
		return isp
	except Exception as Error:
		logs_api.errors_log("Error: "+str(Error))
		pass
	return

def traceroute(hostname, iface):

	try:
		out = subprocess.check_output("traceroute "+hostname+" -i "+iface, shell=True)
		count = 0
		for line in out.split('\n')[1:]:
			if line:
				count += 1
		return count

	except subprocess.CalledProcessError:
		logs_api.errors_log("Error: "+str(subprocess.CalledProcessError))
		pass
	return

def get_AP_fingerprint():

	try:
		gateway = subprocess.check_output(" netstat -nr | grep 'UG[ \t]' | awk 'NR==2 {print $2}' ", shell=True)
		gateway = gateway.strip()
		print gateway
		cp_name = subprocess.check_output(" nmap -sC -O "+gateway+" | grep 'Computer name' | awk '{print $4}' ", shell=True)
		return cp_name
	except subprocess.CalledProcessError:
		logs_api.errors_log("Error: "+str(subprocess.CalledProcessError))
		pass
	return
