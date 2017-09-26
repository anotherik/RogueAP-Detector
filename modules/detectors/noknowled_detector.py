#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)


def suspicious_behaviours(scanned_ap, captured_aps):

	for ap in captured_aps:
		try:
			
			# captured AP with same essid and dif bssid and encryption
			if (scanned_ap['essid'] == ap['essid'] and scanned_ap['mac'] != ap['mac'] and scanned_ap['key type'] != ap['key type']):
				return "suspicious_3"

			# captured AP with same bssid and dif essid and encryption (karma)
			elif (scanned_ap['mac'] == ap['mac'] and scanned_ap['essid'] != ap['essid'] and scanned_ap['key type'] != ap['key type']):
				return "suspicious_2"
		
			# captured AP with same essid, bssid and dif channel and encryption)
			elif (scanned_ap['essid'] == ap['essid'] and scanned_ap['mac'] == ap['mac'] and scanned_ap['channel'] != ap['channel'] and scanned_ap['key type'] != ap['key type']):
				return "suspicious_3"

			# captured AP with same essid, bssid, channel and dif encryption
			elif (scanned_ap['essid'] == ap['essid'] and scanned_ap['mac'] == ap['mac'] and scanned_ap['channel'] == ap['channel'] and scanned_ap['key type'] != ap['key type']):
				return "suspicious_4"

			# captured AP with same essid, bssid, channel and encryption
			elif (scanned_ap['essid'] == ap['essid'] and scanned_ap['mac'] == ap['mac'] and scanned_ap['channel'] == ap['channel'] and scanned_ap['key type'] == ap['key type']):
				return "suspicious_3"

		except Exception as e:
			print("Exception: %s" % e)
			return

	return False


