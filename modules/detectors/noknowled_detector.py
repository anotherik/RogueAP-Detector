#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)


def suspicious_behaviours(scanned_ap, captured_aps):

	for ap in captured_aps:
		try:
			
			# captured AP with same essid and dif bssid, print with gray to notify
			if (scanned_ap['essid'] == ap['essid'] and scanned_ap['mac'] != ap['mac']):
				return "suspicious_1"

			# captured AP with same bssid and dif essid (karma)
			elif (scanned_ap['mac'] == ap['mac'] and scanned_ap['essid'] != ap['essid']):
				return "suspicious_2"
		
			# captured AP with same essid, bssid and dif channel)
			elif (scanned_ap['essid'] == ap['essid'] and scanned_ap['mac'] == ap['mac'] and scanned_ap['channel'] != ap['channel']):
				return "suspicious_3"

			# captured AP with same essid, bssid and channel
			elif (scanned_ap['essid'] == ap['essid'] and scanned_ap['mac'] == ap['mac'] and scanned_ap['channel'] == ap['channel']):
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


