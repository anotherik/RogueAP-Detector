#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)

# the method will return in case of a detection
def rogueAP_detector(access_point, captured_aps):
	rogue = False
	for ap in captured_aps:
		try:
			# type of rap (same ssid and dif bssid)
			if ap['essid'] == access_point['essid'] and ap['mac'] != access_point['mac']:
				rogue = True
			# type of rap (same bssid and dif ssid)
			if ap['mac'] == access_point['mac'] and ap['essid'] != access_point['essid']:
				rogue = True
			# type of rap (same ssid, same bssid and dif channel)
			if ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] != access_point['channel']:
				rogue = True
			# type of rap (same ssid, same bssid and same channel)
			if ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel']:
				rogue = True
		except Exception as e:
			print e
			pass
	return rogue
