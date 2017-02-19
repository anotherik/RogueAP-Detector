#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)

# the method will return in case of a detection
def rogueAP_detector(access_point, captured_aps):
	rogue = False
	for ap in captured_aps:
		try:
			if ap['essid'] == access_point['essid'] and ap['mac'] != access_point['mac']: # type of rap (same ssid and dif bssid)
				rogue = True
			if ap['mac'] == access_point['mac'] and ap['essid'] != access_point['essid']: # type of rap (same bssid and dif ssid)
				rogue = True
			if ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] != access_point['channel']: # type of rap (same ssid, same bssid and dif channel)
				rogue = True
		except Exception as e:
			print e
			pass
	return rogue
