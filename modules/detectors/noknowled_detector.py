#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)


# the method will return in case of a detection
def rogueAP_detector(access_point, captured_aps):

	for ap in captured_aps:
		try:
			# type of rap (same ssid and dif bssid) (small change of RAP type)
			if ap['essid'] == access_point['essid'] and ap['mac'] != access_point['mac']:
				return True
			# type of rap (same bssid and dif ssid)
			elif ap['mac'] == access_point['mac'] and ap['essid'] != access_point['essid']:
				return True
			# type of rap (same ssid, same bssid and dif channel)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] != access_point['channel']:
				return True
			# type of rap (same ssid, same bssid and same channel)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel']:
				return True
			# type of rap (same ssid, same bssid , same channel and same encryption)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel'] and ap['key type'] == access_point['key type']:
				return True
		except Exception as e:
			print("Exception: %s" % e)
			return
	return False


