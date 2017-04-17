#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)

global possible_rogues
possible_rogues = {'Type1': 0,'Type2': 0,'Type3': 0,'Type4': 0, 'Type5': 0}
rates = {'Type1 rate': 1,'Type2 rate': 1,'Type3 rate': 1,'Type4 rate': 1, 'Type5 rate': 1}

# dict['Age'] = 8;

# the method will return in case of a detection
def rogueAP_detector(access_point, captured_aps):
	global possible_rogues

	for ap in captured_aps:
		try:
			# type of rap (same ssid and dif bssid) (small change of RAP type)
			if ap['essid'] == access_point['essid'] and ap['mac'] != access_point['mac']:
				possible_rogues['Type1']+=1
				rates['Type1 rate'] *= 0.20
				return True
			# type of rap (same bssid and dif ssid)
			elif ap['mac'] == access_point['mac'] and ap['essid'] != access_point['essid']:
				possible_rogues['Type2']+=1
				rates['Type2 rate'] *= 0.20
				return True
			# type of rap (same ssid, same bssid and dif channel)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] != access_point['channel']:
				possible_rogues['Type3']+=1
				rates['Type3 rate'] *= 0.40
				return True
			# type of rap (same ssid, same bssid and same channel)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel']:
				possible_rogues['Type4']+=1
				rates['Type4 rate'] *= 0.60
				return True
			# type of rap (same ssid, same bssid , same channel and same encryption)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel'] and ap['key type'] == access_point['key type']:
				possible_rogues['Type5']+=1
				rates['Type5 rate'] *= 0.80
				return True

		except Exception as e:
			print "Exception found: " + str(e)
			pass
	return False


def statistics():
	print("Possible RogueAPs: "+ str(possible_rogues))
	print("Ratings: "+ str(rates))