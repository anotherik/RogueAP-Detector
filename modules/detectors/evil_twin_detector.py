#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)

global possible_rogues
possible_rogues = {'Type1': 0,'Type2': 0,'Type3': 0,'Type4': 0, 'Type5': 0}
rates = {'Type1 rate': 0.5,'Type2 rate': 0.4,'Type3 rate': 0.4,'Type4 rate': 0.8, 'Type5 rate': 1}

global aps
aps = {'eduroam': 1, 'wifi_eventos': 1, 'UPorto': 1}
aps_rates = {'eduroam': 0, 'wifi_eventos': 0, 'UPorto': 0}

# the method will return in case of a detection
def rogueAP_detector(access_point, captured_aps):
	global possible_rogues

	for ap in captured_aps:
		try:
			# type of rap (same ssid and dif bssid) (small change of RAP type)
			if ap['essid'] == access_point['essid'] and ap['mac'] != access_point['mac']:
				##aps[ap['essid']]+=1
				possible_rogues['Type1']+=1
				#rates['Type1 rate'] /= possible_rogues['Type1']
				return True
			# type of rap (same bssid and dif ssid)
			elif ap['mac'] == access_point['mac'] and ap['essid'] != access_point['essid']:
				possible_rogues['Type2']+=1
				#rates['Type2 rate'] *= 0.20
				return True
			# type of rap (same ssid, same bssid and dif channel)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] != access_point['channel']:
				possible_rogues['Type3']+=1
				#rates['Type3 rate'] *= 0.40
				return True
			# type of rap (same ssid, same bssid and same channel)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel']:
				possible_rogues['Type4']+=1
				#rates['Type4 rate'] *= 0.60
				return True
			# type of rap (same ssid, same bssid , same channel and same encryption)
			elif ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel'] and ap['key type'] == access_point['key type']:
				possible_rogues['Type5']+=1
				#rates['Type5 rate'] *= 0.80
				return True

		except Exception as e:
			print "Exception found: " + str(e)
			pass
	return False


def statistics():
	if(possible_rogues['Type1']>0):
		rates['Type1 rate'] /= possible_rogues['Type1']
	print("Possible RogueAPs: "+ str(possible_rogues))
	print("Global Rates: "+ str(rates))
	print("Number of APs: "+str(aps))

	if(aps['eduroam']>0):
		aps_rates['eduroam'] = 0.5 / aps['eduroam']
	if(aps['wifi_eventos']>0):
		aps_rates['wifi_eventos'] = 0.5 / aps['wifi_eventos'] 
	if(aps['UPorto']>0):
		aps_rates['UPorto'] = 0.5 / aps['UPorto']

	print("Rates in AP: "+str(aps_rates))