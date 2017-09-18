import modules.colors as colors
import modules.actuators.associate as associateTo
import Queue, multiprocessing

def authorized_aps(ssid, bssid, rssi, encryption, profile):

	with open(profile+'.txt','r') as f:
		next(f)
		for line in f:
			auth_ssid, auth_enc, auth_rssi = line.split()[0], line.split()[1], line.split()[2]
			auth_rssi = int(auth_rssi)
			if (ssid == auth_ssid):	
				auth_bssids = []
				c = 3
				while c<len(line.split()):
				 	auth_bssids.append(line.split()[c])
				 	c+=1

				if (bssid in auth_bssids):
					if (auth_enc != 'Open' and encryption == "0"):
						print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, different encryption." % (ssid,bssid) +colors.get_color("ENDC"))
						break 
					if ( abs(int(rssi)) > auth_rssi+15 or abs(int(rssi)) < auth_rssi-15 ):
					 	print(colors.get_color("FAIL")+"[%s | %s] Stange RSSI!!! Associate?" % (ssid,bssid) +colors.get_color("ENDC"))
					 	#call associate
				else:
					print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, unauthorized bssid." % (ssid,bssid) +colors.get_color("ENDC") )	


def authorized_aps_iwlist(scanned_ap, profile):
	
	with open(profile+'.txt','r') as f:
		next(f)
		for line in f:
			auth_ssid, auth_enc, auth_rssi = line.split()[0], line.split()[1], line.split()[2]
			auth_rssi = int(auth_rssi)
			if (scanned_ap['essid'] == auth_ssid):
				auth_bssids = []
				c = 3
				while c<len(line.split()):
				 	auth_bssids.append(line.split()[c])
				 	c+=1

				if (scanned_ap['mac'].lower() in auth_bssids):
					if (auth_enc != 'Open' and scanned_ap['key type'] == "Open"):
						print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, different encryption." % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC"))
						break
					if ( abs(int(scanned_ap['signal'])) > auth_rssi+15 or abs(int(scanned_ap['signal'])) < auth_rssi-15 ):
					 	print(colors.get_color("FAIL")+"[%s | %s] Stange RSSI!!! Associate? (y/n)" % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC"))
					 	associate = str(raw_input())
					 	if(associate=="y"):
					 		pwd = str(raw_input("Enter AP password: "))
					 		iface = str(raw_input("Choose interface to association process: "))
					 		p = multiprocessing.Process(associateTo.associate(scanned_ap['essid'],scanned_ap['mac'],pwd,iface))
					 	else:
					 		break
				else:
					print(colors.get_color("FAIL")+"[%s | %s] Possible Rogue Access Point!\n[Type] Evil Twin, unauthorized bssid." % (scanned_ap['essid'],scanned_ap['mac']) +colors.get_color("ENDC") )	