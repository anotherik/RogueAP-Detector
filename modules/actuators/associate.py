import os

def associate(ap_name,bssid,pwd,iface):
	#connect using nmcli
	if(pwd==''):
		print("Trying to associate...")
		os.system("nmcli dev wifi connect "+ap_name+" bssid "+bssid+" ifname "+iface)
	else:
		print("Trying to associate...")
		os.system("nmcli dev wifi connect "+ap_name+" password "+pwd+" bssid "+bssid+" ifname "+iface)
		# call active detectors
		os.system("ifconfig %s" % iface)
		os.system("dig +short myip.opendns.com @resolver1.opendns.com")
		internal_ip = os.system("ifconfig $1 | grep 'inet ' | awk -F' ' '{print $2}' | tail -1")
		print internal_ip
		#os.system("nmap -sV -sC -O 192.168.43.1")