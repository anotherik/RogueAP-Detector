import os
import modules.colors as colors
import modules.actuators.active_detectors as active_detectors
import modules.logs.logs_api as logs_api


#connect to AP using nmcli
def associateToAp(ap_name,bssid,pwd,iface):
	
	if(pwd==''):
		print(colors.get_color("ORANGE")+"Trying to associate to [%s | %s]" % (ap_name,bssid) +colors.get_color("ENDC"))
		os.system("nmcli dev wifi connect "+ap_name+" bssid "+bssid+" ifname "+iface)

		call_active_methods(iface, ap_name, bssid)

	else:
		print(colors.get_color("ORANGE")+"Trying to associate to [%s | %s]" % (ap_name,bssid) +colors.get_color("ENDC"))
		os.system("nmcli dev wifi connect "+str(ap_name)+" password "+str(pwd)+" bssid "+str(bssid).upper()+" ifname "+str(iface))
		
		call_active_methods(iface, ap_name, bssid)


def call_active_methods(iface, ap_name, bssid):
		
		internal_ip = active_detectors.get_internal_IP(iface)
		print ("Internal IP: %s" % internal_ip)

		external_ip = active_detectors.get_external_IP()
		print ("External IP: %s" % external_ip)

		isp = active_detectors.get_ISP(external_ip)
		print ("ISP: %s" % isp)

		#active_detectors.traceroute(hostname_internal, iface) # test internal address
		hostname_external = "sapo.pt"

		print(colors.get_color("ORANGE")+"Calculating the traceroute..."+colors.get_color("ENDC"))
		traceroute_val = active_detectors.traceroute(hostname_external, iface)
		print ("Traceroute for %s: %s" % (hostname_external, traceroute_val)) # test external address)
		
		print(colors.get_color("ORANGE")+"Checking AP fingerprint..."+colors.get_color("ENDC"))
		cp_name = active_detectors.get_AP_fingerprint()
		print ("Fingerprint computer name: %s" % cp_name)
		
		# disconnect
		print(colors.get_color("ORANGE")+"Disconnecting from [%s | %s]" % (ap_name,bssid) +colors.get_color("ENDC"))
		try:
			os.system("nmcli device disconnect "+iface)
		except Exception as Error:
			logs_api.errors_log("Error: "+str(subprocess.CalledProcessError))
			pass

		return