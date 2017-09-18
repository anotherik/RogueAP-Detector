import os
from subprocess import check_output

def associate(ap_name,bssid,pwd,iface):
	#connect using nmcli
	if(pwd==''):
		os.system("nmcli dev wifi connect "+ap_name+" bssid "+bssid+" ifname "+iface)
	else:
		os.system("nmcli dev wifi connect "+ap_name+" password "+pwd+" bssid "+bssid+" ifname "+iface)

def traceroute(hostname):

    out = check_output(['traceroute', hostname])
    count = 0
    for line in out.split('\n')[1:]:
        if line:
            count += 1
    return count

last_hops = traceroute('sigarra.up.pt')
current_hops = traceroute('sigarra.up.pt')
if current_hops !=last_hops:
	print "Alert!"
print last_hops
print current_hops

associate('ZON-69CC','00:26:18:10:2B:F7','','wlp0s20u2')
