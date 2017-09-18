#!/usr/bin/python2
# Network monitor using iwlist
import subprocess, sys, time, re, json, os, signal
import manufacturer.parse_manufacturer as manufacturer
import modules.detectors.evil_twin_detector as detector1
import modules.logs.logs_api as logs_api
import modules.detectors.passive_detectors as passive_detectors

captured_aps = []
manufacturer_table = "manufacturer/manufacturer_table.txt"
table_of_manufacturers = {}

def getTimeDate():
	return time.strftime("%X") +" "+ time.strftime("%x")#time.strftime("%c")

class colors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WHITE = '\033[37m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        FAIL2 = '\033[41m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        GRAY = '\033[90m'
        UNDERLINE = '\033[4m'

def signal_handler(signal, frame):
	print colors.GRAY + "\nYou pressed Ctrl+C!\nGoodbye!" + colors.ENDC
	#detector1.statistics()
	sys.exit(0)

def scan(*arg):
	interface = arg[0]
	profile = arg[1]
	global table_of_manufacturers
	table_of_manufacturers = manufacturer.MacParser(manufacturer_table).refresh()

	table = ['Date','AP Name','BSSID', 'CH', 'Brand','Signal','Quality','Encryption','Cipher', 'Pairwise','Authentication']
	print colors.WARNING + '{:^25s}|{:^22s}|{:^19s}|{:^9s}|{:^24s}|{:^8s}|{:^9s}|{:^16s}|{:^8s}|{:^11s}|{:^16s}'.format(table[0],table[1],table[2],table[3],table[4],table[5],table[6],table[7],table[8],table[9],table[10]) + colors.ENDC
	while True:
		ap_list = get_results(interface)
		#print ap_list
		try:
			for line in ap_list:
				#print line
				# filter to check if APs already exists 
				if filter_aps(line):	     
					limited = False
					if len(line['essid'])>21:
						limited = True
					
					passive_detectors.authorized_aps_iwlist(line, profile)	

					if limited:
						if detector1.rogueAP_detector(line,captured_aps):
							print colors.FAIL2 + '{:^25s} {:<21s}  {:^19s} {:^9s} {:^24s} {:^8s} {:^9s} {:^16s} {:^8s}  {:^10s} {:^16s}'.format(getTimeDate(),line['essid'][0:21],line['mac'],line['channel'], line['manufacturer'],line['signal'],line['quality'],line['key type'],line['group cipher'],line['pairwise cipher'], line['authentication suites']) + colors.ENDC
						else:
							print '{:^25s} {:<21s}  {:^19s} {:^9s} {:^24s} {:^8s} {:^9s} {:^16s} {:^8s}  {:^10s} {:^16s}'.format(getTimeDate(),line['essid'][0:21],line['mac'],line['channel'], line['manufacturer'],line['signal'],line['quality'],line['key type'],line['group cipher'],line['pairwise cipher'], line['authentication suites'])
					else:
						if detector1.rogueAP_detector(line,captured_aps):
							print colors.FAIL2 + '{:^25s} {:<21s}  {:^19s} {:^9s} {:^24s} {:^8s} {:^9s} {:^16s} {:^8s}  {:^10s} {:^16s}'.format(getTimeDate(),line['essid'],line['mac'],line['channel'], line['manufacturer'],line['signal'],line['quality'],line['key type'],line['group cipher'],line['pairwise cipher'], line['authentication suites']) + colors.ENDC
						else:
							print '{:^25s} {:<21s}  {:^19s} {:^9s} {:^24s} {:^8s} {:^9s} {:^16s} {:^8s}  {:^10s} {:^16s}'.format(getTimeDate(),line['essid'],line['mac'],line['channel'], line['manufacturer'],line['signal'],line['quality'],line['key type'],line['group cipher'],line['pairwise cipher'], line['authentication suites'])

					captured_aps.append(line)
					#print captured_aps
			signal.signal(signal.SIGINT, signal_handler)
			time.sleep(1)
		except Exception, err:
			logs_api.errors_log(str(err))
			pass

def get_results(interface):
    list_of_results=[]
    try:
		#Call the process to get the output to parse
        proc = subprocess.check_output("iwlist "+interface+" scan",shell=True)
		#Break the output making an array containing the info of each Access Point 
        list_of_results = re.split(r'\bCell \d{2}\b - ',proc)[1:]
    except subprocess.CalledProcessError:
    	logs_api.errors_log("Error"+str(subprocess.CalledProcessError))

    return parse(list_of_results)

def filter_aps(access_point):
    for ap in captured_aps:
		try:
			#print "a= " + str(float(ap['quality_calc']))
			#print "b= " + str(float(access_point['quality_calc']))
			#print "diff =" + str( abs((float(ap['quality_calc'])) - (float(access_point['quality_calc']))) )
			#if ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel'] and ap['key type'] == access_point['key type'] and ap['group cipher'] == access_point['group cipher'] and ( abs( float(ap['quality_calc']) - float(access_point['quality_calc']) ) <= 0.25 ):
			#print "***************************************************"
			#print abs(int(access_point['signal']))
			#print abs(int(ap['signal']))
			if ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel'] and ap['key type'] == access_point['key type'] and ap['group cipher'] == access_point['group cipher'] and ( abs(int(access_point['signal'])) <= abs(int(ap['signal']))+15 and abs(int(access_point['signal'])) >= abs(int(ap['signal']))-15):
				return False
		except Exception as e: 
			logs_api.errors_log("Exception found: "+str(e))
			pass		
    return True

def parse(list):
    parsed_list = []

    for network in list:
		try:
			ap={}	
			network = network.strip()
			essid=""
			address=""
			quality=""
			signal=""
			channel=""
			encryption_key=""
			key_type=""
			group_cipher=""
			pairwise_cipher=""
			authentication_suites=""
			
			#Get the name of the AP 
			match = re.search('ESSID:"(([ ]*(\S+)*)*)"',network)
			if match: 
			    essid = match.group(1)
			    ap.update({"essid":essid})
			
			#Get the BSSID of the AP
			match = re.search('Address: (\S+)',network)
			if match: 
			    address = match.group(1)
			    ap.update({"mac":address})

			#Get the Channel of the AP 
			match = re.search('Channel:(\S+)',network)
			if match: 
			    channel = match.group(1)
			    ap.update({"channel":channel})

			#Find the brand of the AP    
			global table_of_manufacturers
			manufacturer_data = manufacturer.search(table_of_manufacturers,str(address))
			if(len(manufacturer_data)>0):
				ap.update({"manufacturer":manufacturer_data[0].manuf})
				ap.update({"comment":manufacturer_data[0].comment})
			else: 	
				ap.update({"manufacturer":"Null"})
				ap.update({"comment":"Null"})

			#Get the quality of the signal and the signal level 
			match = re.search('Quality=(\d+/\d+)  Signal level=(-\d+) dBm',network)
			if match: 
			    quality = match.group(1)
			    a = quality[0:2]
			    b = quality[3:5]
			    quality_calc = format((float(a)/float(b)), '.2f')
			    # print quality_calc
			    # quality = str(int(round(float(quality[0]) / float(quality[1]) * 100))).rjust(3) + " %"
			    signal = match.group(2)
			    ap.update({"quality":quality})
			    ap.update({"quality_calc":quality_calc})
			    ap.update({"signal":signal})		
			
			#Check if there is an Encryption key on the AP
			match = re.search('Encryption key:(\S+)',network)
			if match: 
			    encryption_key = match.group(1)
			    ap.update({"encryption":encryption_key})
			
			#Find the encryption type (WEP, WPA, WPA2 or Open)
			match = re.search(r'(?<=802.11i/)[a-zA-Z0-9_ ]*',network)
			if match and match != "Unknown" and match != "IEEE 802":
			    key_type=match.group(0)
			    ap.update({"key type":key_type})	        
			elif ap['encryption']=='on':
			    key_type="WEP"
			    ap.update({"key type":key_type})
			else:
			    key_type="Open"
			    ap.update({"key type":key_type})
			
			#Get the Cipher being used
			match = re.search(r'Group Cipher : ([a-zA-Z0-9_ ]*)',network)
			if match:
			    group_cipher=match.group(1)	        
			    ap.update({"group cipher":group_cipher})	
			elif ap['encryption']=='on':
			    group_cipher="WEP"
			    ap.update({"group cipher":group_cipher})	
			else:
			    group_cipher=""
			    ap.update({"group cipher":group_cipher})	
			
			#Get the Pairwise Cipher being used	
			match = re.search('Pairwise Ciphers ([(\d+)]*) : ([a-zA-Z0-9_ ]*)',network)
			if match:
			    pairwise_cipher=match.group(2)
			    ap.update({"pairwise cipher":pairwise_cipher})    
			elif ap['encryption']=='on':
			    pairwise_cipher="WEP"
			    ap.update({"pairwise cipher":pairwise_cipher})	
			else:
			    pairwise_cipher=""
			    ap.update({"pairwise cipher":pairwise_cipher})

			#Get the Authentication Suites
			match = re.search('Authentication Suites ([(\d+)]*) : ([a-zA-Z0-9_ ]*)',network)
			if match:
				authentication_suites=match.group(2)	    
				ap.update({"authentication suites":authentication_suites})	
			elif ap['encryption']=='on':
			    authentication_suites=""
			    ap.update({"authentication suites":authentication_suites})
			else:
			    authentication_suites=""
			    ap.update({"authentication suites":authentication_suites})
			
			parsed_list.append(ap)	 
		except:
			pass

    return parsed_list
